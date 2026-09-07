(ns trexsql.batch
  "JDBC batch transfer for cache creation.
   Implements streaming data transfer from JDBC sources to TrexSQL cache files
   with progress reporting and resume capability."
  (:require [trexsql.db :as db]
            [trexsql.native :as native]
            [trexsql.jobs :as jobs]
            [trexsql.jdbc-types :as jdbc-types]
            [trexsql.errors :as errors]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [honey.sql :as sql])
  (:import [java.sql Connection DriverManager PreparedStatement ResultSet]
           [java.util HashMap]
           [com.zaxxer.hikari HikariConfig HikariDataSource]))

;; Sized for OMOP CDM cache builds against a co-located postgres source:
;; - batch-size: how many rows the DuckDB Appender holds before flushing;
;;   larger reduces flush overhead, no real downside up to a few hundred
;;   thousand rows for narrow CDM tables.
;; - fetch-size: postgres JDBC cursor row count per network round-trip;
;;   default 0 buffers the entire result set client-side. 2k was safe but
;;   forced ~25x more round-trips than needed for the big vocab tables.
(def default-batch-size 50000)
(def default-fetch-size 10000)
(def default-progress-interval 50000)

(def min-batch-size 100)
(def max-batch-size 200000)

(def ^:private default-pool-size 5)
(def ^:private default-connection-timeout 30000)
(def ^:private default-idle-timeout 600000)
(def ^:private default-max-lifetime 1800000)

(defn create-connection-pool
  "Create a HikariCP connection pool for JDBC source.
   Returns a HikariDataSource that should be closed when done.

   Options:
   - :jdbc-url - JDBC connection URL (required)
   - :user - database username
   - :password - database password
   - :pool-size - max connections (default 5)
   - :pool-name - name for the pool (default 'batch-source-pool')
   - :connection-timeout - timeout in ms (default 30000)
   - :idle-timeout - idle connection timeout in ms (default 600000)
   - :max-lifetime - max connection lifetime in ms (default 1800000)
   - :read-only - set connections to read-only (default true for source DBs)"
  [{:keys [jdbc-url user password pool-size pool-name
           connection-timeout idle-timeout max-lifetime read-only]
    :or {pool-size default-pool-size
         pool-name "batch-source-pool"
         connection-timeout default-connection-timeout
         idle-timeout default-idle-timeout
         max-lifetime default-max-lifetime
         read-only true}}]
  (let [config (doto (HikariConfig.)
                 (.setJdbcUrl jdbc-url)
                 (.setMaximumPoolSize pool-size)
                 (.setPoolName pool-name)
                 (.setConnectionTimeout connection-timeout)
                 (.setIdleTimeout idle-timeout)
                 (.setMaxLifetime max-lifetime)
                 (.setAutoCommit false))]
    (when (and read-only (not (re-find #"(?i)duckdb" (or jdbc-url ""))))
      (.setReadOnly config true))
    (when user (.setUsername config user))
    (when password (.setPassword config password))
    (log/debug (format "Creating connection pool '%s' with %d connections to %s"
                       pool-name pool-size jdbc-url))
    (HikariDataSource. config)))

(defn close-connection-pool!
  "Close a connection pool and release all connections."
  [^HikariDataSource pool]
  (when pool
    (log/debug (format "Closing connection pool '%s'" (.getPoolName pool)))
    (.close pool)))

(defmacro with-connection-pool
  "Execute body with a connection pool. Pool is automatically closed when done.
   Binds pool-sym to the HikariDataSource."
  [[pool-sym pool-config] & body]
  `(let [~pool-sym (create-connection-pool ~pool-config)]
     (try
       ~@body
       (finally
         (close-connection-pool! ~pool-sym)))))

(defmacro with-pooled-connection
  "Get a connection from pool, execute body, return connection to pool.
   Binds conn-sym to the Connection."
  [[conn-sym pool] & body]
  `(with-open [~conn-sym (.getConnection ~pool)]
     ~@body))

(defn validate-batch-config
  "Validate batch configuration. Returns error message or nil if valid."
  [{:keys [batch-size] :as config}]
  (cond
    (and batch-size (not (<= min-batch-size batch-size max-batch-size)))
    (format "batch-size must be between %d and %d" min-batch-size max-batch-size)

    (str/blank? (:schema-name config))
    "schema-name is required"

    :else nil))

(defn build-select-query
  "Build SELECT query with optional filters using HoneySQL.
   Returns [sql-string & params] for parameterized execution."
  [{:keys [schema table columns patient-filter timestamp-filter column-filter]}]
  (let [select-cols (if-let [cols (get column-filter table)]
                      (mapv keyword cols)
                      (or columns [:*]))
        base-query {:select select-cols
                    :from [[(keyword (str schema "." table))]]}
        with-patient (if patient-filter
                       (assoc base-query :where [:in :person_id patient-filter])
                       base-query)
        with-timestamp (if timestamp-filter
                         (if (:where with-patient)
                           (update with-patient :where #(vector :and % [:>= :observation_date timestamp-filter]))
                           (assoc with-patient :where [:>= :observation_date timestamp-filter]))
                         with-patient)]
    (sql/format with-timestamp {:quoted true})))

(defn build-create-table-ddl
  "Generate CREATE TABLE DDL from column metadata.
   `qualified-table` may be either a bare \"table\" or a \"catalog.table\"
   reference; the function quotes each dot-separated segment individually so
   DuckDB resolves it as a proper qualified name (and not as a single literal
   identifier containing a dot)."
  [qualified-table columns]
  (let [parts (str/split qualified-table #"\.")
        quoted-table (str/join "." (map #(format "\"%s\"" %) parts))
        col-defs (for [{:keys [name trexsql-type nullable? precision scale]} columns]
                   (let [type-str (if (and (= trexsql-type "DECIMAL") precision (pos? precision))
                                    (format "DECIMAL(%d,%d)" precision (or scale 0))
                                    trexsql-type)
                         null-str (if nullable? "" " NOT NULL")]
                     (format "\"%s\" %s%s" name type-str null-str)))]
    (format "CREATE TABLE IF NOT EXISTS %s (%s)"
            quoted-table
            (str/join ", " col-defs))))

(defn retry-with-backoff
  "Retry a function with exponential backoff for transient errors.
   Options: :max-retries (default 3), :initial-delay-ms (default 1000), :max-delay-ms (default 30000)"
  [f {:keys [max-retries initial-delay-ms max-delay-ms on-retry]
      :or {max-retries 3 initial-delay-ms 1000 max-delay-ms 30000}}]
  (loop [attempt 1
         delay initial-delay-ms]
    (let [result (try
                   {:success (f)}
                   (catch java.sql.SQLTransientException e
                     {:error e :retryable true})
                   (catch java.net.SocketTimeoutException e
                     {:error e :retryable true})
                   (catch java.sql.SQLRecoverableException e
                     {:error e :retryable true})
                   (catch Exception e
                     ;; Check for connection-related errors
                     (if (re-find #"(?i)connection|timeout|network|reset" (.getMessage e))
                       {:error e :retryable true}
                       {:error e :retryable false})))]
      (cond
        (:success result) (:success result)

        (and (:retryable result) (< attempt max-retries))
        (do
          (when on-retry
            (on-retry attempt (:error result)))
          (log/warn (format "Retrying after transient error (attempt %d/%d): %s"
                            attempt max-retries (.getMessage ^Throwable (:error result))))
          (Thread/sleep (long delay))
          (recur (inc attempt) (min (* delay 2) max-delay-ms)))

        :else
        (throw (:error result))))))

(defn create-table-schema!
  "Create the destination table at `<cache-alias>.<schema-name>.<table>`,
   where `schema-name` mirrors the source's CDM schema (e.g. `cdm`). The
   cache count + circe SQL handlers query `<cache-alias>.<cdm-schema>` for
   patient counts and live preview, so the cache layout has to match.
   We CREATE SCHEMA first because, by default, an attached DuckDB catalog
   only has a `main` schema."
  [trexsql-db cache-alias schema-name table-name columns]
  (let [esc (fn [s] (str/replace (str s) "\"" "\"\""))
        create-schema-sql (format "CREATE SCHEMA IF NOT EXISTS \"%s\".\"%s\""
                                  (esc cache-alias) (esc schema-name))]
    (try
      (db/execute! trexsql-db create-schema-sql)
      (catch Exception e
        (when-not (re-find #"(?i)already exists" (.getMessage e))
          (log/warn (format "CREATE SCHEMA \"%s\".\"%s\" failed: %s"
                            cache-alias schema-name (.getMessage e))))))
    (let [qualified (format "%s.%s.%s" cache-alias schema-name table-name)
          ddl (build-create-table-ddl qualified columns)]
      (log/info (format "Creating cache table: %s" qualified))
      (db/execute! trexsql-db ddl)
      (log/info (format "Created cache table: %s" qualified)))))

(def ^:private insert-batch-size
  "Rows per multi-VALUES INSERT. Larger amortizes parse/plan cost at the
   expense of bigger SQL strings; 10000 is a good balance for OMOP CDM
   tables (typically 10-30 columns wide). DuckDB's parser handles
   statements up to a few hundred MB, so this stays well within bounds.
   The native Appender path is in batch.clj's commit history; it hits a
   trex catalog-resolution issue that needs further investigation, so
   we're on multi-VALUES INSERT for now."
  10000)

(defn- read-row-values
  [^ResultSet rs columns]
  (mapv (fn [[idx col]]
          (jdbc-types/read-typed-value rs (inc idx) (:trexsql-type col)))
        (map-indexed vector columns)))

(defn- build-insert-prefix
  "INSERT INTO \"<cat>\".\"<schema>\".\"<table>\" (\"c1\",...) VALUES "
  [cache-alias schema-name table-name columns]
  (let [esc (fn [s] (str/replace (str s) "\"" "\"\""))
        col-list (str/join ","
                   (map (fn [c] (str "\"" (esc (:name c)) "\"")) columns))]
    (format "INSERT INTO \"%s\".\"%s\".\"%s\" (%s) VALUES "
            (esc cache-alias) (esc schema-name) (esc table-name) col-list)))

(defn- flush-insert-batch!
  [trexsql-db ^String insert-prefix pending-rows num-cols]
  (when (seq pending-rows)
    (let [row-placeholder (str "(" (str/join "," (repeat num-cols "?")) ")")
          all-placeholders (str/join "," (repeat (count pending-rows) row-placeholder))
          sql (str insert-prefix all-placeholders)
          flat-params (vec (mapcat identity pending-rows))]
      (db/execute-with-params! trexsql-db sql flat-params))))

(defn copy-rows-batched!
  "Copy rows from a JDBC ResultSet into the attached cache catalog at
   `<cache-alias>.<schema-name>.<table-name>` via batched multi-row INSERTs."
  [trexsql-db cache-alias schema-name table-name ^ResultSet rs columns config progress-fn]
  (let [progress-interval (or (:progress-interval config) default-progress-interval)
        estimated-rows (:estimated-rows config)
        num-cols (count columns)
        insert-prefix (build-insert-prefix cache-alias schema-name table-name columns)]
    (loop [total 0
           pending []]
      (if (.next rs)
        (let [row-values (read-row-values rs columns)
              pending' (conj pending row-values)
              new-total (inc total)]
          (cond
            (zero? (mod new-total insert-batch-size))
            (do
              (flush-insert-batch! trexsql-db insert-prefix pending' num-cols)
              (when (and progress-fn (zero? (mod new-total progress-interval)))
                (progress-fn {:phase :row-progress
                              :table table-name
                              :rows-processed new-total
                              :estimated-rows estimated-rows}))
              (recur new-total []))

            :else
            (recur new-total pending')))
        (do
          (flush-insert-batch! trexsql-db insert-prefix pending num-cols)
          total)))))

(declare copy-table-jdbc-impl)

(defmacro with-trexsql-transaction
  "Execute body within a TrexSQL transaction.
   Commits on success, rolls back on exception.

   Usage:
   (with-trexsql-transaction [trexsql-db]
     (do-work ...))"
  [[db-sym] & body]
  `(let [handle# (db/get-raw-handle ~db-sym)]
     (native/execute! handle# "BEGIN TRANSACTION")
     (try
       (let [result# (do ~@body)]
         (native/execute! handle# "COMMIT")
         result#)
       (catch Exception e#
         (try
           (native/execute! handle# "ROLLBACK")
           (catch Exception rollback-err#
             (log/warn (format "Rollback failed: %s" (.getMessage rollback-err#)))))
         (throw e#)))))

(defn copy-table-with-transaction
  "Copy a table within a TrexSQL transaction on the main handle.
   Creates the table in the attached cache catalog and copies all rows
   atomically. On failure, rolls back to leave the cache consistent."
  [trexsql-db source-conn cache-alias table-name config progress-fn]
  (with-trexsql-transaction [trexsql-db]
    (copy-table-jdbc-impl trexsql-db source-conn cache-alias table-name config progress-fn)))

(defn copy-table-jdbc-impl
  "Copy a single table from a JDBC source into the attached cache catalog.
   DDL targets `<cache-alias>.<table-name>`; the Appender targets the same
   catalog via trexsql_appender_create_ext."
  [trexsql-db ^Connection source-conn cache-alias table-name config progress-fn]
  (let [start-time (System/currentTimeMillis)
        {:keys [schema-name fetch-size column-filter patient-filter timestamp-filter]} config
        fetch-size (or fetch-size default-fetch-size)]
    (try
      (let [[query-sql & params] (build-select-query
                                   {:schema schema-name
                                    :table table-name
                                    :column-filter column-filter
                                    :patient-filter patient-filter
                                    :timestamp-filter timestamp-filter})]
        (log/debug (format "Executing query for table %s: %s" table-name query-sql))

        (with-open [stmt (doto (.prepareStatement source-conn query-sql
                                 ResultSet/TYPE_FORWARD_ONLY
                                 ResultSet/CONCUR_READ_ONLY)
                           (.setFetchSize fetch-size))]
          (doseq [[idx param] (map-indexed vector params)]
            (.setObject stmt (inc idx) param))

          (with-open [rs (.executeQuery stmt)]
            (let [columns (jdbc-types/get-column-info (.getMetaData rs))]
              (create-table-schema! trexsql-db cache-alias schema-name table-name columns)
              (let [rows-copied (copy-rows-batched! trexsql-db cache-alias schema-name table-name rs columns config progress-fn)
                    duration-ms (- (System/currentTimeMillis) start-time)]
                {:success? true
                 :table-name table-name
                 :rows-copied rows-copied
                 :duration-ms duration-ms})))))
      (catch Exception e
        (let [duration-ms (- (System/currentTimeMillis) start-time)]
          (log/error e (format "Failed to copy table %s: %s"
                               table-name (.getMessage e)))
          {:success? false
           :table-name table-name
           :error (.getMessage e)
           :phase :data
           :duration-ms duration-ms})))))

(defn copy-table-jdbc
  "Copy a single table with optional transaction wrapping."
  [trexsql-db source-conn cache-alias table-name config progress-fn]
  (let [use-transactions? (get config :use-transactions true)]
    (if use-transactions?
      (copy-table-with-transaction trexsql-db source-conn cache-alias table-name config progress-fn)
      (copy-table-jdbc-impl trexsql-db source-conn cache-alias table-name config progress-fn))))

(defn get-source-tables
  "Get list of tables in source schema via JDBC metadata."
  [^Connection source-conn schema-name]
  (with-open [rs (.getTables (.getMetaData source-conn) nil schema-name "%" (into-array String ["TABLE"]))]
    (loop [tables []]
      (if (.next rs)
        (recur (conj tables (.getString rs "TABLE_NAME")))
        tables))))

(defn get-completed-tables
  "Get list of tables already copied to the attached cache catalog."
  [trexsql-db cache-alias]
  (try
    (let [[query-sql & params] (sql/format
                                 {:select [:table_name]
                                  :from [:information_schema.tables]
                                  :where [:= :table_catalog cache-alias]})
          results (db/query-with-params trexsql-db query-sql (vec params))]
      (set (map #(.get ^HashMap % "table_name") results)))
    (catch Exception e
      (log/debug (format "Could not get completed tables for %s: %s" cache-alias (.getMessage e)))
      #{})))

(defn get-tables-to-copy
  "Get tables that need to be copied (not yet in cache).
   If table-filter provided, only include those tables."
  [source-conn trexsql-db cache-alias schema-name table-filter]
  (let [source-tables (get-source-tables source-conn schema-name)
        completed-tables (get-completed-tables trexsql-db cache-alias)
        tables-needed (if table-filter
                        (filter (set table-filter) source-tables)
                        source-tables)]
    (remove completed-tables tables-needed)))

(defn drop-partial-table!
  "Drop a table if it exists (for re-copying partial tables)."
  [trexsql-db cache-alias table-name]
  (try
    (db/execute! trexsql-db (format "DROP TABLE IF EXISTS %s.%s" cache-alias table-name))
    (catch Exception e
      (log/warn (format "Failed to drop partial table %s.%s: %s" cache-alias table-name (.getMessage e))))))

(defn check-cancellation
  "Check if job has been cancelled. Returns true if cancelled."
  [trexsql-db database-code]
  (when-let [job-status (jobs/get-job-status trexsql-db database-code)]
    (= "CANCELED" (:status job-status))))

(declare create-cache-jdbc-with-connection)

(defn create-cache-jdbc
  "Main orchestration function for JDBC batch cache creation.
   Handles job tracking, progress reporting, and resume capability.
   Uses HikariCP connection pooling for efficient source database access.

   config keys:
   - :source-credentials - JDBC connection info {:jdbc-url :user :password :pool-size}
   - :schema-name - source schema to copy
   - :database-code - unique cache identifier
   - :batch-size - rows per batch (default 10000)
   - :table-filter - optional list of table names to copy
   - :column-filter - optional map of table -> columns
   - :patient-filter - optional list of patient IDs
   - :timestamp-filter - optional minimum timestamp
   - :cache-path - cache directory (default ./data/cache)
   - :resume? - if true, skip completed tables
   - :use-transactions - wrap table copies in transactions (default true)
   - :use-pooling - use connection pooling (default true)

   progress-fn is called with progress events:
   - {:phase :job-start :total-tables N}
   - {:phase :table-start :table T :table-index I :total-tables N}
   - {:phase :row-progress :table T :rows-processed R :estimated-rows E}
   - {:phase :table-complete :table T :rows-copied R :duration-ms M}
   - {:phase :table-failed :table T :error E}
   - {:phase :job-complete :tables-copied [...] :tables-failed [...] :duration-ms M}"
  [trexsql-db config progress-fn]
  (let [start-time (System/currentTimeMillis)
        {:keys [source-credentials schema-name database-code cache-path
                table-filter resume? use-pooling]
         :or {use-pooling true}} config
        cache-path (or cache-path "./data/cache")
        webapi-ds (jobs/get-webapi-datasource trexsql-db)]

    (when-let [error (validate-batch-config config)]
      (throw (errors/config-error error :batch-config)))

    (let [{:keys [jdbc-url user password pool-size]} source-credentials
          pool-config {:jdbc-url jdbc-url
                       :user user
                       :password password
                       :pool-size (or pool-size default-pool-size)
                       :pool-name (str "batch-" database-code)
                       :read-only true}
          run-with-connection
          (fn [get-conn-fn]
            ;; Attach the cache file as catalog `database-code` on the main
            ;; trex handle. The Appender then uses
            ;; trexsql_appender_create_ext to target this catalog directly.
            (db/attach-cache-file! trexsql-db database-code cache-path)
            (create-cache-jdbc-with-connection trexsql-db config progress-fn
              get-conn-fn start-time database-code schema-name cache-path
              table-filter webapi-ds))]
      (if use-pooling
        ;; Use connection pooling
        (with-connection-pool [pool pool-config]
          (run-with-connection #(.getConnection ^HikariDataSource pool)))
        ;; Direct connection (for testing or simple cases)
        (run-with-connection #(doto (DriverManager/getConnection jdbc-url user password)
                               (.setReadOnly true)
                               (.setAutoCommit false)))))))

(defn- create-cache-jdbc-with-connection
  "Internal implementation. The main trex handle has the cache file attached
   as catalog `database-code`; DDL and Appender writes both target it via
   the ext-form appender_create."
  [trexsql-db config progress-fn get-conn-fn start-time database-code schema-name
   cache-path table-filter webapi-ds]
  (with-open [^Connection source-conn (get-conn-fn)]
    (let [tables-to-copy (get-tables-to-copy source-conn trexsql-db database-code schema-name table-filter)
          total-tables (count tables-to-copy)
          exec-id (jobs/write-spring-batch-job! trexsql-db "cacheGeneration"
                    {:database-code database-code :schema-name schema-name})
          _ (jobs/create-local-job! trexsql-db database-code
              {:job-execution-id exec-id
               :source-key database-code
               :status "RUNNING"
               :total-tables total-tables
               :config config})]

      (when progress-fn
        (progress-fn {:phase :job-start :total-tables total-tables}))

      (try
        (loop [remaining tables-to-copy
               idx 1
               tables-copied []
               tables-failed []
               total-rows-processed 0]
          (if (empty? remaining)
            (let [duration-ms (- (System/currentTimeMillis) start-time)
                  success? (empty? tables-failed)]
              (jobs/update-spring-batch-status! trexsql-db exec-id
                (if success? "COMPLETED" "FAILED"))
              (jobs/update-local-status! trexsql-db database-code
                (if success? "COMPLETE" "FAILED"))
              (jobs/update-local-progress! trexsql-db database-code
                {:completed-tables (count tables-copied)
                 :tables-copied tables-copied
                 :tables-failed tables-failed})
              (when progress-fn
                (progress-fn {:phase :job-complete
                              :tables-copied tables-copied
                              :tables-failed tables-failed
                              :duration-ms duration-ms}))
              {:success? success?
               :database-code database-code
               :schema-name schema-name
               :tables-copied tables-copied
               :tables-failed tables-failed
               :duration-ms duration-ms})

            (if (check-cancellation trexsql-db database-code)
              (let [duration-ms (- (System/currentTimeMillis) start-time)]
                (jobs/update-spring-batch-status! trexsql-db exec-id "STOPPED")
                (jobs/update-local-status! trexsql-db database-code "CANCELED")
                {:success? false
                 :database-code database-code
                 :schema-name schema-name
                 :tables-copied tables-copied
                 :tables-failed tables-failed
                 :duration-ms duration-ms
                 :error "Job cancelled by user"})

              (let [table-name (first remaining)
                    _ (when progress-fn
                        (progress-fn {:phase :table-start
                                      :table table-name
                                      :table-index idx
                                      :total-tables total-tables}))
                    _ (jobs/update-local-progress! trexsql-db database-code
                        {:current-table table-name})
                    result (retry-with-backoff
                             #(copy-table-jdbc trexsql-db source-conn database-code table-name config progress-fn)
                             {:max-retries 3
                              :on-retry (fn [attempt err]
                                          (jobs/update-retry-status! trexsql-db database-code
                                            attempt (.getMessage ^Throwable err)))})]
                (if (:success? result)
                  (let [new-total (+ total-rows-processed (or (:rows-copied result) 0))]
                    (when progress-fn
                      (progress-fn {:phase :table-complete
                                    :table table-name
                                    :rows-copied (:rows-copied result)
                                    :duration-ms (:duration-ms result)}))
                    (jobs/update-local-progress! trexsql-db database-code
                      {:completed-tables idx
                       :processed-rows new-total})
                    (recur (rest remaining)
                           (inc idx)
                           (conj tables-copied result)
                           tables-failed
                           new-total))
                  (do
                    (when progress-fn
                      (progress-fn {:phase :table-failed
                                    :table table-name
                                    :error (:error result)}))
                    (recur (rest remaining)
                           (inc idx)
                           tables-copied
                           (conj tables-failed result)
                           total-rows-processed)))))))

        (catch Exception e
          (let [duration-ms (- (System/currentTimeMillis) start-time)
                error-msg (.getMessage e)]
            (jobs/update-spring-batch-status! trexsql-db exec-id "FAILED" error-msg)
            (jobs/update-local-status! trexsql-db database-code "ERROR" error-msg)
            (when progress-fn
              (progress-fn {:phase :job-failed :error error-msg}))
            {:success? false
             :database-code database-code
             :schema-name schema-name
             :tables-copied []
             :tables-failed []
             :duration-ms duration-ms
             :error error-msg}))))))
