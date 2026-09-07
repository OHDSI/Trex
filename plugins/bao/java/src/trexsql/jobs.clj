(ns trexsql.jobs
  "Job tracking for JDBC batch cache operations.
   Dual-write to local _cache_jobs.db and Spring Batch tables."
  (:require [trexsql.db :as db]
            [trexsql.errors :as errors]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [trexsql.json :as json]
            [honey.sql :as sql]
            [honey.sql.helpers :as h])
  (:import [javax.sql DataSource]
           [java.sql Connection DriverManager PreparedStatement ResultSet SQLException]
           [java.util Properties HashMap]
           [java.time Instant LocalDateTime ZoneId]
           [java.io File]))

(def ^:private jobs-db-name "_cache_jobs")

(defn- jobs-table
  "Get qualified jobs table name as keyword."
  [jobs-db]
  (keyword (str jobs-db ".cache_generation_info")))

(def ^:private jobs-db-initialized (atom {}))

(defn get-jobs-db
  "Attach local jobs database. Creates if needed.
   Memoizes initialization per connection to avoid repeated DDL execution."
  [trexsql-db]
  ;; Type-hinted so the compiler emits a direct `new File(...)`. Unhinted, these
  ;; go through clojure.lang.Reflector, which resolves constructors at runtime —
  ;; and inside libwebapi-native.so (GraalVM native-image) that reflection is not
  ;; registered, so it throws. It only surfaced on the native-scanner dialects,
  ;; because those are the ones that reach this from the cache build.
  (let [^String cache-path (or (get-in trexsql-db [:config :cache-path]) "./data/cache")
        cache-dir (File. cache-path)
        jobs-file (File. cache-dir ^String (str jobs-db-name ".db"))
        file-path (.getAbsolutePath jobs-file)
        conn-hash (System/identityHashCode (:handle trexsql-db))]
    (when (not= conn-hash (get @jobs-db-initialized file-path))
      (when-not (.exists cache-dir)
        (.mkdirs cache-dir))
      (let [escaped-path (str/replace file-path "'" "''")
            attach-sql (format "ATTACH IF NOT EXISTS '%s' AS %s" escaped-path jobs-db-name)]
        (db/execute! trexsql-db attach-sql)
        ;; cache_generation_info has JSON-typed columns, so the json
        ;; extension must be loaded before the DDL runs. Idempotent.
        (db/load-extension! trexsql-db "json")
        (db/execute! trexsql-db (str "
          CREATE TABLE IF NOT EXISTS " jobs-db-name ".cache_generation_info (
            database_code     VARCHAR PRIMARY KEY,
            job_execution_id  BIGINT,
            source_key        VARCHAR NOT NULL,
            status            VARCHAR NOT NULL,
            start_time        TIMESTAMP,
            end_time          TIMESTAMP,
            total_tables      INTEGER,
            completed_tables  INTEGER,
            current_table     VARCHAR,
            processed_rows    BIGINT,
            tables_copied     JSON,
            tables_failed     JSON,
            error_message     VARCHAR,
            config            JSON,
            retry_count       INTEGER DEFAULT 0,
            last_error        VARCHAR
          )"))
        (db/execute! trexsql-db (str "
          CREATE TABLE IF NOT EXISTS " jobs-db-name ".study_execution_info (
            study_id          VARCHAR PRIMARY KEY,
            job_execution_id  BIGINT,
            source_key        VARCHAR NOT NULL,
            status            VARCHAR NOT NULL,
            start_time        TIMESTAMP,
            end_time          TIMESTAMP,
            current_module    VARCHAR,
            modules_completed JSON,
            error_message     VARCHAR,
            env_name          VARCHAR,
            database_name     VARCHAR,
            analysis_spec     VARCHAR,
            config            JSON
          )"))
        (swap! jobs-db-initialized assoc file-path conn-hash)))
    jobs-db-name))

(defn create-local-job!
  "Insert job record. Returns database_code."
  [trexsql-db database-code {:keys [job-execution-id source-key status config total-tables]}]
  (let [jobs-db (get-jobs-db trexsql-db)
        now (LocalDateTime/now)
        config-json (when config (json/write-str config))]
    (db/execute-with-params! trexsql-db
      (str "INSERT OR REPLACE INTO " jobs-db ".cache_generation_info "
           "(database_code, job_execution_id, source_key, status, start_time, "
           "total_tables, completed_tables, processed_rows, tables_copied, "
           "tables_failed, config, retry_count) "
           "VALUES (?, ?, ?, ?, ?, ?, 0, 0, '[]', '[]', ?, 0)")
      [database-code
       job-execution-id
       (or source-key database-code)
       (or status "RUNNING")
       now
       (or total-tables 0)
       config-json])
    database-code))

(defn update-local-progress!
  "Update job progress fields."
  [trexsql-db database-code {:keys [completed-tables current-table processed-rows
                                     tables-copied tables-failed]}]
  (let [jobs-db (get-jobs-db trexsql-db)
        set-map (cond-> {}
                  (some? completed-tables) (assoc :completed_tables completed-tables)
                  (some? current-table) (assoc :current_table (str current-table))
                  (some? processed-rows) (assoc :processed_rows processed-rows)
                  (some? tables-copied) (assoc :tables_copied (json/write-str tables-copied))
                  (some? tables-failed) (assoc :tables_failed (json/write-str tables-failed)))]
    (when (seq set-map)
      (let [[update-sql & params] (sql/format
                                    {:update (jobs-table jobs-db)
                                     :set set-map
                                     :where [:= :database_code database-code]})]
        (db/execute-with-params! trexsql-db update-sql (vec params))))))

(defn update-local-status!
  "Update job status. Sets end_time for terminal statuses."
  [trexsql-db database-code status & [error-msg]]
  (let [jobs-db (get-jobs-db trexsql-db)
        now (LocalDateTime/now)
        terminal? (contains? #{"COMPLETE" "ERROR" "CANCELED" "FAILED"} status)
        set-map (cond-> {:status status}
                  terminal? (assoc :end_time now)
                  error-msg (assoc :error_message error-msg))
        [update-sql & params] (sql/format
                                {:update (jobs-table jobs-db)
                                 :set set-map
                                 :where [:= :database_code database-code]})]
    (db/execute-with-params! trexsql-db update-sql (vec params))))

(defn delete-job!
  "Drop the cache_generation_info row for a database code. Called when its cache
   file is deleted, so /cache/status stops reporting a build for a cache that is
   no longer on disk."
  [trexsql-db database-code]
  (let [jobs-db (get-jobs-db trexsql-db)
        [delete-sql & params] (sql/format
                                {:delete-from (jobs-table jobs-db)
                                 :where [:= :database_code database-code]})]
    (db/execute-with-params! trexsql-db delete-sql (vec params))))

(defn- parse-json-field [value]
  (when value
    (let [s (str value)]
      (when-not (or (str/blank? s) (= s "null") (= s "NULL"))
        (try
          (json/read-str s :key-fn keyword)
          (catch Exception _ nil))))))

(defn get-job-status
  "Get job status. Returns nil if not found."
  [trexsql-db database-code]
  (let [jobs-db (get-jobs-db trexsql-db)
        [query-sql & params] (sql/format
                               {:select [:*]
                                :from [(jobs-table jobs-db)]
                                :where [:= :database_code database-code]})
        results (db/query-with-params trexsql-db query-sql (vec params))]
    (when (seq results)
      (let [row (first results)]
        {:database-code (.get ^HashMap row "database_code")
         :job-execution-id (.get ^HashMap row "job_execution_id")
         :source-key (.get ^HashMap row "source_key")
         :status (.get ^HashMap row "status")
         :start-time (.get ^HashMap row "start_time")
         :end-time (.get ^HashMap row "end_time")
         :total-tables (.get ^HashMap row "total_tables")
         :completed-tables (.get ^HashMap row "completed_tables")
         :current-table (.get ^HashMap row "current_table")
         :processed-rows (.get ^HashMap row "processed_rows")
         :tables-copied (parse-json-field (.get ^HashMap row "tables_copied"))
         :tables-failed (parse-json-field (.get ^HashMap row "tables_failed"))
         :error-message (.get ^HashMap row "error_message")
         :config (parse-json-field (.get ^HashMap row "config"))
         :retry-count (.get ^HashMap row "retry_count")
         :last-error (.get ^HashMap row "last_error")}))))

(defn list-jobs
  "List jobs, optionally filtered by status."
  [trexsql-db & {:keys [status]}]
  (let [jobs-db (get-jobs-db trexsql-db)
        base-query {:select [:database_code :source_key :status :start_time :end_time
                             :total_tables :completed_tables :error_message]
                    :from [(jobs-table jobs-db)]
                    :order-by [[:start_time :desc]]}
        query (if status
                (assoc base-query :where [:= :status status])
                base-query)
        [query-sql & params] (sql/format query)
        results (if (seq params)
                  (db/query-with-params trexsql-db query-sql (vec params))
                  (db/query trexsql-db query-sql))]
    (mapv (fn [^HashMap row]
            {:database-code (.get row "database_code")
             :source-key (.get row "source_key")
             :status (.get row "status")
             :start-time (.get row "start_time")
             :end-time (.get row "end_time")
             :total-tables (.get row "total_tables")
             :completed-tables (.get row "completed_tables")
             :error-message (.get row "error_message")})
          results)))

(defn create-study-job!
  "Insert study execution job record. Returns study-id."
  [trexsql-db study-id {:keys [job-execution-id source-key env-name database-name analysis-spec config]}]
  (let [jobs-db (get-jobs-db trexsql-db)
        now (LocalDateTime/now)
        config-json (when config (json/write-str config))]
    (db/execute-with-params! trexsql-db
      (str "INSERT OR REPLACE INTO " jobs-db ".study_execution_info "
           "(study_id, job_execution_id, source_key, status, start_time, "
           "current_module, modules_completed, env_name, database_name, "
           "analysis_spec, config) "
           "VALUES (?, ?, ?, 'RUNNING', ?, '', '[]', ?, ?, ?, ?)")
      [study-id
       job-execution-id
       (or source-key "")
       now
       (or env-name "")
       (or database-name "")
       (or analysis-spec "")
       config-json])
    study-id))

(defn update-study-progress!
  "Update study execution progress from hades_status result."
  [trexsql-db study-id {:keys [status current-module modules-completed error-message]}]
  (let [jobs-db (get-jobs-db trexsql-db)
        set-map (cond-> {}
                  (some? status) (assoc :status status)
                  (some? current-module) (assoc :current_module current-module)
                  (some? modules-completed) (assoc :modules_completed (json/write-str modules-completed))
                  (some? error-message) (assoc :error_message error-message))
        terminal? (contains? #{"COMPLETED" "FAILED" "CANCELLED"} status)
        set-map (if terminal? (assoc set-map :end_time (LocalDateTime/now)) set-map)]
    (when (seq set-map)
      (let [[update-sql & params] (sql/format
                                    {:update (keyword (str jobs-db ".study_execution_info"))
                                     :set set-map
                                     :where [:= :study_id study-id]})]
        (db/execute-with-params! trexsql-db update-sql (vec params))))))

(defn get-study-status
  "Get study execution status. Returns nil if not found."
  [trexsql-db study-id]
  (let [jobs-db (get-jobs-db trexsql-db)
        [query-sql & params] (sql/format
                               {:select [:*]
                                :from [(keyword (str jobs-db ".study_execution_info"))]
                                :where [:= :study_id study-id]})
        results (db/query-with-params trexsql-db query-sql (vec params))]
    (when (seq results)
      (let [row (first results)]
        {:study-id (.get ^HashMap row "study_id")
         :job-execution-id (.get ^HashMap row "job_execution_id")
         :source-key (.get ^HashMap row "source_key")
         :status (.get ^HashMap row "status")
         :start-time (.get ^HashMap row "start_time")
         :end-time (.get ^HashMap row "end_time")
         :current-module (.get ^HashMap row "current_module")
         :modules-completed (parse-json-field (.get ^HashMap row "modules_completed"))
         :error-message (.get ^HashMap row "error_message")
         :env-name (.get ^HashMap row "env_name")
         :database-name (.get ^HashMap row "database_name")
         :analysis-spec (.get ^HashMap row "analysis_spec")
         :config (parse-json-field (.get ^HashMap row "config"))}))))

(defn list-study-jobs
  "List study execution jobs, optionally filtered by status."
  [trexsql-db & {:keys [status]}]
  (let [jobs-db (get-jobs-db trexsql-db)
        base-query {:select [:study_id :source_key :status :start_time :end_time
                             :current_module :modules_completed :error_message
                             :env_name :database_name]
                    :from [(keyword (str jobs-db ".study_execution_info"))]
                    :order-by [[:start_time :desc]]}
        query (if status
                (assoc base-query :where [:= :status status])
                base-query)
        [query-sql & params] (sql/format query)
        results (if (seq params)
                  (db/query-with-params trexsql-db query-sql (vec params))
                  (db/query trexsql-db query-sql))]
    (mapv (fn [^HashMap row]
            {:study-id (.get row "study_id")
             :source-key (.get row "source_key")
             :status (.get row "status")
             :start-time (.get row "start_time")
             :end-time (.get row "end_time")
             :current-module (.get row "current_module")
             :modules-completed (parse-json-field (.get row "modules_completed"))
             :error-message (.get row "error_message")
             :env-name (.get row "env_name")
             :database-name (.get row "database_name")})
          results)))

(defn update-retry-status!
  "Update retry count and last error."
  [trexsql-db database-code retry-count last-error]
  (let [jobs-db (get-jobs-db trexsql-db)
        set-map (cond-> {:retry_count retry-count}
                  last-error (assoc :last_error (str last-error)))
        [update-sql & params] (sql/format
                                {:update (jobs-table jobs-db)
                                 :set set-map
                                 :where [:= :database_code database-code]})]
    (db/execute-with-params! trexsql-db update-sql (vec params))))

(defn store-resume-config!
  "Store config for resume capability."
  [trexsql-db database-code config]
  (let [jobs-db (get-jobs-db trexsql-db)
        config-json (json/write-str config)
        [update-sql & params] (sql/format
                                {:update (jobs-table jobs-db)
                                 :set {:config config-json}
                                 :where [:= :database_code database-code]})]
    (db/execute-with-params! trexsql-db update-sql (vec params))))

(defn get-resume-config
  "Get stored config for resume."
  [trexsql-db database-code]
  (when-let [job-status (get-job-status trexsql-db database-code)]
    (:config job-status)))

(def ^:private terminal-statuses #{"COMPLETED" "FAILED" "STOPPED" "ABANDONED"})

(defn terminal-status? [status]
  (contains? terminal-statuses status))

;; BATCH_JOB_INSTANCE has a unique constraint on (JOB_NAME, JOB_KEY) and JOB_KEY
;; is VARCHAR(32), so a key derived from the params alone collides on the second
;; build of the same cache. Mix in the execution id to keep each build distinct.
(defn- job-key-for [params exec-id]
  (let [raw (str (hash (pr-str params)) "-" exec-id)]
    (subs raw 0 (min 32 (count raw)))))

(def ^:private default-batch-table-prefix "webapi.BATCH_")

(defn- batch-table-prefix [trexsql-db]
  (or (get-in trexsql-db [:config :batch-table-prefix]) default-batch-table-prefix))

;; Only ever built from the configured prefix, never from request data.
(defn- batch-table [prefix suffix]
  (str prefix suffix))

(defn- exec-on-conn!
  "Execute parameterized SQL on an open connection. Returns row count."
  [^Connection conn sql params]
  (with-open [stmt (.prepareStatement conn ^String sql)]
    (doseq [[idx param] (map-indexed vector params)]
      (.setObject stmt (inc idx) param))
    (.executeUpdate stmt)))

(defn- query-on-conn
  "Execute parameterized query on an open connection. Returns first column of first row."
  [^Connection conn sql params]
  (with-open [stmt (.prepareStatement conn ^String sql)]
    (doseq [[idx param] (map-indexed vector params)]
      (.setObject stmt (inc idx) param))
    (with-open [rs (.executeQuery stmt)]
      (when (.next rs)
        (.getObject rs 1)))))

;; WebAPI's DataSource is the JPA-managed Hikari pool, which hands out
;; connections with autocommit off. Borrowing one per statement and closing it
;; therefore discards the write: the JOB_INSTANCE insert never lands and the
;; JOB_EXECUTION insert then fails job_inst_exec_fk. Do the whole write on one
;; connection and commit it, which also makes instance+execution atomic.
;; Type-hinted for the same reason as the File constructors above: unhinted,
;; every call here goes through clojure.lang.Reflector, and inside
;; libwebapi-native.so (GraalVM native-image) HikariDataSource's methods are not
;; registered for reflection, so opening the job threw
;; "No matching field found: getConnection for class HikariDataSource" and every
;; cache build ran without a job row.
(defn- with-tx
  [^DataSource datasource f]
  (with-open [^Connection conn (.getConnection datasource)]
    (let [prev (.getAutoCommit conn)]
      (.setAutoCommit conn false)
      (try
        (let [result (f conn)]
          (.commit conn)
          result)
        (catch Throwable t
          (try (.rollback conn) (catch Exception _ nil))
          (throw t))
        (finally
          (try (.setAutoCommit conn prev) (catch Exception _ nil)))))))

;; The sequence name has to be inlined, not bound: PgJDBC binds a String as
;; varchar and PostgreSQL only has nextval(regclass), so a parameterized
;; NEXTVAL(?) throws and the job silently goes unrecorded.
(defn- next-sequence-value [^Connection conn sequence-name]
  (query-on-conn conn (str "SELECT nextval('" sequence-name "')") []))

;; WebAPI renders these as the job's parameters, and its /job/execution query
;; left-joins them, so a job without them still lists -- just with no detail.
(defn- write-batch-job-params! [^Connection conn prefix exec-id params]
  (doseq [[k v] params
          :when (some? v)]
    (exec-on-conn!
      conn
      (str "INSERT INTO " (batch-table prefix "JOB_EXECUTION_PARAMS")
           " (job_execution_id, parameter_name, parameter_type, parameter_value, identifying)"
           " VALUES (?, ?, ?, ?, ?)")
      [exec-id (name k) "java.lang.String" (str v) "N"])))

(declare get-webapi-datasource)

(defn write-spring-batch-job!
  "Open a Spring Batch execution so the build shows up in WebAPI's job overview.
   Returns job-execution-id, or nil when no WebAPI datasource is configured."
  [trexsql-db job-name job-params]
  (let [webapi-ds (get-webapi-datasource trexsql-db)
        prefix (batch-table-prefix trexsql-db)]
   (when webapi-ds
    (try
      (with-tx webapi-ds
        (fn [conn]
          (let [instance-id (next-sequence-value conn (batch-table prefix "JOB_SEQ"))
                exec-id (next-sequence-value conn (batch-table prefix "JOB_EXECUTION_SEQ"))
                now (java.sql.Timestamp. (System/currentTimeMillis))]
            (when (and instance-id exec-id)
              (exec-on-conn!
                conn
                (str "INSERT INTO " (batch-table prefix "JOB_INSTANCE")
                     " (job_instance_id, job_name, job_key, version) VALUES (?, ?, ?, ?)")
                [instance-id job-name (job-key-for job-params exec-id) 0])
              (exec-on-conn!
                conn
                (str "INSERT INTO " (batch-table prefix "JOB_EXECUTION")
                     " (job_execution_id, job_instance_id, create_time, start_time,"
                     "  status, version, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
                [exec-id instance-id now now "STARTED" 0 now])
              (write-batch-job-params! conn prefix exec-id
                                       (assoc job-params :jobName job-name))
              exec-id))))
      (catch SQLException e
        (log/warn (format "Failed to write Spring Batch job: %s" (.getMessage e)))
        nil)))))

;; WebAPI maps this column straight through BatchStatus/valueOf inside a
;; ResultSetExtractor, so an unknown value 500s /job/execution for every job,
;; not just this row. The local registry's vocabulary (COMPLETE/ERROR/CANCELED)
;; must never reach here.
(def ^:private batch-statuses
  #{"COMPLETED" "STARTING" "STARTED" "STOPPING" "STOPPED" "FAILED" "ABANDONED" "UNKNOWN"})

(defn update-spring-batch-status!
  "Close or update a Spring Batch execution."
  [trexsql-db exec-id status & [exit-message]]
  (let [webapi-ds (get-webapi-datasource trexsql-db)
        prefix (batch-table-prefix trexsql-db)]
   (when (and webapi-ds exec-id)
    (if-not (contains? batch-statuses status)
      (log/error (format "Refusing to write non-BatchStatus value %s to %s" status
                         (batch-table prefix "JOB_EXECUTION")))
      (try
        (let [now (java.sql.Timestamp. (System/currentTimeMillis))
              terminal? (terminal-status? status)
              truncate (fn [^String s] (when s (subs s 0 (min 2500 (count s)))))]
          (with-tx webapi-ds
            (fn [conn]
              (if terminal?
                (exec-on-conn!
                  conn
                  (str "UPDATE " (batch-table prefix "JOB_EXECUTION")
                       " SET status = ?, end_time = ?, exit_code = ?, exit_message = ?,"
                       "     last_updated = ?, version = COALESCE(version, 0) + 1"
                       " WHERE job_execution_id = ?")
                  [status now status (truncate exit-message) now exec-id])
                (exec-on-conn!
                  conn
                  (str "UPDATE " (batch-table prefix "JOB_EXECUTION")
                       " SET status = ?, last_updated = ?, version = COALESCE(version, 0) + 1"
                       " WHERE job_execution_id = ?")
                  [status now exec-id])))))
        (catch SQLException e
          (log/warn (format "Failed to update Spring Batch status: %s" (.getMessage e)))))))))

(defn get-webapi-datasource
  "Get WebAPI datasource from config. Returns nil if not configured."
  [trexsql-db]
  (get-in trexsql-db [:config :webapi-datasource]))

(defn start-cache-job!
  "Open a cache-generation job: a Spring Batch execution (so the build shows up
   in WebAPI's job overview alongside every other job) plus the local
   cache_generation_info row that drives /cache/status. Returns the Spring Batch
   execution id, or nil when no WebAPI datasource is configured.

   Both cache paths must call this. The JDBC path opens its job inline because
   it also drives per-table progress and cancellation from the same loop; the
   native-scanner path (postgres/mysql/bigquery) copies in one statement and has
   no such loop, so without this it produced no job row at all — leaving builds
   invisible in the overview and every status reading as instantly ready."
  [trexsql-db database-code schema-name & [total-tables]]
  (let [exec-id (write-spring-batch-job! trexsql-db "cacheGeneration"
                  {:database-code database-code :schema-name schema-name
                   :source_key database-code})]
    (create-local-job! trexsql-db database-code
      {:job-execution-id exec-id
       :source-key database-code
       :status "RUNNING"
       :total-tables (or total-tables 0)})
    exec-id))

(defn finish-cache-job!
  "Close a job opened by start-cache-job!, mirroring the terminal status into
   both the Spring Batch row and cache_generation_info. `error-msg` is recorded
   so callers see why a build failed instead of a bare `undefined`."
  [trexsql-db database-code exec-id success? & [error-msg]]
  (do
    (when exec-id
      (update-spring-batch-status! trexsql-db exec-id
                                   (if success? "COMPLETED" "FAILED") error-msg))
    (update-local-status! trexsql-db database-code
                          (if success? "COMPLETE" "ERROR")
                          error-msg)))
