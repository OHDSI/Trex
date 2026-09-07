(ns trexsql.db
  "TrexSQL connection management and query execution via native C API."
  (:require [clojure.string :as str]
            [clojure.tools.logging :as log]
            [trexsql.native :as native]
            [trexsql.errors :as errors]
            [trexsql.source-dsn :as source-dsn])
  (:import [com.sun.jna Pointer]
           [java.util ArrayList HashMap]))

(def ^:private identifier-pattern
  "Valid SQL identifier pattern: starts with letter/underscore,
   contains only alphanumeric and underscores, max 128 chars."
  #"^[a-zA-Z_][a-zA-Z0-9_]{0,127}$")

(defn validate-identifier
  "Validate that a string is a safe SQL identifier.
   Returns nil if valid, error message if invalid.
   Valid identifiers: start with letter/underscore, contain only alphanumeric/underscore."
  [^String s]
  (cond
    (nil? s)
    "Identifier cannot be nil"

    (str/blank? s)
    "Identifier cannot be empty"

    (> (count s) 128)
    (str "Identifier too long (max 128 chars): " (subs s 0 32) "...")

    (not (re-matches identifier-pattern s))
    (str "Invalid identifier '" s "'. Must start with letter/underscore and contain only alphanumeric/underscore characters.")

    :else nil))

(defn validate-identifier!
  "Validate identifier and throw validation error if invalid."
  [^String s ^String context]
  (when-let [error (validate-identifier s)]
    (throw (errors/validation-error (str context ": " error) {:field context}))))

(defn escape-identifier
  "Escape a SQL identifier by wrapping in double quotes and escaping internal quotes.
   Validates the identifier first to prevent SQL injection.
   Throws IllegalArgumentException if identifier is invalid."
  [^String s ^String context]
  (validate-identifier! s context)
  (str "\"" (str/replace s "\"" "\"\"") "\""))

(defn create-connection
  "Create a TrexSQL native connection.
   Returns a JNA Pointer handle to the database.
   Config options:
   - :allow-unsigned-extensions - enable loading unsigned extensions

   When running embedded as the trex DuckDB extension (trexsql.use.pool=true),
   acquire a trex pool session so queries share the host engine instance (same
   catalog/cache as the runtime). Otherwise (standalone JVM) open our own
   ':memory:' database. Falls back to ':memory:' if the pool is unavailable."
  ([]
   (create-connection {}))
  ([config]
   (let [flags (if (:allow-unsigned-extensions config) 1 0)]
     (if (= "true" (System/getProperty "trexsql.use.pool"))
       (try
         (log/info "Acquiring trex pool session (shared host instance)")
         (native/open-pool-session)
         (catch Exception e
           (log/warn (str "pool session unavailable, opening own :memory: db: " (.getMessage e)))
           (native/open ":memory:" flags)))
       (native/open ":memory:" flags)))))

(defrecord TrexsqlDatabase [handle                ; JNA Pointer to native TrexDatabase
                            extensions-loaded      ; atom of set
                            config
                            closed?])              ; atom of boolean

(defn make-database
  "Create a new TrexsqlDatabase record.
   Uses atoms for mutable state (closed?, extensions-loaded)."
  [handle config]
  (map->TrexsqlDatabase {:handle handle
                         :extensions-loaded (atom #{})
                         :config config
                         :closed? (atom false)}))

(defn ensure-open!
  "Throw resource error if database is closed."
  [^TrexsqlDatabase db]
  (when @(:closed? db)
    (throw (errors/resource-error "Database is closed" :connection))))

(defn close!
  "Close the database connection and mark as closed."
  [^TrexsqlDatabase db]
  (when-not @(:closed? db)
    (when-let [handle (:handle db)]
      (native/close! handle))
    (reset! (:closed? db) true)))

(defn closed?
  "Check if the database connection is closed."
  [^TrexsqlDatabase db]
  @(:closed? db))

(defn extension-loaded?
  "Check if an extension has been loaded in this database session."
  [^TrexsqlDatabase db ^String ext-name]
  (contains? @(:extensions-loaded db) ext-name))

(defn load-extension!
  "Load a TrexSQL extension if not already loaded.
   Caches loaded extensions to avoid redundant INSTALL/LOAD calls.
   Returns true if extension was loaded, false if already loaded."
  [^TrexsqlDatabase db ^String ext-name & {:keys [source] :or {source nil}}]
  (ensure-open! db)
  (if (extension-loaded? db ext-name)
    false
    (do
      (let [install-sql (if source
                          (format "INSTALL %s FROM %s" ext-name source)
                          (format "INSTALL %s" ext-name))]
        (try
          (native/execute! (:handle db) install-sql)
          (catch Exception e
            (log/debug (format "Extension %s install returned: %s (may already be installed)"
                               ext-name (.getMessage e)))))
        (native/execute! (:handle db) (format "LOAD %s" ext-name)))
      (swap! (:extensions-loaded db) conj ext-name)
      true)))

(defn query
  "Execute a SQL query and return results as ArrayList<HashMap>.
   Throws sql-error on error.
   Throws resource-error if database is closed."
  [^TrexsqlDatabase db ^String sql]
  (ensure-open! db)
  (native/query (:handle db) sql))

(defn execute!
  "Execute a non-query SQL statement (DDL, DML, LOAD, etc.).
   Returns true on success.
   Throws sql-error on error.
   Throws resource-error if database is closed."
  [^TrexsqlDatabase db ^String sql]
  (ensure-open! db)
  (native/execute! (:handle db) sql))

(defn open-cache-handle!
  "Open a fresh TrexsqlDatabase pointed directly at the cache file for
   `database-code`. The cache file becomes the default catalog of the
   returned handle, which is what the trex native Appender API needs to
   resolve table names — the Appender takes (schema, table) and looks up
   in the connection's default database, not in any attached catalog.

   The caller is responsible for closing the returned handle (via
   `close!`) when the cache build is finished."
  [^String database-code ^String cache-path]
  (validate-identifier! database-code "database-code")
  (let [cache-dir (java.io.File. cache-path)
        cache-file (java.io.File. cache-dir (str database-code ".db"))
        file-path (.getAbsolutePath cache-file)]
    (when-not (.exists cache-dir)
      (.mkdirs cache-dir))
    (let [handle (native/open file-path 0)]
      (when (nil? handle)
        (throw (errors/resource-error
                (str "Failed to open cache handle at " file-path)
                :cache-file)))
      (make-database handle {:cache-path cache-path
                             :database-code database-code}))))

;; The trex handle is shared across WebAPI's request threads, but the pool
;; hands out one Connection per session and `take_conn` (plugins/pool) returns
;; `session <n> busy` rather than waiting when another thread already holds it.
;; Two concurrent requests therefore make ATTACH fail even though nothing is
;; wrong — and a failed auto-attach leaves the frontend seeing
;; `cacheAttached:false`, which it maps to status='error' and then refuses to
;; fire any count/inclusion calls. The contention is brief (one query), so a
;; bounded retry turns it back into a wait; a session held longer than the
;; budget still surfaces the original error.
(defn- session-busy-error?
  [^Throwable e]
  (boolean (some->> (.getMessage e) (re-find #"(?i)session \d+ busy"))))

(def ^:private busy-max-attempts 5)

(defn- retry-while-busy
  "Call f, retrying only the transient session-busy failure. Any other error
   propagates on the first attempt so real failures are not masked."
  [f]
  (loop [attempt 1
         delay-ms 20]
    (let [outcome (try
                    {:value (f)}
                    (catch Exception e
                      (if (and (session-busy-error? e) (< attempt busy-max-attempts))
                        {:busy e}
                        (throw e))))]
      (if (contains? outcome :value)
        (:value outcome)
        (do
          (Thread/sleep (long delay-ms))
          (recur (inc attempt) (min (* delay-ms 2) 200)))))))

(defn attach-cache-file!
  "Attach a TrexSQL cache file. If the alias is already attached but the
   underlying file no longer exists (e.g. it was deleted on disk while the
   trex handle still held the alias), DETACH first so the new ATTACH
   actually creates a fresh file. Without this, `ATTACH IF NOT EXISTS`
   silently no-ops on the stale alias and downstream
   `information_schema.tables` queries report the in-memory stale catalog,
   making `get-completed-tables` return tables that don't exist on disk
   and `tables-to-copy` come out empty.

   Returns the database alias on success.
   Throws IllegalArgumentException if database-code is invalid.
   Throws RuntimeException if the cache file is locked or on other errors."
  [^TrexsqlDatabase db ^String database-code ^String cache-path]
  (ensure-open! db)
  (let [escaped-alias (escape-identifier database-code "database-code")
        cache-dir (java.io.File. cache-path)
        cache-file (java.io.File. cache-dir (str database-code ".db"))
        file-path (.getAbsolutePath cache-file)
        escaped-path (str/replace file-path "'" "''")
        already-attached?
        (try
          (let [results (query db "SELECT database_name FROM duckdb_databases()")]
            (boolean (some #(= database-code (.get ^HashMap % "database_name")) results)))
          (catch Exception _ false))
        file-exists? (.exists cache-file)]
    (when-not (.exists cache-dir)
      (.mkdirs cache-dir))
    ;; Stale-handle case: alias is attached but the file is gone. Detach
    ;; before re-attaching so DuckDB reads a fresh empty file from disk.
    (when (and already-attached? (not file-exists?))
      (try (execute! db (format "DETACH %s" escaped-alias))
           (catch Exception _ nil)))
    (try
      (retry-while-busy
        #(execute! db (format "ATTACH IF NOT EXISTS '%s' AS %s"
                              escaped-path
                              escaped-alias)))
      database-code
      (catch clojure.lang.ExceptionInfo e
        (if (re-find #"(?i)lock" (.getMessage e))
          (throw (errors/resource-error
                  (str "Cache file is locked by another process: " file-path)
                  :cache-file))
          (throw e))))))

;; === Native source attach (DuckDB scanners) ===
;; Source attached as alias "<database-code>__srcdb" on the same handle that
;; holds the cache, so a cross-catalog CREATE TABLE AS SELECT copies the data.

(defn- source-alias-for [database-code]
  (str database-code "__srcdb"))

(defn- sql-literal
  "Single-quoted SQL string literal (doubling internal quotes) for the ATTACH DSN."
  [s]
  (str "'" (str/replace s "'" "''") "'"))

(defn postgres-attach-sql
  "READ_ONLY postgres ATTACH statement for a source. Pure."
  [database-code credentials]
  (validate-identifier! database-code "database-code")
  (format "ATTACH IF NOT EXISTS %s AS %s (TYPE postgres, READ_ONLY)"
          (sql-literal (source-dsn/postgres-dsn credentials))
          (escape-identifier (source-alias-for database-code) "source-alias")))

(defn mysql-attach-sql
  "READ_ONLY mysql ATTACH statement for a source. Pure."
  [database-code credentials]
  (validate-identifier! database-code "database-code")
  (format "ATTACH IF NOT EXISTS %s AS %s (TYPE mysql, READ_ONLY)"
          (sql-literal (source-dsn/mysql-dsn credentials))
          (escape-identifier (source-alias-for database-code) "source-alias")))

(defn bigquery-attach-sql
  "BigQuery ATTACH statement (inherently read-only). Pure."
  [database-code credentials]
  (validate-identifier! database-code "database-code")
  (format "ATTACH IF NOT EXISTS 'project=%s' AS %s (TYPE bigquery)"
          (source-dsn/bigquery-project credentials)
          (escape-identifier (source-alias-for database-code) "source-alias")))

(defn- redact-credentials
  "Replace literal user/password values with *** so a failed-ATTACH error can't
   leak them (robust to quoting). Blank values are skipped."
  [^String s {:keys [user password]}]
  (cond-> (str s)
    (not (str/blank? password)) (str/replace (str password) "***")
    (not (str/blank? user))     (str/replace (str user) "***")))

(defn- execute-attach!
  "Run an ATTACH, redacting credentials from any thrown error. The original
   cause is dropped on purpose — errors/format-error would surface its message
   (which can echo the connection string) into JSON responses."
  [^TrexsqlDatabase db ^String attach-sql credentials]
  (try
    (execute! db attach-sql)
    (catch Exception e
      (throw (errors/resource-error
              (str "Source ATTACH failed: " (redact-credentials (.getMessage e) credentials))
              :source)))))

(defn attach-source-postgres!
  "INSTALL/LOAD the postgres scanner and ATTACH the source. Returns the alias."
  [^TrexsqlDatabase db ^String database-code credentials]
  (ensure-open! db)
  (load-extension! db "postgres")
  (execute-attach! db (postgres-attach-sql database-code credentials) credentials)
  (source-alias-for database-code))

(defn attach-source-mysql!
  "INSTALL/LOAD the mysql scanner and ATTACH the source. Returns the alias."
  [^TrexsqlDatabase db ^String database-code credentials]
  (ensure-open! db)
  (load-extension! db "mysql")
  (execute-attach! db (mysql-attach-sql database-code credentials) credentials)
  (source-alias-for database-code))

(defn attach-source-bigquery!
  "INSTALL/LOAD the bigquery (community) scanner and ATTACH. Returns the alias."
  [^TrexsqlDatabase db ^String database-code credentials]
  (ensure-open! db)
  (load-extension! db "bigquery" :source "community")
  (execute-attach! db (bigquery-attach-sql database-code credentials) credentials)
  (source-alias-for database-code))

(defn is-attached?
  "Check if a database with the given alias is currently attached.
   Returns true if attached, false otherwise.
   Throws RuntimeException on SQL errors."
  [^TrexsqlDatabase db ^String database-alias]
  (ensure-open! db)
  (let [results (query db "SELECT database_name FROM duckdb_databases()")]
    (boolean (some #(= database-alias (.get ^HashMap % "database_name")) results))))

(defn detach-database!
  "Detach a previously attached database.
   Throws validation-error if database-alias is invalid.
   Throws resource-error if the database is not attached."
  [^TrexsqlDatabase db ^String database-alias]
  (ensure-open! db)
  (let [escaped-alias (escape-identifier database-alias "database-alias")]
    (when-not (is-attached? db database-alias)
      (throw (errors/resource-error (str "Database is not attached: " database-alias) :database)))
    (execute! db (format "DETACH %s" escaped-alias))))

(defn query-with-params
  "Execute a parameterized SQL query and return results as ArrayList<HashMap>.
   Params is a vector of values to bind to ? placeholders in the SQL.
   Uses string interpolation with proper escaping.
   Throws sql-error on error.
   Throws resource-error if database is closed."
  [^TrexsqlDatabase db ^String sql params]
  (ensure-open! db)
  (native/query-with-params (:handle db) sql params))

(defn execute-with-params!
  "Execute a parameterized non-query SQL statement (INSERT, UPDATE, DELETE).
   Params is a vector of values to bind to ? placeholders in the SQL.
   Uses string interpolation with proper escaping.
   Throws sql-error on error.
   Throws resource-error if database is closed."
  [^TrexsqlDatabase db ^String sql params]
  (ensure-open! db)
  (native/execute-with-params! (:handle db) sql params))

(defn get-raw-handle
  "Get the underlying native database handle. Use with caution - prefer using
   query, execute!, etc. for normal operations.
   Throws resource-error if database is closed."
  ^Pointer [^TrexsqlDatabase db]
  (ensure-open! db)
  (:handle db))

(defn running-servers
  "Query the trexsql engine for currently-running trexas servers.
   Returns a vector of maps with keys :server-id, :host, :port, :status.
   Returns empty vector if the trexas extension isn't loaded yet."
  [^TrexsqlDatabase db]
  (try
    (->> (query db "SELECT server_id, ip, port, status FROM trex_list_servers()")
         (mapv (fn [row]
                 {:server-id (get row "server_id")
                  :host      (get row "ip")
                  :port      (get row "port")
                  :status    (get row "status")})))
    (catch Exception _
      [])))
