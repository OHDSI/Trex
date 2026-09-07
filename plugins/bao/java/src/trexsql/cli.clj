(ns trexsql.cli
  "CLI commands for cache operations.
   Provides cache create, status, and cancel subcommands."
  (:require [trexsql.core :as core]
            [trexsql.jobs :as jobs]
            [trexsql.batch :as batch]
            [clojure.tools.cli :refer [parse-opts]]
            [clojure.string :as str]
            [trexsql.json :as json]))

;; Cache Create Command

(def cache-create-options
  [["-s" "--source SOURCE" "Source key or database code (required)"
    :missing "Source is required"]
   ["-j" "--jdbc-url URL" "JDBC connection URL (required for JDBC sources)"
    :default nil]
   ["-u" "--user USER" "Database username"
    :default nil]
   ["-p" "--password PASSWORD" "Database password"
    :default nil]
   ["-d" "--dialect DIALECT" "Database dialect (sql server, oracle, mysql, mariadb, postgres, bigquery)"
    :default nil]
   ["-S" "--schema SCHEMA" "Schema name to copy (required)"
    :missing "Schema name is required"]
   ["-b" "--batch-size SIZE" "Rows per batch (100-100000)"
    :default 10000
    :parse-fn #(Integer/parseInt %)
    :validate [#(<= 100 % 100000) "Batch size must be between 100 and 100000"]]
   ["-t" "--tables TABLES" "Comma-separated list of tables to copy"
    :default nil
    :parse-fn #(str/split % #",")]
   ["-c" "--cache-path PATH" "Cache directory path"
    :default "./data/cache"]
   [nil "--json" "Output result as JSON"
    :default false]
   ["-h" "--help" "Show this help message"]])

(defn cache-create-help []
  "cache create - Create a TrexSQL cache from a source database

Usage: trexsql cache create [options]

Options:
  -s, --source SOURCE      Source key or database code (required)
  -j, --jdbc-url URL       JDBC connection URL (required for JDBC sources)
  -u, --user USER          Database username
  -p, --password PASSWORD  Database password
  -d, --dialect DIALECT    Database dialect (sql server, oracle, mysql, etc.)
  -S, --schema SCHEMA      Schema name to copy (required)
  -b, --batch-size SIZE    Rows per batch (default: 10000)
  -t, --tables TABLES      Comma-separated list of tables to copy
  -c, --cache-path PATH    Cache directory path (default: ./data/cache)
      --json               Output result as JSON
  -h, --help               Show this help message

Examples:
  # Create cache from SQL Server
  trexsql cache create -s my-source -j \"jdbc:sqlserver://host:1433\" -u admin -p secret -d \"sql server\" -S cdm

  # Create cache with specific tables
  trexsql cache create -s my-source -j \"jdbc:mysql://host:3306/db\" -u admin -p secret -d mysql -S cdm -t person,observation")

(defn print-progress [event]
  (let [phase (:phase event)]
    (case phase
      :job-start
      (println (format "Starting cache creation: %d tables to copy" (:total-tables event)))

      :table-start
      (println (format "[%d/%d] Copying table: %s"
                       (:table-index event)
                       (:total-tables event)
                       (:table event)))

      :row-progress
      (print (format "\r  Rows: %,d" (:rows-processed event)))

      :table-complete
      (println (format "\n  Completed: %,d rows in %,d ms"
                       (:rows-copied event)
                       (:duration-ms event)))

      :table-failed
      (println (format "\n  FAILED: %s" (:error event)))

      :job-complete
      (do
        (println (format "\nCache creation complete:"))
        (println (format "  Tables copied: %d" (count (:tables-copied event))))
        (println (format "  Tables failed: %d" (count (:tables-failed event))))
        (println (format "  Duration: %,d ms" (:duration-ms event))))

      :job-failed
      (println (format "\nCache creation FAILED: %s" (:error event)))

      nil)))

(defn run-cache-create [args]
  (let [{:keys [options errors summary]} (parse-opts args cache-create-options)]
    (cond
      (:help options)
      (do
        (println (cache-create-help))
        {:exit-code 0})

      (seq errors)
      (do
        (doseq [err errors]
          (println (str "Error: " err)))
        (println "\nUse 'trexsql cache create --help' for usage information.")
        {:exit-code 1})

      :else
      (let [{:keys [source jdbc-url user password dialect schema batch-size tables cache-path json]} options
            db (core/init {:cache-path cache-path})
            ;; Build config for JDBC batch transfer
            batch-config {:source-credentials {:jdbc-url jdbc-url
                                               :user user
                                               :password password
                                               :dialect dialect}
                          :schema-name schema
                          :database-code source
                          :batch-size (or batch-size 10000)
                          :table-filter tables
                          :cache-path cache-path}
            progress-fn (when-not json print-progress)]
        (try
          ;; Use batch/create-cache-jdbc for JDBC sources with progress support
          (let [result (batch/create-cache-jdbc db batch-config progress-fn)]
            (if json
              (println (json/write-str
                        {:success (:success? result)
                         :databaseCode (:database-code result)
                         :schemaName (:schema-name result)
                         :tablesCopied (count (:tables-copied result))
                         :tablesFailed (count (:tables-failed result))
                         :durationMs (:duration-ms result)
                         :error (:error result)}))
              (when-not (:success? result)
                (println (format "\nError: %s" (:error result)))))
            {:exit-code (if (:success? result) 0 1)})
          (catch Exception e
            (if json
              (println (json/write-str {:success false :error (.getMessage e)}))
              (println (format "Error: %s" (.getMessage e))))
            {:exit-code 1})
          (finally
            (core/shutdown! db)))))))

;; Cache Status Command

(def cache-status-options
  [["-s" "--source SOURCE" "Source key or database code (required)"
    :missing "Source is required"]
   ["-c" "--cache-path PATH" "Cache directory path"
    :default "./data/cache"]
   [nil "--json" "Output result as JSON"
    :default false]
   ["-h" "--help" "Show this help message"]])

(defn cache-status-help []
  "cache status - Get status of a cache and any running job

Usage: trexsql cache status [options]

Options:
  -s, --source SOURCE      Source key or database code (required)
  -c, --cache-path PATH    Cache directory path (default: ./data/cache)
      --json               Output result as JSON
  -h, --help               Show this help message

Examples:
  trexsql cache status -s my-source
  trexsql cache status -s my-source --json")

(defn run-cache-status [args]
  (let [{:keys [options errors summary]} (parse-opts args cache-status-options)]
    (cond
      (:help options)
      (do
        (println (cache-status-help))
        {:exit-code 0})

      (seq errors)
      (do
        (doseq [err errors]
          (println (str "Error: " err)))
        {:exit-code 1})

      :else
      (let [{:keys [source cache-path json]} options
            db (core/init {:cache-path cache-path})
            cache-file (java.io.File. ^String cache-path ^String (str source ".db"))
            exists? (.exists cache-file)]
        (try
          (let [job-status (try (jobs/get-job-status db source) (catch Exception _ nil))
                result {:sourceKey source
                        :cacheExists exists?
                        :cacheFilePath (when exists? (.getAbsolutePath cache-file))
                        :cacheSizeBytes (when exists? (.length cache-file))
                        :job (when job-status
                               {:status (:status job-status)
                                :startTime (str (:start-time job-status))
                                :endTime (when (:end-time job-status) (str (:end-time job-status)))
                                :totalTables (:total-tables job-status)
                                :completedTables (:completed-tables job-status)
                                :currentTable (:current-table job-status)
                                :processedRows (:processed-rows job-status)
                                :error (:error-message job-status)})}]
            (if json
              (println (json/write-str result))
              (do
                (println (format "Source: %s" source))
                (println (format "Cache exists: %s" exists?))
                (when exists?
                  (println (format "Cache file: %s" (.getAbsolutePath cache-file)))
                  (println (format "Cache size: %,d bytes" (.length cache-file))))
                (when job-status
                  (println (format "\nJob status: %s" (:status job-status)))
                  (println (format "Started: %s" (:start-time job-status)))
                  (when (:end-time job-status)
                    (println (format "Ended: %s" (:end-time job-status))))
                  (println (format "Progress: %d/%d tables"
                                   (or (:completed-tables job-status) 0)
                                   (or (:total-tables job-status) 0)))
                  (when (:current-table job-status)
                    (println (format "Current table: %s" (:current-table job-status))))
                  (when (:error-message job-status)
                    (println (format "Error: %s" (:error-message job-status)))))))
            {:exit-code 0})
          (catch Exception e
            (if json
              (println (json/write-str {:error (.getMessage e)}))
              (println (format "Error: %s" (.getMessage e))))
            {:exit-code 1})
          (finally
            (core/shutdown! db)))))))

;; Cache Cancel Command

(def cache-cancel-options
  [["-s" "--source SOURCE" "Source key or database code (required)"
    :missing "Source is required"]
   ["-c" "--cache-path PATH" "Cache directory path"
    :default "./data/cache"]
   [nil "--json" "Output result as JSON"
    :default false]
   ["-h" "--help" "Show this help message"]])

(defn cache-cancel-help []
  "cache cancel - Cancel a running cache job

Usage: trexsql cache cancel [options]

Options:
  -s, --source SOURCE      Source key or database code (required)
  -c, --cache-path PATH    Cache directory path (default: ./data/cache)
      --json               Output result as JSON
  -h, --help               Show this help message

Examples:
  trexsql cache cancel -s my-source")

(defn run-cache-cancel [args]
  (let [{:keys [options errors summary]} (parse-opts args cache-cancel-options)]
    (cond
      (:help options)
      (do
        (println (cache-cancel-help))
        {:exit-code 0})

      (seq errors)
      (do
        (doseq [err errors]
          (println (str "Error: " err)))
        {:exit-code 1})

      :else
      (let [{:keys [source cache-path json]} options
            db (core/init {:cache-path cache-path})]
        (try
          (let [job-status (jobs/get-job-status db source)]
            (cond
              (nil? job-status)
              (do
                (if json
                  (println (json/write-str {:success false :error "No job found"}))
                  (println (format "No cache job found for: %s" source)))
                {:exit-code 1})

              (not= "RUNNING" (:status job-status))
              (do
                (if json
                  (println (json/write-str {:success false
                                            :error (format "Job is not running. Current status: %s" (:status job-status))}))
                  (println (format "Job is not running. Current status: %s" (:status job-status))))
                {:exit-code 1})

              :else
              (do
                (jobs/update-local-status! db source "CANCELED")
                (if json
                  (println (json/write-str {:success true :status "CANCELED" :message "Job cancellation requested"}))
                  (println "Job cancellation requested. The job will stop after completing the current table."))
                {:exit-code 0})))
          (catch Exception e
            (if json
              (println (json/write-str {:success false :error (.getMessage e)}))
              (println (format "Error: %s" (.getMessage e))))
            {:exit-code 1})
          (finally
            (core/shutdown! db)))))))

;; Cache Help

(defn cache-help []
  "cache - Manage TrexSQL caches from source databases

Usage: trexsql cache <command> [options]

Commands:
  create     Create a TrexSQL cache from a source database
  status     Get status of a cache and any running job
  cancel     Cancel a running cache job

Use 'trexsql cache <command> --help' for more information about a command.

Examples:
  trexsql cache create -s my-source -j \"jdbc:sqlserver://host\" -u admin -p secret -d \"sql server\" -S cdm
  trexsql cache status -s my-source
  trexsql cache cancel -s my-source")

(defn run-cache [args]
  (let [subcommand (first args)
        sub-args (rest args)]
    (case subcommand
      "create" (run-cache-create sub-args)
      "status" (run-cache-status sub-args)
      "cancel" (run-cache-cancel sub-args)
      "--help" (do (println (cache-help)) {:exit-code 0})
      "-h" (do (println (cache-help)) {:exit-code 0})
      nil (do (println (cache-help)) {:exit-code 0})
      (do
        (println (format "Unknown cache command: %s" subcommand))
        (println "\nUse 'trexsql cache --help' for usage information.")
        {:exit-code 1}))))

;; Bundle Command

(def bundle-options
  [["-e" "--entrypoint PATH" "Path to entrypoint file (required)"
    :missing "Entrypoint is required"]
   ["-o" "--output PATH" "Output eszip file path (required)"
    :missing "Output path is required"]
   ["-c" "--checksum TYPE" "Checksum type: none, sha256, xxhash3"
    :default nil]
   ["-s" "--static PATTERN" "Static file glob pattern (can be repeated)"
    :default []
    :assoc-fn (fn [m k v] (update m k conj v))]
   ["-t" "--timeout SECONDS" "Bundle timeout in seconds"
    :default nil
    :parse-fn #(Integer/parseInt %)]
   [nil "--no-module-cache" "Disable module caching"
    :default false]
   [nil "--json" "Output result as JSON"
    :default false]
   ["-h" "--help" "Show this help message"]])

(defn bundle-help []
  "bundle - Create an eszip bundle from a TypeScript/JavaScript entrypoint

Usage: trexsql bundle [options]

Options:
  -e, --entrypoint PATH    Path to entrypoint file (required)
  -o, --output PATH        Output eszip file path (required)
  -c, --checksum TYPE      Checksum type: none, sha256, xxhash3
  -s, --static PATTERN     Static file glob pattern (can be repeated)
  -t, --timeout SECONDS    Bundle timeout in seconds
      --no-module-cache    Disable module caching
      --json               Output result as JSON
  -h, --help               Show this help message

Examples:
  # Basic bundle
  trexsql bundle -e main.ts -o output.eszip

  # With checksum and static files
  trexsql bundle -e main.ts -o output.eszip -c sha256 -s \"assets/**/*\"

  # With timeout
  trexsql bundle -e main.ts -o output.eszip -t 60")

(defn run-bundle [args]
  (let [{:keys [options errors]} (parse-opts args bundle-options)]
    (cond
      (:help options)
      (do
        (println (bundle-help))
        {:exit-code 0})

      (seq errors)
      (do
        (doseq [err errors]
          (println (str "Error: " err)))
        (println "\nUse 'trexsql bundle --help' for usage information.")
        {:exit-code 1})

      :else
      (let [{:keys [entrypoint output checksum static timeout no-module-cache json]} options
            db (core/init {})]
        (try
          (let [options-map (cond-> {}
                              checksum (assoc :checksum checksum)
                              (seq static) (assoc :static_patterns static)
                              no-module-cache (assoc :no_module_cache true)
                              timeout (assoc :timeout_sec timeout))
                options-json (when (seq options-map) (json/write-str options-map))
                sql (if options-json
                      (format "SELECT trex_create_bundle('%s', '%s', '%s')"
                              (str/replace entrypoint "'" "''")
                              (str/replace output "'" "''")
                              (str/replace options-json "'" "''"))
                      (format "SELECT trex_create_bundle('%s', '%s')"
                              (str/replace entrypoint "'" "''")
                              (str/replace output "'" "''")))
                result (core/query db sql)
                result-str (-> result first vals first)]
            (if json
              (println (json/write-str {:success (not (str/starts-with? (str result-str) "Error"))
                                        :message result-str}))
              (println result-str))
            {:exit-code (if (str/starts-with? (str result-str) "Error") 1 0)})
          (catch Exception e
            (if json
              (println (json/write-str {:success false :error (.getMessage e)}))
              (println (format "Error: %s" (.getMessage e))))
            {:exit-code 1})
          (finally
            (core/shutdown! db)))))))
