(ns trexsql.study
  "Study execution orchestration.
   Calls hades.trex DuckDB extension SQL functions and bridges
   progress into local jobs DB + Spring Batch tables."
  (:require [trexsql.db :as db]
            [trexsql.jobs :as jobs]
            [trexsql.json :as json]
            [clojure.string :as str]
            [clojure.tools.logging :as log])
  (:import [java.util HashMap]))

(def ^:private poll-interval-ms 5000)

(def ^:private hades-terminal-statuses #{"COMPLETED" "FAILED" "CANCELLED"})

(defn- parse-hades-json
  "Parse JSON string returned by hades SQL functions."
  [^String s]
  (when (and s (not= s ""))
    (try
      (json/read-str s :key-fn keyword)
      (catch Exception e
        (log/warn (format "Failed to parse hades response: %s" (.getMessage e)))
        nil))))

(defn- escape-sql-string
  "Escape single quotes for SQL string literals."
  [^String s]
  (str/replace (str s) "'" "''"))

(defn- query-hades-status
  "Call SELECT * FROM hades_status('job-id') and return parsed map, or nil."
  [trexsql-db hades-job-id]
  (try
    (let [sql (format "SELECT * FROM hades_status('%s')"
                      (escape-sql-string hades-job-id))
          results (db/query trexsql-db sql)]
      (when (seq results)
        (let [^HashMap row (first results)]
          {:status (.get row "status")
           :current-module (.get row "current_module")
           :modules-completed (parse-hades-json (.get row "modules_completed"))
           :elapsed-ms (.get row "elapsed_ms")
           :error-message (.get row "error_message")
           :env-name (.get row "env_name")
           :database-name (.get row "database_name")
           :log-tail (parse-hades-json (.get row "log_tail"))})))
    (catch Exception e
      (log/warn (format "Failed to query hades_status for %s: %s"
                        hades-job-id (.getMessage e)))
      nil)))

(defn- map-hades-status-to-spring-batch
  "Map hades status to Spring Batch status strings."
  [hades-status]
  (case hades-status
    "COMPLETED" "COMPLETED"
    "FAILED"    "FAILED"
    "CANCELLED" "STOPPED"
    "RUNNING"   "STARTED"
    "STARTED"))

(defn- poll-study-progress
  "Background polling loop. Reads hades_status and syncs to local DB + Spring Batch.
   Runs until the hades job reaches a terminal status."
  [trexsql-db study-id hades-job-id spring-batch-exec-id]
  (loop []
    (Thread/sleep (long poll-interval-ms))
    (let [hades (query-hades-status trexsql-db hades-job-id)]
      (if (nil? hades)
        (do
          (log/warn (format "hades_status returned nil for study %s (hades job %s)"
                            study-id hades-job-id))
          (recur))
        (let [terminal? (contains? hades-terminal-statuses (:status hades))]
          (try
            (jobs/update-study-progress! trexsql-db study-id
              {:status (:status hades)
               :current-module (:current-module hades)
               :modules-completed (:modules-completed hades)
               :error-message (:error-message hades)})
            (catch Exception e
              (log/warn (format "Failed to update study progress for %s: %s"
                                study-id (.getMessage e)))))
          (when spring-batch-exec-id
            (try
              (jobs/update-spring-batch-status!
                trexsql-db spring-batch-exec-id
                (map-hades-status-to-spring-batch (:status hades)))
              (catch Exception e
                (log/warn (format "Failed to update Spring Batch for study %s: %s"
                                  study-id (.getMessage e))))))
          (when-not terminal?
            (recur)))))))

(defn execute-study!
  "Execute a Strategus study via hades.trex.
   1. Calls hades_execute SQL function (async — spawns R process)
   2. Writes job records to local DB + Spring Batch
   3. Starts background polling thread
   Returns {:study-id, :hades-job-id, :status} or throws."
  [trexsql-db {:keys [source-key analysis-spec-path cdm-database-schema
                       work-database-schema output-path database-name
                       env-name env-base-dir]}]
  (let [sql (format "SELECT hades_execute('%s', '%s', '%s', '%s', '%s', '%s', '%s')"
                    (escape-sql-string analysis-spec-path)
                    (escape-sql-string cdm-database-schema)
                    (escape-sql-string work-database-schema)
                    (escape-sql-string output-path)
                    (escape-sql-string database-name)
                    (escape-sql-string env-name)
                    (escape-sql-string env-base-dir))
        results (db/query trexsql-db sql)
        _ (when (empty? results)
            (throw (ex-info "hades_execute returned no result" {})))
        response-json (.get ^HashMap (first results) "hades_execute")
        response (parse-hades-json (str response-json))
        _ (when (= "error" (:status response))
            (throw (ex-info (str "hades_execute failed: " (:error response))
                            {:error (:error response)})))
        hades-job-id (:job_id response)
        study-id hades-job-id
        spring-batch-exec-id (jobs/write-spring-batch-job!
                               trexsql-db "studyExecution"
                               {:study-id study-id
                                :database-name database-name
                                :env-name env-name})
        _ (jobs/create-study-job! trexsql-db study-id
            {:job-execution-id spring-batch-exec-id
             :source-key source-key
             :env-name env-name
             :database-name database-name
             :analysis-spec analysis-spec-path
             :config {:cdm-database-schema cdm-database-schema
                      :work-database-schema work-database-schema
                      :output-path output-path
                      :env-base-dir env-base-dir}})]
    (future
      (try
        (poll-study-progress trexsql-db study-id hades-job-id spring-batch-exec-id)
        (catch Throwable t
          (log/error t (format "Study progress polling failed for %s" study-id))
          (try
            (jobs/update-study-progress! trexsql-db study-id
              {:status "FAILED" :error-message (str "Polling error: " (.getMessage t))})
            (catch Exception _)))))
    {:study-id study-id
     :hades-job-id hades-job-id
     :status "RUNNING"}))

(defn cancel-study!
  "Cancel a running study via hades_cancel + local status update."
  [trexsql-db study-id]
  (let [sql (format "SELECT hades_cancel('%s')" (escape-sql-string study-id))
        results (db/query trexsql-db sql)
        response-json (when (seq results)
                        (.get ^HashMap (first results) "hades_cancel"))
        response (parse-hades-json (str response-json))]
    (jobs/update-study-progress! trexsql-db study-id
      {:status "CANCELLED"})
    (when-let [study-status (jobs/get-study-status trexsql-db study-id)]
      (when-let [exec-id (:job-execution-id study-status)]
        (jobs/update-spring-batch-status! trexsql-db exec-id "STOPPED")))
    response))

(defn setup-environment!
  "Setup an R environment via hades_setup_env. Synchronous — blocks until complete."
  [trexsql-db lockfile-path env-name env-base-dir]
  (let [sql (format "SELECT hades_setup_env('%s', '%s', '%s')"
                    (escape-sql-string lockfile-path)
                    (escape-sql-string env-name)
                    (escape-sql-string env-base-dir))
        results (db/query trexsql-db sql)]
    (when (seq results)
      (parse-hades-json (str (.get ^HashMap (first results) "hades_setup_env"))))))
