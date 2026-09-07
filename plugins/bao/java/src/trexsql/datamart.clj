(ns trexsql.datamart
  "Datamart (cache) creation for source database schemas in TrexSQL.
   postgres/mysql/bigquery use DuckDB's native scanners (ATTACH + CREATE TABLE
   AS SELECT over the TrexEngine FFI handle); all other dialects use the JDBC
   batch transfer path (HikariCP + HoneySQL-built standard SQL). FTS indexing
   and progress reporting run on the cache file after the copy completes."
  (:require [trexsql.db :as db]
            [trexsql.util :as util]
            [trexsql.batch :as batch]
            [trexsql.jobs :as jobs]
            [trexsql.errors :as errors]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [honey.sql :as sql])
  (:import [java.util Map ArrayList HashMap]))

(defrecord SourceCredentials
  [dialect host port database-name user password])

(defrecord DatamartConfig
  [database-code schema-name target-schema-name source-credentials table-filter patient-filter timestamp-filter fts-tables cache-path parallel-copy])

(defrecord TableResult
  [table-name rows-copied indexes-created])

(defrecord TableError
  [table-name error phase])

(defrecord CacheResult
  [success? database-code schema-name tables-copied tables-failed fts-indexes-created duration-ms error])

;; Mirrors WebAPI's DBMSType enum (org.ohdsi.webapi.arachne.commons.types.DBMSType)
;; so any source the WebAPI accepts can also be cached. postgres/mysql/bigquery
;; read via DuckDB's bundled scanners (see native-scanner-dialects); the rest
;; read via JDBC (HikariCP + HoneySQL-built standard SQL), whose drivers are
;; bundled with WebAPI and reachable from bao via java.sql.DriverManager when
;; running in-process.
;;
;; "postgres" is kept alongside "postgresql" (and "mariadb" alongside "mysql")
;; as a forgiving alias because older Source rows may still carry the short form.
;; "mysql" / "mariadb" are extras — not in WebAPI's enum, but harmless to
;; accept since the drivers may be present in custom deployments.
(def valid-dialects
  #{"postgres" "postgresql"
    "sql server" "pdw" "synapse"
    "redshift"
    "oracle"
    "impala"
    "netezza"
    "hive" "spark"
    "snowflake"
    "bigquery"
    "mysql" "mariadb"})

;; Retained as an alias for callers that still ask "is this a JDBC dialect?".
;; Now that every supported dialect goes through JDBC, this is identical to
;; valid-dialects.
(def jdbc-dialects valid-dialects)

;; Dialects DuckDB can read directly via a bundled scanner. These take the
;; native ATTACH + CREATE TABLE AS SELECT path; every other valid dialect
;; falls back to the JDBC batch path. postgresql/mariadb are aliases.
(def native-scanner-dialects
  #{"postgres" "postgresql" "mysql" "mariadb" "bigquery"})

(defn native-scanner-dialect?
  "True if `dialect` should use the native DuckDB scanner path."
  [dialect]
  (contains? native-scanner-dialects (str/lower-case (or dialect ""))))

(defn- valid-database-code?
  "Check if database-code is valid for filesystem naming."
  [code]
  (and (string? code)
       (seq code)
       (re-matches #"^[a-zA-Z0-9_-]+$" code)))

(defn validate-credentials
  "Validate SourceCredentials. Returns nil if valid, error message if invalid.
   Every dialect uses the same JDBC shape: jdbc-url + user + password."
  [creds]
  (cond
    (nil? creds)
    "Missing required config: source-credentials"

    (not (contains? valid-dialects (:dialect creds)))
    (str "Unsupported dialect: " (:dialect creds) ". Must be one of: "
         (str/join ", " (sort valid-dialects)))

    (str/blank? (:jdbc-url creds))
    (str "Missing required JDBC config: jdbc-url for dialect " (:dialect creds))

    (str/blank? (:user creds))
    (str "Missing required JDBC config: user for dialect " (:dialect creds))

    (str/blank? (:password creds))
    (str "Missing required JDBC config: password for dialect " (:dialect creds))

    :else nil))

(defn validate-config
  "Validate DatamartConfig. Returns nil if valid, error message if invalid."
  [config]
  (cond
    (nil? config)
    "Config is nil"

    (not (valid-database-code? (:database-code config)))
    (str "Invalid database-code: " (:database-code config)
         ". Must be non-empty and contain only alphanumeric, underscore, or hyphen characters.")

    (str/blank? (:schema-name config))
    "Missing required config: schema-name"

    :else
    (validate-credentials (:source-credentials config))))

(defn java-map->source-credentials
  "Convert Java Map to SourceCredentials record."
  [^Map m]
  (let [clj-map (util/java-map->clj-map m)]
    (map->SourceCredentials clj-map)))

(defn java-map->datamart-config
  "Convert Java Map to DatamartConfig record.
   Applies defaults for optional fields."
  [^Map m]
  (let [clj-map (util/java-map->clj-map m)
        source-creds (when-let [creds (:source-credentials clj-map)]
                       (if (map? creds)
                         (map->SourceCredentials creds)
                         creds))]
    (map->DatamartConfig
     {:database-code (:database-code clj-map)
      :schema-name (:schema-name clj-map)
      :target-schema-name (or (:target-schema-name clj-map)
                              (:schema-name clj-map))
      :source-credentials source-creds
      :table-filter (:table-filter clj-map)
      :patient-filter (when-let [pf (:patient-filter clj-map)]
                        (vec pf))
      :timestamp-filter (:timestamp-filter clj-map)
      :fts-tables (or (:fts-tables clj-map) ["concept" "concept_synonym"])
      :cache-path (or (:cache-path clj-map) "./data/cache")
      :parallel-copy (boolean (:parallel-copy clj-map))})))

(defn table-result->java-map
  "Convert TableResult record to Java HashMap."
  [^TableResult tr]
  (doto (HashMap.)
    (.put "table-name" (:table-name tr))
    (.put "rows-copied" (:rows-copied tr))
    (.put "indexes-created" (:indexes-created tr))))

(defn table-error->java-map
  "Convert TableError record to Java HashMap."
  [^TableError te]
  (doto (HashMap.)
    (.put "table-name" (:table-name te))
    (.put "error" (:error te))
    (.put "phase" (:phase te))))

(defn tables-to-arraylist
  "Convert list of TableResult or TableError records to ArrayList<HashMap>."
  [records converter-fn]
  (let [al (ArrayList.)]
    (doseq [r records]
      (.add al (converter-fn r)))
    al))

(defn result->java-map
  "Convert CacheResult record to Java HashMap for Spring Batch compatibility."
  [^CacheResult result]
  (doto (HashMap.)
    (.put "success" (boolean (:success? result)))
    (.put "database-code" (:database-code result))
    (.put "schema-name" (:schema-name result))
    (.put "tables-copied" (tables-to-arraylist (:tables-copied result) table-result->java-map))
    (.put "tables-failed" (tables-to-arraylist (:tables-failed result) table-error->java-map))
    ;; vec, not (or ... []): a type hint on a macro form is dropped during
    ;; expansion, so the hinted `or` still compiled to a reflective ctor call.
    (.put "fts-indexes-created" (ArrayList. ^java.util.Collection (vec (:fts-indexes-created result))))
    (.put "duration-ms" (:duration-ms result))
    (.put "error" (:error result))))

;; === Native-scanner copy helpers (DuckDB ATTACH + CREATE TABLE AS SELECT) ===

(defn get-source-tables
  "List table names in the attached source schema via information_schema."
  [db source-alias schema-name]
  (db/validate-identifier! source-alias "source-alias")
  (db/validate-identifier! schema-name "schema-name")
  (let [[query-sql & params] (sql/format
                              {:select [:table_name]
                               :from [:information_schema.tables]
                               :where [:and
                                       [:= :table_schema schema-name]
                                       [:= :table_catalog source-alias]]})
        results (db/query-with-params db query-sql (vec params))]
    (mapv #(.get ^HashMap % "table_name") results)))

(defn apply-table-filter
  "Keep only tables present in `table-filter` keys; nil filter keeps all."
  [tables table-filter]
  (if (nil? table-filter)
    tables
    (filterv #(contains? table-filter %) tables)))

(defn build-select-clause
  "\"*\" for nil/empty/[\"*\"]; otherwise escaped, comma-joined column names."
  [columns]
  (if (or (nil? columns) (empty? columns)
          (= ["*"] columns) (= "*" (first columns)))
    "*"
    (do
      (doseq [col columns] (db/validate-identifier! col "column-name"))
      (str/join ", " (map #(db/escape-identifier % "column") columns)))))

(defn- validate-patient-ids [patient-filter]
  (when patient-filter
    (let [invalid (seq (remove #(or (integer? %)
                                    (and (string? %) (re-matches #"^\d+$" %)))
                               patient-filter))]
      (when invalid
        (str "Invalid patient IDs (must be numeric): " (pr-str (take 5 invalid)))))))

(defn- validate-timestamp-filter [timestamp-filter]
  (when timestamp-filter
    (when-not (re-matches #"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?$" (str timestamp-filter))
      (str "Invalid timestamp format: " timestamp-filter
           ". Expected ISO 8601 (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)"))))

(defn build-where-clause
  "WHERE clause for patient and timestamp filters, or nil. Validates inputs."
  [patient-filter timestamp-filter]
  (when-let [error (validate-patient-ids patient-filter)]
    (throw (errors/validation-error error {:field :patient-filter})))
  (when-let [error (validate-timestamp-filter timestamp-filter)]
    (throw (errors/validation-error error {:field :timestamp-filter})))
  (let [clauses (cond-> []
                  patient-filter
                  (conj (str "person_id IN ("
                             (str/join ", " (map #(if (integer? %) % (Long/parseLong (str %)))
                                                 patient-filter))
                             ")"))
                  timestamp-filter
                  (conj (str "observation_date >= '" timestamp-filter "'")))]
    (when (seq clauses)
      (str " WHERE " (str/join " AND " clauses)))))

;; Column each CDM table is range-partitioned on when copying in chunks. Mirrors
;; the map d2e's create_cachedb_file flow uses, so both loaders chunk the same
;; tables the same way. A table absent here is copied in one statement.
(def ^:private chunk-column-map
  {"person"                 "person_id"
   "observation_period"     "person_id"
   "visit_occurrence"       "person_id"
   "visit_detail"           "person_id"
   "condition_occurrence"   "person_id"
   "drug_exposure"          "person_id"
   "procedure_occurrence"   "person_id"
   "device_exposure"        "person_id"
   "measurement"            "person_id"
   "observation"            "person_id"
   "death"                  "person_id"
   "note"                   "person_id"
   "note_nlp"               "note_nlp_id"
   "specimen"               "person_id"
   "payer_plan_period"      "person_id"
   "cost"                   "cost_id"
   "drug_era"               "person_id"
   "dose_era"               "person_id"
   "condition_era"          "person_id"
   "episode"                "person_id"
   "concept"                "concept_id"
   "concept_relationship"   "concept_id_1"
   "concept_ancestor"       "ancestor_concept_id"
   "concept_synonym"        "concept_id"})

;; Rows per copy statement. Sized for BigQuery, which bills and rate-limits per
;; scan and so wants as few statements as possible; the local engines handle a
;; slice this size comfortably, so there is no reason to split them finer.
;; d2e's flow uses the same value for BigQuery (chunk_utils/determine_chunk_size).
(def ^:private default-chunk-size 5000000)

(defn- chunk-size-for
  "Rows per copy statement. An explicit :chunk-size in config always wins."
  [configured]
  (if (and configured (pos? (long configured)))
    (long configured)
    default-chunk-size))

(defn- chunk-bounds
  "MIN/MAX of the chunk column, or nil when the table is empty or the bounds
   aren't usable (non-numeric key, all NULL). nil means copy in one statement."
  [db source-table chunk-col]
  (try
    (let [sql-str (format "SELECT MIN(%s) AS lo, MAX(%s) AS hi FROM %s"
                          (db/escape-identifier chunk-col "chunk-col")
                          (db/escape-identifier chunk-col "chunk-col")
                          source-table)
          row (first (db/query db sql-str))
          ;; clojure.core/get, not .get: db/query hands back java HashMaps and
          ;; the interop form compiles to a reflective call that native-image
          ;; cannot resolve. get reads a java.util.Map without reflection.
          lo (get row "lo")
          hi (get row "hi")]
      (when (and (number? lo) (number? hi))
        [(long lo) (long hi)]))
    (catch Exception e
      (log/debug (format "Chunk bounds unavailable for %s on %s: %s"
                         source-table chunk-col (.getMessage e)))
      nil)))

(defn- copy-rows!
  "Move rows into the (already created) target table.

   Copying a whole CDM table in a single INSERT … SELECT makes the engine
   materialize the entire scan at once, which is what makes large BigQuery
   sources expensive and slow. When the table has a known integer key, walk it
   in key ranges instead so each statement covers a bounded slice."
  [db table-name select-clause source-table target-table where-clause config]
  (let [chunk-col (get chunk-column-map (str/lower-case (str table-name)))
        bounds (when chunk-col (chunk-bounds db source-table chunk-col))
        base-where (or where-clause "")]
    (if-not bounds
      (db/execute! db (format "INSERT INTO %s SELECT %s FROM %s%s"
                              target-table select-clause source-table base-where))
      (let [[lo hi] bounds
            size (chunk-size-for (:chunk-size config))
            quoted-col (db/escape-identifier chunk-col "chunk-col")
            joiner (if (str/blank? base-where) " WHERE " (str base-where " AND "))]
        (log/info (format "Copying %s in ranges of %d on %s (%d..%d)"
                          table-name size chunk-col lo hi))
        (loop [start lo]
          (when (<= start hi)
            ;; Inclusive upper bound so the final slice picks up `hi` itself.
            (let [end (min hi (+ start (dec size)))]
              (db/execute! db (format "INSERT INTO %s SELECT %s FROM %s%s%s >= %d AND %s <= %d"
                                      target-table select-clause source-table
                                      joiner quoted-col start quoted-col end))
              (recur (inc end)))))))))

(defn copy-table
  "Copy one table from the attached source to the cache catalog.
   Returns TableResult on success, TableError on failure."
  [db source-alias cache-alias schema-name target-schema table-name config]
  (try
    (db/validate-identifier! source-alias "source-alias")
    (db/validate-identifier! cache-alias "cache-alias")
    (db/validate-identifier! schema-name "schema-name")
    (db/validate-identifier! target-schema "target-schema")
    (db/validate-identifier! table-name "table-name")
    (let [{:keys [table-filter patient-filter timestamp-filter]} config
          columns (get table-filter table-name)
          select-clause (build-select-clause columns)
          where-clause (build-where-clause patient-filter timestamp-filter)
          source-table (format "%s.%s.%s"
                               (db/escape-identifier source-alias "source-alias")
                               (db/escape-identifier schema-name "schema-name")
                               (db/escape-identifier table-name "table-name"))
          target-table (format "%s.%s.%s"
                               (db/escape-identifier cache-alias "cache-alias")
                               (db/escape-identifier target-schema "target-schema")
                               (db/escape-identifier table-name "table-name"))
          create-sql (format "CREATE OR REPLACE TABLE %s AS SELECT %s FROM %s WHERE false"
                             target-table select-clause source-table)]
      (db/execute! db create-sql)
      (copy-rows! db table-name select-clause source-table target-table where-clause config)
      (let [count-sql (format "SELECT COUNT(*) as cnt FROM %s" target-table)
            count-result (db/query db count-sql)
            row-count (or (get (first count-result) "cnt") 0)]
        (->TableResult table-name row-count 0)))
    (catch Exception e
      (->TableError table-name (.getMessage e) "copy"))))

(defn- copy-tables-sequential
  [db source-alias cache-alias schema-name target-schema tables-to-copy config]
  (let [total (count tables-to-copy)]
    (loop [remaining tables-to-copy, idx 1, copied [], failed []]
      (if (empty? remaining)
        {:tables-copied copied :tables-failed failed}
        (let [t (first remaining)
              _ (log/info (format "Copying table %d of %d: %s" idx total t))
              result (copy-table db source-alias cache-alias schema-name target-schema t config)]
          (if (instance? TableResult result)
            (recur (rest remaining) (inc idx) (conj copied result) failed)
            (recur (rest remaining) (inc idx) copied (conj failed result))))))))

(defn- copy-tables-parallel
  ;; Opt-in (:parallel-copy). pmap interleaves statements across tables on one
  ;; shared `db` handle — only safe if the native layer serializes per-handle.
  [db source-alias cache-alias schema-name target-schema tables-to-copy config]
  (let [results (doall
                 (pmap #(copy-table db source-alias cache-alias schema-name target-schema % config)
                       tables-to-copy))
        {copied true failed false} (group-by #(instance? TableResult %) results)]
    {:tables-copied (vec copied) :tables-failed (vec failed)}))

(defn copy-schema
  "Copy all (filtered) tables from the source schema into the cache catalog.
   Returns {:tables-copied [...] :tables-failed [...]}."
  [db source-alias cache-alias config]
  ;; Cache mirrors the source schema (target-schema-name is not honored, matching
  ;; the JDBC path) so both read paths and the FTS step resolve the same tables.
  (let [{:keys [schema-name table-filter parallel-copy]} config
        target-schema schema-name
        _ (db/validate-identifier! source-alias "source-alias")
        _ (db/validate-identifier! schema-name "schema-name")
        _ (db/validate-identifier! cache-alias "cache-alias")
        _ (db/validate-identifier! target-schema "target-schema")
        all-tables (get-source-tables db source-alias schema-name)
        tables-to-copy (apply-table-filter all-tables table-filter)
        create-schema-sql (format "CREATE SCHEMA IF NOT EXISTS %s.%s"
                                  (db/escape-identifier cache-alias "cache-alias")
                                  (db/escape-identifier target-schema "target-schema"))]
    (try
      (db/execute! db create-schema-sql)
      (catch Exception e
        (when-not (re-find #"(?i)already exists" (.getMessage e))
          (log/warn (format "Failed to create schema %s.%s: %s"
                            cache-alias target-schema (.getMessage e))))))
    (if parallel-copy
      (copy-tables-parallel db source-alias cache-alias schema-name target-schema tables-to-copy config)
      (copy-tables-sequential db source-alias cache-alias schema-name target-schema tables-to-copy config))))

;; Mirrors d2e's DUCKDB_FULLTEXT_SEARCH_CONFIG
;; (plugins/flows/base/create_cachedb_file_plugin/utils.py). Tables without a
;; unique single-column PK in OMOP CDM declare a synthetic id column; the
;; FTS step adds it before building the index because DuckDB's
;; create_fts_index requires a unique document identifier.
(def ^:private fts-config
  {"concept"              {:document-identifier "concept_id"}
   "vocabulary"           {:document-identifier "vocabulary_id"}
   "relationship"         {:document-identifier "relationship_id"}
   "concept_class"        {:document-identifier "concept_class_id"}
   "domain"               {:document-identifier "domain_id"}
   "note"                 {:document-identifier "note_id"}
   "concept_synonym"      {:document-identifier "fts_document_identifier_id" :synthetic? true}
   "concept_relationship" {:document-identifier "fts_document_identifier_id" :synthetic? true}
   "concept_ancestor"     {:document-identifier "fts_document_identifier_id" :synthetic? true}
   "concept_recommended"  {:document-identifier "fts_document_identifier_id" :synthetic? true}})

(defn get-document-identifier
  "Get document identifier column name for a table.
   Consults the static fts-config first; falls back to a heuristic that picks
   {table}_id, then any *_id column, then any integer column."
  [db cache-alias schema-name table-name]
  (or
   (get-in fts-config [table-name :document-identifier])
   (try
    (let [primary-id (str table-name "_id")
          [query-sql & params] (sql/format
                                 {:select [:column_name]
                                  :from [:information_schema.columns]
                                  :where [:and
                                          [:= :table_catalog cache-alias]
                                          [:= :table_schema schema-name]
                                          [:= :table_name table-name]
                                          [:or
                                           [:like :column_name "%_id"]
                                           [:in :data_type ["INTEGER" "BIGINT"]]]]
                                  :order-by [[[:raw (format "CASE WHEN column_name = '%s' THEN 0 WHEN column_name LIKE '%%_id' THEN 1 ELSE 2 END" primary-id)]]
                                             :column_name]
                                  :limit 1})
          results (db/query-with-params db query-sql (vec params))]
      (when (seq results)
        (.get ^HashMap (first results) "column_name")))
    (catch Exception e
      (log/warn (format "Failed to get document identifier for %s: %s" table-name (.getMessage e)))
      nil))))

(defn get-text-columns
  "Get text/varchar columns from a table for FTS indexing."
  [db cache-alias schema-name table-name]
  (try
    (let [[query-sql & params] (sql/format
                                 {:select [:column_name]
                                  :from [:information_schema.columns]
                                  :where [:and
                                          [:= :table_catalog cache-alias]
                                          [:= :table_schema schema-name]
                                          [:= :table_name table-name]
                                          [:in :data_type ["VARCHAR" "TEXT"]]]})
          results (db/query-with-params db query-sql (vec params))]
      (mapv #(.get ^HashMap % "column_name") results))
    (catch Exception e
      (log/warn (format "Failed to get text columns for %s: %s" table-name (.getMessage e)))
      [])))

(defn- ensure-synthetic-id-column!
  "For tables flagged :synthetic? in fts-config, add an auto-increment INTEGER
   column named by :document-identifier so the FTS PRAGMA has a unique input_id.
   Idempotent — uses CREATE SEQUENCE IF NOT EXISTS and ADD COLUMN IF NOT EXISTS,
   so re-running on an existing cache preserves sequence state and existing ids.
   No-op for tables without :synthetic?."
  [db cache-alias schema-name table-name]
  (when-let [cfg (get fts-config table-name)]
    (when (:synthetic? cfg)
      (let [id-col (:document-identifier cfg)
            seq-name (str table-name "_id_sequence")
            _ (db/validate-identifier! id-col "column-name")
            _ (db/validate-identifier! seq-name "sequence-name")
            ;; Each segment is quoted so hyphenated database-codes
            ;; (allowed by valid-database-code?) parse correctly inside
            ;; the NEXTVAL string literal.
            qualified-seq (format "\"%s\".\"%s\".\"%s\"" cache-alias schema-name seq-name)]
        (db/execute! db (format "CREATE SEQUENCE IF NOT EXISTS %s START 1" qualified-seq))
        (db/execute! db (format "ALTER TABLE \"%s\".\"%s\".\"%s\" ADD COLUMN IF NOT EXISTS \"%s\" INTEGER DEFAULT NEXTVAL('%s')"
                                cache-alias schema-name table-name id-col qualified-seq))))))

(defn create-fts-index
  "Create FTS index on a table. Returns table name on success, nil on failure.
   Consults fts-config for the document identifier; if the table has no
   natural PK, adds a synthetic auto-increment column first.
   Text columns are discovered dynamically from information_schema."
  [db cache-alias schema-name table-name]
  (try
    (db/validate-identifier! cache-alias "cache-alias")
    (db/validate-identifier! schema-name "schema-name")
    (db/validate-identifier! table-name "table-name")

    (log/info (format "Creating FTS index on %s" table-name))
    (ensure-synthetic-id-column! db cache-alias schema-name table-name)

    (let [qualified-table (format "\"%s\".\"%s\".\"%s\"" cache-alias schema-name table-name)
          id-column (get-document-identifier db cache-alias schema-name table-name)
          text-columns (get-text-columns db cache-alias schema-name table-name)]

      (cond
        (not id-column)
        (do
          (log/warn (format "No document identifier found for %s, skipping FTS index" table-name))
          nil)

        (empty? text-columns)
        (do
          (log/warn (format "No text columns found for %s, skipping FTS index" table-name))
          nil)

        :else
        (do
          (doseq [col (cons id-column text-columns)]
            (db/validate-identifier! col "column-name"))
          ;; ignore= regex matches d2e's create_cachedb_file_plugin so
          ;; tokenization is identical to Prefect-built caches.
          (let [fts-sql (format "PRAGMA create_fts_index(%s, %s, %s, stemmer='english', stopwords='english', ignore='(\\.|[^a-z0-9!@#$%%^&*()`+\"\\-\\/])+', strip_accents=1, lower=1, overwrite=1)"
                                qualified-table
                                id-column
                                (str/join ", " text-columns))]
            (log/debug (format "FTS SQL: %s" fts-sql))
            (db/execute! db fts-sql)
            (log/info (format "FTS index created successfully on %s" table-name))
            table-name))))
    (catch Exception e
      (log/warn (format "Failed to create FTS index on %s: %s" table-name (.getMessage e)))
      nil)))

(defn create-fts-indexes
  "Create FTS indexes on configured tables.
   Returns vector of table names with successful FTS index creation."
  [db cache-alias schema-name fts-tables copied-tables]
  (when (util/load-fts-extension! db)
    (let [copied-table-names (set (map :table-name copied-tables))
          tables-to-index (filter copied-table-names fts-tables)]
      (filterv some? (map #(create-fts-index db cache-alias schema-name %) tables-to-index)))))

(defn jdbc-dialect?
  "True for any dialect that goes through the generic JDBC batch transfer
   path. Now true for every supported dialect — kept as a function so
   callers reading older shape don't have to be touched."
  [dialect]
  (contains? jdbc-dialects (str/lower-case (or dialect ""))))

(defn- convert-config-for-jdbc
  "Convert DatamartConfig to JDBC batch config format."
  [config]
  (let [{:keys [database-code schema-name source-credentials table-filter
                patient-filter timestamp-filter cache-path]} config
        {:keys [dialect jdbc-url user password]} source-credentials]
    {:database-code database-code
     :schema-name schema-name
     :source-credentials {:jdbc-url jdbc-url
                          :user user
                          :password password
                          :dialect dialect}
     :table-filter (when table-filter (keys table-filter))
     :column-filter table-filter
     :patient-filter patient-filter
     :timestamp-filter timestamp-filter
     :cache-path (or cache-path "./data/cache")
     :batch-size (or (:batch-size config) 10000)}))

(defn- attach-source!
  "Attach the source via the matching DuckDB scanner. Returns the alias."
  [db database-code credentials]
  (case (str/lower-case (or (:dialect credentials) ""))
    ("postgres" "postgresql") (db/attach-source-postgres! db database-code credentials)
    ("mysql" "mariadb")       (db/attach-source-mysql! db database-code credentials)
    "bigquery"                (db/attach-source-bigquery! db database-code credentials)
    (throw (errors/config-error
            (str "Dialect is not a native-scanner dialect: " (:dialect credentials))
            :dialect))))

(defn- create-cache-native
  "Native-scanner cache read: attach cache + source on one handle, copy the
   schema (DuckDB handles type conversion), detach source. Returns the same map
   shape as batch/create-cache-jdbc so create-cache's shared FTS/result code is
   path-agnostic. On failure the cache catalog is detached and a structured
   failure map is returned; on success the cache stays attached for the FTS step."
  [db config]
  (let [start (System/currentTimeMillis)
        {:keys [database-code schema-name source-credentials cache-path]} config
        ;; Open the job before any work so the build is visible in WebAPI's job
        ;; overview while it runs, not just after it finishes. The JDBC path does
        ;; this inline; this path had no job at all, which is why postgres caches
        ;; never appeared in the overview and /cache/status reported ready
        ;; immediately (a nil job status counts as "done").
        exec-id (try (jobs/start-cache-job! db database-code schema-name)
                     (catch Exception e
                       (log/warn (format "Could not open cache job for %s: %s"
                                         database-code (.getMessage e)))
                       nil))]
    (db/attach-cache-file! db database-code (or cache-path "./data/cache"))
    (try
      (let [source-alias (attach-source! db database-code source-credentials)]
        (try
          (let [{:keys [tables-copied tables-failed]}
                (copy-schema db source-alias database-code config)
                success? (empty? tables-failed)
                ;; A copy that moved no tables is a failure, not an empty
                ;; success: it means the source schema was missing or had
                ;; nothing to read, and reporting it as COMPLETE is what let a
                ;; 12KB cache pass as a healthy one.
                copied-any? (seq tables-copied)
                failure-msg (cond
                              (not success?)
                              (str "Failed to copy " (count tables-failed) " table(s): "
                                   (str/join ", " (map :table-name tables-failed)))
                              (not copied-any?)
                              (str "No tables were copied from schema '" schema-name
                                   "' — the schema is missing or contains no readable tables"))]
            (jobs/update-local-progress! db database-code
              {:completed-tables (count tables-copied)
               :tables-copied tables-copied
               :tables-failed tables-failed})
            (jobs/finish-cache-job! db database-code exec-id
                                    (and success? (boolean copied-any?)) failure-msg)
            {:success? (and success? (boolean copied-any?))
             :database-code database-code
             :schema-name schema-name
             :tables-copied (mapv (fn [t] {:table-name (:table-name t)
                                           :rows-copied (:rows-copied t)}) tables-copied)
             :tables-failed (mapv (fn [t] {:table-name (:table-name t)
                                           :error (:error t)
                                           :phase (:phase t)}) tables-failed)
             :duration-ms (- (System/currentTimeMillis) start)
             :error failure-msg})
          (finally
            (try (db/detach-database! db source-alias)
                 (catch Exception e
                   (log/warn (format "Failed to detach source %s: %s"
                                     source-alias (.getMessage e))))))))
      (catch Exception e
        ;; Detach the cache so a retry with the same database-code isn't blocked.
        (try (db/detach-database! db database-code) (catch Exception _ nil))
        (jobs/finish-cache-job! db database-code exec-id false (.getMessage e))
        {:success? false
         :database-code database-code
         :schema-name schema-name
         :tables-copied []
         :tables-failed []
         :duration-ms (- (System/currentTimeMillis) start)
         :error (.getMessage e)}))))

(defn create-cache
  "Unified cache creation. postgres/mysql/bigquery use the native DuckDB
   scanner path; all other dialects use the JDBC batch transfer path. After the
   copy, FTS indexes are built on the configured tables (default: `concept`,
   `concept_synonym`) inside the cache file.
   Returns a CacheResult.
   `progress-fn` is invoked with per-phase progress events during transfer."
  ([db config]
   (create-cache db config nil))
  ([db config progress-fn]
   (let [dialect (get-in config [:source-credentials :dialect])
         result (if (native-scanner-dialect? dialect)
                  (create-cache-native db config)
                  (batch/create-cache-jdbc db (convert-config-for-jdbc config) progress-fn))
         tables-copied (:tables-copied result)
         ;; FTS only on success; both paths write at <cache>.<source-schema>.<table>,
         ;; the coordinates the FTS indexer and downstream cache queries resolve.
         fts-created (when (and (:success? result) (seq tables-copied))
                       (try
                         (create-fts-indexes db
                                             (:database-code result)
                                             (:schema-name result)
                                             (or (:fts-tables config) ["concept" "concept_synonym"])
                                             (mapv (fn [t] {:table-name (:table-name t)})
                                                   tables-copied))
                         (catch Exception e
                           (log/warn (format "FTS index creation failed for %s: %s"
                                             (:database-code result) (.getMessage e)))
                           [])))]
     (->CacheResult
      (:success? result)
      (:database-code result)
      (:schema-name result)
      (mapv (fn [t] (->TableResult (:table-name t) (:rows-copied t) 0)) tables-copied)
      (mapv (fn [t] (->TableError (:table-name t) (:error t) (or (:phase t) "copy"))) (:tables-failed result))
      (or fts-created [])
      (:duration-ms result)
      (:error result)))))

(defn is-attached?
  "Check if a database is attached. Delegates to db/is-attached?"
  [db database-code]
  (db/is-attached? db database-code))

(defn detach-database!
  "Detach a database. Delegates to db/detach-database!"
  [db database-code]
  (db/detach-database! db database-code))
