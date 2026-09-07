(ns trexsql.util
  "Shared utility functions for trexsql."
  (:require [trexsql.db :as db]
            [clojure.string :as str]
            [clojure.tools.logging :as log])
  (:import [java.util Map List ArrayList HashMap]))

(defn java-map->clj-map
  "Convert Java Map to Clojure map with keyword keys.
   Recursively converts nested Maps and Lists."
  [^Map m]
  (when m
    (into {}
          (for [[k v] m]
            [(if (string? k) (keyword k) k)
             (cond
               (instance? Map v) (java-map->clj-map v)
               (instance? List v) (vec v)
               :else v)]))))

(defn clj-map->java-map
  "Convert Clojure map to Java HashMap.
   Converts keyword keys to strings."
  [m]
  (when m
    (let [result (HashMap.)]
      (doseq [[k v] m]
        (.put result (if (keyword? k) (name k) (str k)) v))
      result)))

(defn load-fts-extension!
  "Install and load the FTS extension using cached extension loading.
   Returns true on success, false on failure.
   Uses db/load-extension! for caching."
  [db]
  (try
    (db/load-extension! db "fts")
    true
    (catch Exception e
      (log/warn "Failed to load FTS extension" e)
      false)))

(defn load-circe-extension!
  "Load the circe extension with a direct-path fallback."
  [db]
  (try
    (db/load-extension! db "circe")
    true
    (catch Exception e
      (log/debug "circe load failed; trying direct path" e)
      (try
        (let [ext-path "/data/.duckdb/extensions/v1.4.0/linux_amd64/circe.duckdb_extension"]
          (db/execute! db (format "LOAD '%s'" ext-path))
          (swap! (:extensions-loaded db) conj "circe")
          true)
        (catch Exception e2
          (log/warn "Failed to load circe" e2)
          false)))))

(defn valid-database-code?
  "Check if database-code is valid for filesystem and SQL naming.
   Allows alphanumeric, underscore, and hyphen characters."
  [code]
  (and (string? code)
       (seq code)
       (re-matches #"^[a-zA-Z0-9_-]+$" code)))

(defn valid-schema-name?
  "Check if schema-name is valid for SQL identifiers.
   Allows alphanumeric and underscore characters only."
  [name]
  (and (string? name)
       (seq name)
       (re-matches #"^[a-zA-Z_][a-zA-Z0-9_]*$" name)))

(defn validate-positive-int
  "Validate that value is a positive integer.
   Returns nil if valid, error message if invalid."
  [value field-name]
  (cond
    (nil? value)
    (str "Missing required field: " field-name)

    (not (integer? value))
    (str "Invalid " field-name ": " value ". Must be an integer.")

    (< value 1)
    (str "Invalid " field-name ": " value ". Must be a positive integer.")

    :else nil))

(defn validate-bounded-int
  "Validate that value is an integer within bounds.
   Returns nil if valid, error message if invalid."
  [value field-name min-val max-val]
  (cond
    (nil? value)
    (str "Missing required field: " field-name)

    (not (integer? value))
    (str "Invalid " field-name ": " value ". Must be an integer.")

    (< value min-val)
    (str "Invalid " field-name ": " value ". Must be at least " min-val ".")

    (> value max-val)
    (str "Invalid " field-name ": " value ". Must be at most " max-val ".")

    :else nil))

(defn records->arraylist
  "Convert a sequence of records to ArrayList using a converter function."
  [records converter-fn]
  (let [al (ArrayList.)]
    (doseq [r records]
      (.add al (converter-fn r)))
    al))

(defn seq->arraylist
  "Convert a Clojure sequence to Java ArrayList."
  [coll]
  ;; vec, not (or ... []): a type hint on a macro form is dropped during
  ;; expansion, leaving a reflective ctor call that native-image can't resolve.
  (ArrayList. ^java.util.Collection (vec coll)))

(defn build-qualified-table-ref
  "Build a fully qualified and escaped table reference.
   Format: \"database\".\"schema\".\"table\""
  [database-code schema-name table-name]
  (db/validate-identifier! database-code "database-code")
  (db/validate-identifier! schema-name "schema-name")
  (db/validate-identifier! table-name "table-name")
  (format "%s.%s.%s"
          (db/escape-identifier database-code "database-code")
          (db/escape-identifier schema-name "schema-name")
          (db/escape-identifier table-name "table-name")))

(defn escape-sql-string
  "Escape single quotes in a string for SQL string literals."
  [^String s]
  (when s
    (str/replace s "'" "''")))

(defn escape-json-string
  "Escape a string for safe JSON inclusion.
   Escapes backslashes, double quotes, and control characters."
  [^String s]
  (when s
    (-> s
        (str/replace "\\" "\\\\")
        (str/replace "\"" "\\\"")
        (str/replace "\n" "\\n")
        (str/replace "\r" "\\r")
        (str/replace "\t" "\\t"))))

(defmacro with-timing
  "Execute body and return [result duration-ms]."
  [& body]
  `(let [start# (System/currentTimeMillis)
         result# (do ~@body)
         duration# (- (System/currentTimeMillis) start#)]
     [result# duration#]))

(defn format-duration
  "Format duration in milliseconds to human-readable string."
  [ms]
  (cond
    (< ms 1000) (str ms "ms")
    (< ms 60000) (format "%.1fs" (/ ms 1000.0))
    :else (format "%.1fm" (/ ms 60000.0))))
