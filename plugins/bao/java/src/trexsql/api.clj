(ns trexsql.api
  "Java API for Trexsql via gen-class."
  (:require [trexsql.core :as core]
            [trexsql.db :as db]
            [trexsql.extensions :as ext]
            [trexsql.datamart :as datamart]
            [trexsql.vocab :as vocab]
            [trexsql.circe :as circe]
            [trexsql.http :as http]
            [trexsql.webapi :as webapi]
            [clojure.string :as str])
  (:import [java.util Map List ArrayList HashMap])
  (:gen-class
   :name org.trex.Trexsql
   :methods [^:static [init [] void]
             ^:static [init [java.util.Map] void]
             ^:static [getDatabase [] Object]
             ^:static [query [String] java.util.List]
             ^:static [execute [String] boolean]
             ^:static [shutdown [] void]
             ^:static [isRunning [] boolean]
             ^:static [getLoadedExtensions [] java.util.List]
             ^:static [createCache [java.util.Map java.util.function.Consumer] java.util.Map]
             ^:static [isAttached [String] boolean]
             ^:static [detachDatabase [String] void]
             ^:static [searchVocab [String java.util.Map] java.util.List]
             ^:static [executeCirce [String java.util.Map] java.util.Map]
             ^:static [renderCirceToSql [String java.util.Map] String]
             ^:static [setSourceRepository [Object] void]]))

(defn- java-map->clj-map
  [^Map m]
  (when m
    (into {} (for [[k v] m] [(if (string? k) (keyword k) k) v]))))

(defn- ensure-arraylist [coll]
  (if (instance? ArrayList coll) coll (ArrayList. ^java.util.Collection coll)))

(defn -init
  ([]
   (core/init))
  ([^Map config]
   (core/init (java-map->clj-map config))))

(defn -getDatabase []
  (core/get-database))

(defn -query [^String sql]
  (ensure-arraylist (db/query (core/get-database) sql)))

(defn -execute [^String sql]
  (db/execute! (core/get-database) sql))

(defn -shutdown []
  (core/shutdown! @core/current-database))

(defn -isRunning []
  (core/is-running? (core/get-database)))

(defn -getLoadedExtensions []
  (ArrayList. ^java.util.Collection (vec (ext/loaded-extensions (core/get-database)))))

(defn -createCache [^Map config ^java.util.function.Consumer progress-callback]
  (let [db (core/get-database)
        clj-config (datamart/java-map->datamart-config config)
        progress-fn (when progress-callback
                      (fn [event]
                        (let [java-event (doto (HashMap.)
                                           (.put "phase" (name (:phase event)))
                                           (.put "table" (:table event))
                                           (.put "tableIndex" (:table-index event))
                                           (.put "totalTables" (:total-tables event))
                                           (.put "rowsProcessed" (:rows-processed event))
                                           (.put "estimatedRows" (:estimated-rows event))
                                           (.put "rowsCopied" (:rows-copied event))
                                           (.put "durationMs" (:duration-ms event))
                                           (.put "error" (:error event)))]
                          (.accept progress-callback java-event))))]
    (when-let [error (datamart/validate-config clj-config)]
      (throw (IllegalArgumentException. ^String error)))
    (datamart/result->java-map (datamart/create-cache db clj-config progress-fn))))

(defn -isAttached [^String database-code]
  (datamart/is-attached? (core/get-database) database-code))

(defn -detachDatabase [^String database-code]
  (datamart/detach-database! (core/get-database) database-code))

(defn -searchVocab [^String search-term ^Map options]
  (let [db (core/get-database)]
    (vocab/results->concept-list
     (vocab/search-vocab db search-term (vocab/java-map->search-options db options)))))

(defn -executeCirce [^String circe-json ^Map options]
  (circe/circe-result->java-map
   (circe/execute-circe (core/get-database) circe-json (circe/java-map->circe-options options))))

(defn -renderCirceToSql [^String circe-json ^Map options]
  (circe/render-circe-to-sql (core/get-database) circe-json (circe/java-map->circe-options options)))

(defn -setSourceRepository [repo]
  (webapi/set-source-repository! repo))
