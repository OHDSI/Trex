(ns trexsql.extensions
  "TrexSQL extension discovery and loading."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [trexsql.native :as native])
  (:import [java.io File InputStream FileOutputStream]
           [java.nio.file Files]
           [java.nio.file.attribute FileAttribute]
           [com.sun.jna Pointer]))

(def ^:private embedded-extensions-resource-path "extensions/")
(def ^:private embedded-extensions-temp-dir (atom nil))

(defn- get-embedded-extensions-dir
  "Get or create a temp directory for extracted embedded extensions."
  []
  (when-not @embedded-extensions-temp-dir
    (let [temp-dir (Files/createTempDirectory "trexsql-extensions"
                                               (make-array FileAttribute 0))]
      (reset! embedded-extensions-temp-dir (.toFile temp-dir))
      ;; Register shutdown hook to clean up
      (.addShutdownHook (Runtime/getRuntime)
                        (Thread. #(when-let [^File dir @embedded-extensions-temp-dir]
                                    (doseq [^File f (.listFiles dir)]
                                      (.delete f))
                                    (.delete dir))))))
  @embedded-extensions-temp-dir)

(defn- extract-embedded-extension
  "Extract an embedded extension from JAR resources to temp directory.
   Returns the File path or nil if not found."
  [ext-name]
  (let [resource-path (str embedded-extensions-resource-path ext-name ".trex")
        resource (io/resource resource-path)]
    (when resource
      (let [temp-dir (get-embedded-extensions-dir)
            ext-file (File. ^File temp-dir ^String (str ext-name ".trex"))]
        (when-not (.exists ext-file)
          (println (str "Extracting embedded extension: " ext-name))
          (with-open [in (io/input-stream resource)
                      out (FileOutputStream. ext-file)]
            (io/copy in out)))
        ext-file))))

(defn find-embedded-extensions
  "Find all embedded extensions in JAR resources.
   Returns seq of extension names (without .trex suffix)."
  []
  ;; This is tricky - we can't easily list resources in a JAR
  ;; So we check for known extensions
  (let [known-extensions ["circe" "tpm" "pgwire" "llama"]]
    (filter #(io/resource (str embedded-extensions-resource-path % ".trex"))
            known-extensions)))

(defn has-avx-support?
  "Check if the CPU supports AVX instructions.
   Reads /proc/cpuinfo on Linux."
  []
  (try
    (let [cpuinfo (slurp "/proc/cpuinfo")]
      (boolean (re-find #"\bavx\b" cpuinfo)))
    (catch Exception _
      false)))

(defn- extension-file?
  [^File f]
  (and (.isFile f)
       (or (str/ends-with? (.getName f) ".duckdb_extension")
           (str/ends-with? (.getName f) ".trex"))))

(defn- extension-name
  [^File f]
  (str/replace (.getName f) #"\.(duckdb_extension|trex)$" ""))

(defn find-extensions
  "Find all TrexSQL extension files in the given directory.
   Searches recursively in @trex subdirectories.
   Returns seq of {:name <string> :path <string> :requires-avx <boolean>},
   sorted with 'pool' first (load-order requirement of dependent extensions)
   then alphabetic by name for determinism."
  [extensions-path]
  ;; ^File hints keep .isDirectory/.listFiles/.getAbsolutePath as direct method
  ;; calls. Without them Clojure emits reflective calls, which fail under the
  ;; GraalVM native image (libwebapi-native.so) with "No matching field found:
  ;; isDirectory for class java.io.File" and abort webapi_start().
  (let [^File base-dir (io/file extensions-path)]
    (when (.isDirectory base-dir)
      (->> (for [^File subdir (.listFiles base-dir)
                 :when (.isDirectory subdir)
                 ^File ext-file (.listFiles subdir)
                 :when (extension-file? ext-file)
                 :let [ext-name (extension-name ext-file)]]
             {:name ext-name
              :path (.getAbsolutePath ext-file)
              :requires-avx (= ext-name "llama")})
           (sort-by (fn [{ext-name :name}]
                      [(if (= ext-name "pool") 0 1) ext-name]))))))

(defn load-extension
  "Load a single extension into the TrexSQL connection.
   Returns {:name <string> :loaded <boolean> :error <string or nil>}"
  [^Pointer handle {:keys [name path requires-avx]}]
  (let [avx-available? (has-avx-support?)]
    (cond
      ;; Skip llama if no AVX support
      (and requires-avx (not avx-available?))
      (do
        (println (str "Skipping " name " extension (no AVX support)"))
        {:name name :loaded false :error "No AVX support"})

      :else
      (try
        (println (str "Loading extension: " name))
        (native/execute! handle (str "LOAD '" path "'"))
        {:name name :loaded true :error nil}
        (catch Exception e
          (println (str "Failed to load extension: " path))
          (println (str "  Error: " (.getMessage e)))
          {:name name :loaded false :error (.getMessage e)})))))

(defn load-embedded-extension
  "Load a single embedded extension by name.
   Extracts from JAR resources if available.
   Returns {:name <string> :loaded <boolean> :error <string or nil>}"
  [^Pointer handle ext-name]
  (let [avx-available? (has-avx-support?)
        requires-avx? (= ext-name "llama")]
    (cond
      ;; Skip llama if no AVX support
      (and requires-avx? (not avx-available?))
      (do
        (println (str "Skipping embedded " ext-name " extension (no AVX support)"))
        {:name ext-name :loaded false :error "No AVX support"})

      :else
      (if-let [^File ext-file (extract-embedded-extension ext-name)]
        (try
          (println (str "Loading embedded extension: " ext-name))
          (native/execute! handle (str "LOAD '" (.getAbsolutePath ext-file) "'"))
          {:name ext-name :loaded true :error nil}
          (catch Exception e
            (println (str "Failed to load embedded extension: " ext-name))
            (println (str "  Error: " (.getMessage e)))
            {:name ext-name :loaded false :error (.getMessage e)}))
        {:name ext-name :loaded false :error "Not embedded in JAR"}))))

(defn load-all-embedded-extensions
  "Load all embedded extensions from JAR resources.
   Returns set of successfully loaded extension names."
  [^Pointer handle]
  (let [embedded (find-embedded-extensions)]
    (if (empty? embedded)
      (do
        (println "No embedded extensions found in JAR")
        #{})
      (let [results (map #(load-embedded-extension handle %) embedded)
            loaded (filter :loaded results)]
        (println (str "Loaded " (count loaded) " embedded extension(s)"))
        (set (map :name loaded))))))

(defn load-extensions
  "Load all extensions from the configured directory and embedded resources.
   Returns set of successfully loaded extension names."
  [^Pointer handle extensions-path]
  ;; First load embedded extensions
  (let [embedded-loaded (load-all-embedded-extensions handle)
        ;; Then load from external directory
        external-extensions (find-extensions extensions-path)
        ;; Filter out extensions already loaded from embedded
        external-to-load (remove #(contains? embedded-loaded (:name %)) external-extensions)]
    (if (empty? external-to-load)
      embedded-loaded
      (let [results (map #(load-extension handle %) external-to-load)
            loaded (filter :loaded results)]
        (into embedded-loaded (map :name loaded))))))

(defn pre-extract-all-embedded
  "Extract every embedded JAR extension to the given directory using the
   existing extract-embedded-extension mechanism. Returns the vector of
   absolute paths to the extracted .trex files (or paths that were
   already on disk).

   Used by orchestrated-mode init so db.trex's orchestrator can LOAD
   each extension by its conventional name without first having to
   handle JAR-resource indirection."
  [target-dir]
  (let [tdir (io/file target-dir)]
    (when-not (.exists tdir)
      (.mkdirs tdir))
    (vec
      (for [ext-name (find-embedded-extensions)
            :let [src (extract-embedded-extension ext-name)
                  ;; src is already on disk: extract-embedded-extension writes the JAR
                  ;; resource to a JVM-private temp dir on first call and returns its File.
                  ;; Copy from there to the caller's target-dir so the orchestrator can LOAD by path.
                  dst (io/file tdir (str ext-name ".trex"))]
            :when src]
        (do
          ;; Size match is sufficient: .trex artifacts change with every build,
          ;; so size collision across versions is vanishingly unlikely.
          (when (or (not (.exists dst))
                    (not= (.length ^File src) (.length ^File dst)))
            (io/copy src dst))
          (.getAbsolutePath dst))))))

(defn load-scoped-extensions
  "Load a caller-specified subset of extensions, ensuring pool is loaded
   first (since other extensions depend on it at LOAD time).

   Args:
     handle           JNA Pointer to the open trexsql native database
     ext-names        seq of extension names (keywords or strings)
     extensions-path  directory to search for external .trex files
     opts (optional)  map with:
                        :no-pool true  skip auto-prepend of pool
                                       (caller asserts no pool-dependent
                                       extension is in the list)

   Returns a set of successfully-loaded extension names."
  [^Pointer handle ext-names extensions-path & [{:keys [no-pool]}]]
  (let [requested  (mapv name ext-names)
        with-pool  (if no-pool
                     requested
                     (cons "pool" (remove #{"pool"} requested)))
        ;; Embedded names are resolved by find-embedded-extensions (filters to
        ;; what's actually in the JAR); external names resolve via find-extensions.
        embedded   (set (find-embedded-extensions))
        external   (->> (find-extensions extensions-path)
                        (map (juxt :name identity))
                        (into {}))
        loaded     (atom #{})]
    (doseq [ename with-pool]
      (cond
        (contains? embedded ename)
        (when (:loaded (load-embedded-extension handle ename))
          (swap! loaded conj ename))

        (contains? external ename)
        (when (:loaded (load-extension handle (get external ename)))
          (swap! loaded conj ename))

        :else
        (println (str "load-scoped-extensions: '" ename "' not found in embedded or " extensions-path))))
    @loaded))

(defn loaded-from-engine
  "Query the trexsql engine for currently-loaded extensions. Returns a set
   of extension-name strings. Used after orchestrated-mode init to sync
   bao's bookkeeping with what the orchestrator actually loaded."
  [^Pointer handle]
  (try
    (let [rows (native/query handle
                  "SELECT extension_name FROM duckdb_extensions() WHERE loaded")]
      ;; native/query returns ArrayList<HashMap<String,Object>> with string keys.
      ;; Each row is a HashMap; extract the "extension_name" column by key.
      (set (map #(get % "extension_name") rows)))
    (catch Exception e
      (println (str "loaded-from-engine: query failed (" (.getMessage e) ")"))
      #{})))

(defn loaded-extensions
  "Return set of loaded extension names from database state."
  [db]
  (:extensions-loaded db))
