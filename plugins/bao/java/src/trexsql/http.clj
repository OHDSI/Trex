(ns trexsql.http
  "HTTP request functions for trex_http_request TrexSQL scalar."
  (:require [trexsql.db :as db]
            [trexsql.errors :as errors]
            [trexsql.json :as json])
  (:import [java.util Map HashMap ArrayList]))

(def ^:const default-timeout-ms 30000)
(def ^:const max-timeout-ms 600000)
(def ^:const default-max-redirects 10)
(def ^:const max-max-redirects 20)
(def ^:const valid-methods #{"GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS"})

(defn validate-http-options
  "Returns nil if valid, error string if invalid."
  [{:keys [method url headers body options]}]
  (cond
    (nil? method) "Method is required"
    (not (string? method)) "Method must be a string"
    (not (contains? valid-methods (clojure.string/upper-case method)))
    (str "Invalid method: " method ". Must be one of: " (clojure.string/join ", " valid-methods))

    (nil? url) "URL is required"
    (not (string? url)) "URL must be a string"
    (and (not (clojure.string/starts-with? url "http://"))
         (not (clojure.string/starts-with? url "https://"))
         (not (clojure.string/starts-with? url "/")))
    "URL must start with http://, https://, or /"

    (and headers (not (map? headers))) "Headers must be a map"
    (and body (not (string? body))) "Body must be a string"
    (and options (not (map? options))) "Options must be a map"

    (and (:timeout-ms options) (not (integer? (:timeout-ms options))))
    "timeout-ms must be an integer"
    (and (:timeout-ms options)
         (or (< (:timeout-ms options) 1) (> (:timeout-ms options) max-timeout-ms)))
    (str "timeout-ms must be between 1 and " max-timeout-ms)

    (and (contains? options :follow-redirects) (not (boolean? (:follow-redirects options))))
    "follow-redirects must be a boolean"

    (and (:max-redirects options) (not (integer? (:max-redirects options))))
    "max-redirects must be an integer"
    (and (:max-redirects options)
         (or (< (:max-redirects options) 0) (> (:max-redirects options) max-max-redirects)))
    (str "max-redirects must be between 0 and " max-max-redirects)

    :else nil))

(defn build-request-json
  "Build JSON string for trex_http_request."
  [{:keys [method url headers body options]}]
  (let [request {:method (clojure.string/upper-case method) :url url}
        request (if (seq headers) (assoc request :headers headers) request)
        request (if body (assoc request :body body) request)
        request (if (seq options)
                  (assoc request :options
                         (cond-> {}
                           (:timeout-ms options) (assoc :timeout_ms (:timeout-ms options))
                           (contains? options :follow-redirects) (assoc :follow_redirects (:follow-redirects options))
                           (:max-redirects options) (assoc :max_redirects (:max-redirects options))))
                  request)]
    (json/write-str request)))

(defn execute-http-request
  "Execute request via trex_http_request. Returns raw JSON response."
  [db request-json]
  (let [escaped-json (clojure.string/replace request-json "'" "''")
        sql (str "SELECT trex_http_request('" escaped-json "')")
        results (db/query db sql)]
    (when (seq results)
      (-> results first vals first))))

(defn parse-response-json
  "Parse JSON response to Clojure map with kebab-case keys."
  [json-str]
  (when json-str
    (let [parsed (json/read-str json-str :key-fn keyword)]
      (cond-> {:success (:success parsed)}
        (some? (:status_code parsed)) (assoc :status-code (:status_code parsed))
        (some? (:headers parsed)) (assoc :headers (:headers parsed))
        (some? (:body parsed)) (assoc :body (:body parsed))
        (some? (:encoding parsed)) (assoc :encoding (:encoding parsed))
        (some? (:truncated parsed)) (assoc :truncated (:truncated parsed))
        (some? (:error parsed)) (assoc :error (:error parsed))))))

(defn http-response->java-map
  "Convert response to Java HashMap."
  [response]
  (let [result (HashMap.)]
    (.put result "success" (:success response))
    (when (:status-code response) (.put result "status-code" (:status-code response)))
    (when (:headers response)
      (let [headers-map (HashMap.)]
        (doseq [[k v] (:headers response)]
          (.put headers-map (name k) v))
        (.put result "headers" headers-map)))
    (when (:body response) (.put result "body" (:body response)))
    (when (:encoding response) (.put result "encoding" (:encoding response)))
    (when (:truncated response) (.put result "truncated" (:truncated response)))
    (when (:error response) (.put result "error" (:error response)))
    result))

(defn java-map->http-options
  "Convert Java Map to options map."
  [^Map m]
  (when m
    (let [method (.get m "method")
          url (.get m "url")
          headers (.get m "headers")
          body (.get m "body")
          options (.get m "options")]
      (cond-> {}
        method (assoc :method method)
        url (assoc :url url)
        headers (assoc :headers (into {} headers))
        body (assoc :body body)
        options (assoc :options
                       (cond-> {}
                         (get options "timeout-ms") (assoc :timeout-ms (get options "timeout-ms"))
                         (some? (get options "follow-redirects")) (assoc :follow-redirects (get options "follow-redirects"))
                         (get options "max-redirects") (assoc :max-redirects (get options "max-redirects"))))))))

(defn http-request
  "Execute HTTP request to user worker. Returns map with :success, :status-code, :headers, :body, :error."
  [db method url & {:keys [headers body options]}]
  (let [request {:method method :url url :headers headers :body body :options options}]
    (when-let [error (validate-http-options request)]
      (throw (errors/validation-error error {:field "http-request"})))
    (-> (build-request-json request)
        (execute-http-request db ,,,)
        parse-response-json)))
