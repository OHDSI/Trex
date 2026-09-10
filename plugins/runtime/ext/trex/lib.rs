pub mod connection;
pub mod query_executor;

use base64::{engine::general_purpose, Engine as _};
use deno_core::op2;
use deno_error::JsError;
use thiserror::Error;

/// Error type for trex operations that implements JsErrorClass
#[derive(Debug, Error, JsError)]
pub enum TrexError {
  #[class(generic)]
  #[error("{0}")]
  Generic(String),
  #[class(generic)]
  #[error("Resource error: {0}")]
  Resource(#[from] deno_core::error::ResourceError),
}
use duckdb::arrow::array::{
  Array, BinaryArray, BooleanArray, Date32Array, Date64Array, Decimal128Array,
  Decimal256Array, Float32Array, Float64Array, Int16Array, Int32Array,
  Int64Array, Int8Array, LargeBinaryArray, LargeStringArray, StringArray,
  Time32SecondArray, Time64MicrosecondArray, TimestampMicrosecondArray,
  TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray,
  UInt16Array, UInt32Array, UInt64Array, UInt8Array,
};
use duckdb::arrow::datatypes::{DataType, TimeUnit};
use duckdb::arrow::record_batch::RecordBatch;
use duckdb::{
  params_from_iter, types::ToSqlOutput, types::Value, Config, Connection, ToSql,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use std::cell::RefCell;
use std::env;
use std::error::Error as StdError;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use tracing::warn;
use uuid::Uuid;

use deno_core::{OpState, Resource, ResourceId};
use std::collections::HashMap;
use std::rc::Rc;
use tokio::sync::{mpsc, oneshot};

type PendingRequestsMap =
  Arc<Mutex<HashMap<String, oneshot::Sender<JsonValue>>>>;
type RequestListenersMap = Arc<Mutex<HashMap<u64, mpsc::Sender<JsonValue>>>>;

static TREX_DB: LazyLock<Arc<Mutex<Connection>>> = LazyLock::new(|| {
  let cfg = Config::default()
    .allow_unsigned_extensions()
    .unwrap_or_default();

  let conn = Connection::open_in_memory_with_flags(cfg)
    .expect("failed to open DuckDB in-memory");

  if let Ok(path) = std::env::var("DUCKDB_CIRCE_EXTENSION") {
    if let Err(e) =
      conn.execute(&format!("LOAD '{}'", path.replace('\'', "''")), [])
    {
      warn!(path, error = %e, "failed to load circe extension");
    }
  } else {
    let _ = conn.execute("LOAD circe", []);
  }

  let pool_size: usize = match env::var("TREX_CONNECTION_POOL_SIZE") {
    Ok(v) => v.parse().unwrap_or_else(|_| {
      warn!(value = %v, "invalid TREX_CONNECTION_POOL_SIZE, defaulting to 0");
      0
    }),
    Err(_) => 0,
  };

  if pool_size > 0 {
    let _ = connection::init_query_executor(&conn, pool_size);
  }
  let conn_arc = Arc::new(Mutex::new(conn));
  conn_arc
});
static DB_CREDENTIALS: LazyLock<Arc<Mutex<String>>> = LazyLock::new(|| {
  Arc::new(Mutex::new(String::from(
    "{\"credentials\":[], \"publications\":{}}",
  )))
});

// Inter-worker request listeners, keyed by registration id. The trexas main
// service runs as several isolates (one per primary-pool thread), each
// registering a listener, so a superseded/closed one no longer disables the
// channel for the others.
static REQUEST_LISTENERS: LazyLock<RequestListenersMap> =
  LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));
static LISTENER_NEXT_ID: AtomicU64 = AtomicU64::new(1);

static PENDING_REQUESTS: LazyLock<PendingRequestsMap> =
  LazyLock::new(|| Arc::new(Mutex::new(HashMap::new())));

#[allow(clippy::type_complexity)]
static STATIC_ROUTES: LazyLock<Arc<RwLock<Vec<(String, PathBuf)>>>> =
  LazyLock::new(|| Arc::new(RwLock::new(Vec::new())));

pub struct StaticFileResponse {
  pub body: Vec<u8>,
  pub content_type: String,
}

#[op2(fast)]
fn op_register_static_route(
  #[string] url_prefix: String,
  #[string] fs_path: String,
) {
  let mut routes = STATIC_ROUTES.write().unwrap();
  routes.push((url_prefix, PathBuf::from(fs_path)));
  routes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
}

pub fn try_serve_static(uri_path: &str) -> Option<StaticFileResponse> {
  let routes = STATIC_ROUTES.read().unwrap();
  for (prefix, fs_root) in routes.iter() {
    if uri_path.starts_with(prefix) {
      let relative = &uri_path[prefix.len()..];
      let relative = relative.trim_start_matches('/');

      if relative.split('/').any(|seg| seg == "..") {
        return None;
      }

      let file_path = if relative.is_empty() {
        fs_root.join("index.html")
      } else {
        fs_root.join(relative)
      };

      if file_path.is_file() {
        if let Ok(body) = std::fs::read(&file_path) {
          let content_type = mime_from_ext(
            file_path.extension().and_then(|e| e.to_str()).unwrap_or(""),
          );
          return Some(StaticFileResponse { body, content_type });
        }
      }
      return None;
    }
  }
  None
}

fn mime_from_ext(ext: &str) -> String {
  match ext {
    "html" | "htm" => "text/html",
    "css" => "text/css",
    "js" | "mjs" => "application/javascript",
    "json" => "application/json",
    "png" => "image/png",
    "jpg" | "jpeg" => "image/jpeg",
    "gif" => "image/gif",
    "svg" => "image/svg+xml",
    "ico" => "image/x-icon",
    "woff" => "font/woff",
    "woff2" => "font/woff2",
    "ttf" => "font/ttf",
    "eot" => "application/vnd.ms-fontobject",
    "txt" => "text/plain",
    "xml" => "application/xml",
    "wasm" => "application/wasm",
    _ => "application/octet-stream",
  }
  .to_string()
}

fn get_active_connection() -> Arc<Mutex<Connection>> {
  connection::get_connection().unwrap_or_else(|| TREX_DB.clone())
}

#[op2]
#[string]
fn op_get_dbc() -> String {
  get_dbc_inner()
}

fn get_dbc_inner() -> String {
  DB_CREDENTIALS.lock().unwrap().clone()
}

#[op2]
#[string]
fn op_get_dbc2() -> String {
  get_dbc2_inner()
}

fn get_dbc2_inner() -> String {
  let mut base_creds: serde_json::Value =
    serde_json::from_str(&DB_CREDENTIALS.lock().unwrap().clone())
      .unwrap_or_else(
        |_| serde_json::json!({"credentials": [], "publications": {}}),
      );

  if let (Ok(host), Ok(port), Ok(user), Ok(password), Ok(dbname)) = (
    std::env::var("TREX__SQL__HOST"),
    std::env::var("TREX__SQL__PORT"),
    std::env::var("TREX__SQL__USER"),
    std::env::var("TREX__SQL__PASSWORD"),
    std::env::var("TREX__SQL__DBNAME"),
  ) {
    let result_db = serde_json::json!({
      "id": "RESULT",
      "code": "RESULT",
      "dialect": "postgres",
      "authentication_mode": "Password",
      "host": host,
      "port": port.parse::<u16>().unwrap_or(5432),
      "name": dbname,
      "credentials": [
        {
          "username": user,
          "password": password,
          "userScope": "Admin",
          "serviceScope": "Internal"
        }
      ],
      "publications": [],
      "vocab_schemas": []
    });

    if let Some(credentials) = base_creds
      .get_mut("credentials")
      .and_then(|c| c.as_array_mut())
    {
      if !credentials
        .iter()
        .any(|c| c.get("id").and_then(|id| id.as_str()) == Some("RESULT"))
      {
        credentials.push(result_db);
      }
    }
  }

  if let (Ok(host), Ok(dbname), Ok(user), Ok(password)) = (
    std::env::var("PG__HOST"),
    std::env::var("PG__FHIR_DB_NAME"),
    std::env::var("PG_USER"),
    std::env::var("PG_PASSWORD"),
  ) {
    let port = std::env::var("PG__PORT")
      .ok()
      .and_then(|p| p.parse::<u16>().ok())
      .unwrap_or(5432);

    let fhir_db = serde_json::json!({
      "id": "FHIR",
      "code": "FHIR",
      "dialect": "postgres",
      "authentication_mode": "Password",
      "host": host,
      "port": port,
      "name": dbname,
      "credentials": [
        {
          "username": user,
          "password": password,
          "userScope": "Admin",
          "serviceScope": "Internal"
        }
      ],
      "publications": [],
      "vocab_schemas": []
    });

    if let Some(credentials) = base_creds
      .get_mut("credentials")
      .and_then(|c| c.as_array_mut())
    {
      if !credentials
        .iter()
        .any(|c| c.get("id").and_then(|id| id.as_str()) == Some("FHIR"))
      {
        credentials.push(fhir_db);
      }
    }
  }

  serde_json::to_string(&base_creds).unwrap_or_else(|_| {
    String::from("{\"credentials\":[], \"publications\":{}}")
  })
}

#[op2(fast)]
fn op_set_dbc(#[string] dbc: String) {
  set_dbc_inner(dbc);
}

fn set_dbc_inner(dbc: String) {
  *DB_CREDENTIALS.lock().unwrap() = dbc;
}

/// Gate for verbose SQL-statement logging. Executed SQL can embed connection
/// strings (e.g. `ATTACH '... password=...'`), so logging it is OFF by default
/// and must be opted into with `TREX__LOG__SQL=1` (or true/yes/on). Even when
/// enabled, the JS layer redacts secrets before printing.
#[op2(fast)]
fn op_sql_log_enabled() -> bool {
  env::var("TREX__LOG__SQL")
    .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
    .unwrap_or(false)
}

#[op2(fast)]
fn op_install_plugin(#[string] name: String, #[string] dir: String) {
  use tracing::{error, info};

  let use_node_modules = env::var("TPM_USE_NODE_MODULES")
    .map(|v| v.to_lowercase() != "false")
    .unwrap_or(true);

  let install_dir = if use_node_modules {
    format!("{dir}/node_modules")
  } else {
    dir
  };

  let _ =
    execute_query("memory".to_string(), "LOAD 'tpm'".to_string(), vec![], -1, 0);

  let sql = format!(
    "SELECT install_results FROM tpm_install('{}', '{}')",
    name.replace('\'', "''"),
    install_dir.replace('\'', "''")
  );

  match execute_query("memory".to_string(), sql, vec![], -1, 0) {
    Ok(json_str) => {
      match serde_json::from_str::<Vec<serde_json::Value>>(&json_str) {
        Ok(rows) if rows.is_empty() => {
          warn!(package = %name, "no packages installed");
        }
        Ok(rows) => {
          let (mut ok, mut err) = (0usize, 0usize);
          for row in rows {
            if let Some(result) = row
              .get("install_results")
              .and_then(|v| serde_json::from_value::<String>(v.clone()).ok())
              .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            {
              let pkg = result
                .get("package")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
              let ver = result
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
              if result
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
              {
                info!(package = pkg, version = ver, "installed");
                ok += 1;
              } else {
                let e = result
                  .get("error")
                  .and_then(|v| v.as_str())
                  .unwrap_or("unknown");
                error!(package = pkg, error = e, "install failed");
                err += 1;
              }
            }
          }
          info!(succeeded = ok, failed = err, "plugin install complete");
        }
        Err(e) => warn!(error = %e, "failed to parse install results"),
      }
    }
    Err(e) => warn!(package = %name, error = %e, "plugin install failed"),
  }
}

#[derive(Serialize, Deserialize)]
enum TrexType {
  Integer(i64),
  String(String),
  Number(f64),
  DateTime(i64),
}

impl ToSql for TrexType {
  fn to_sql(&self) -> duckdb::Result<ToSqlOutput<'_>> {
    match self {
      TrexType::Integer(v) => {
        let value: Value = (*v).into();
        Ok(ToSqlOutput::Owned(value))
      }
      TrexType::String(v) => {
        let value: Value = v.clone().into();
        Ok(ToSqlOutput::Owned(value))
      }
      TrexType::DateTime(v) => {
        let value: Value =
          Value::Timestamp(duckdb::types::TimeUnit::Millisecond, *v);
        Ok(ToSqlOutput::Owned(value))
      }
      TrexType::Number(v) => {
        let value: Value = (*v).into();
        Ok(ToSqlOutput::Owned(value))
      }
    }
  }
}

fn field_value_to_json(
  array: &dyn Array,
  row: usize,
  dt: &DataType,
) -> JsonValue {
  if array.is_null(row) {
    return JsonValue::Null;
  }
  match dt {
    DataType::Null => JsonValue::Null,
    DataType::Utf8 => {
      let arr = array.as_any().downcast_ref::<StringArray>().unwrap();
      JsonValue::String(arr.value(row).to_string())
    }
    DataType::LargeUtf8 => {
      let arr = array.as_any().downcast_ref::<LargeStringArray>().unwrap();
      JsonValue::String(arr.value(row).to_string())
    }
    DataType::Binary => {
      let arr = array.as_any().downcast_ref::<BinaryArray>().unwrap();
      let bytes = arr.value(row);
      JsonValue::String(general_purpose::STANDARD.encode(bytes))
    }
    DataType::LargeBinary => {
      let arr = array.as_any().downcast_ref::<LargeBinaryArray>().unwrap();
      let bytes = arr.value(row);
      JsonValue::String(general_purpose::STANDARD.encode(bytes))
    }
    DataType::Int8 => {
      let arr = array.as_any().downcast_ref::<Int8Array>().unwrap();
      JsonValue::from(arr.value(row) as i64)
    }
    DataType::Int16 => {
      let arr = array.as_any().downcast_ref::<Int16Array>().unwrap();
      JsonValue::from(arr.value(row) as i64)
    }
    DataType::Int32 => {
      let arr = array.as_any().downcast_ref::<Int32Array>().unwrap();
      JsonValue::from(arr.value(row) as i64)
    }
    DataType::Int64 => {
      let arr = array.as_any().downcast_ref::<Int64Array>().unwrap();
      JsonValue::from(arr.value(row))
    }
    DataType::UInt8 => {
      let arr = array.as_any().downcast_ref::<UInt8Array>().unwrap();
      JsonValue::from(arr.value(row) as u64)
    }
    DataType::UInt16 => {
      let arr = array.as_any().downcast_ref::<UInt16Array>().unwrap();
      JsonValue::from(arr.value(row) as u64)
    }
    DataType::UInt32 => {
      let arr = array.as_any().downcast_ref::<UInt32Array>().unwrap();
      JsonValue::from(arr.value(row) as u64)
    }
    DataType::UInt64 => {
      let arr = array.as_any().downcast_ref::<UInt64Array>().unwrap();
      JsonValue::from(arr.value(row))
    }
    DataType::Float32 => {
      let arr = array.as_any().downcast_ref::<Float32Array>().unwrap();
      JsonValue::from(arr.value(row) as f64)
    }
    DataType::Float64 => {
      let arr = array.as_any().downcast_ref::<Float64Array>().unwrap();
      JsonValue::from(arr.value(row))
    }
    DataType::Boolean => {
      let arr = array.as_any().downcast_ref::<BooleanArray>().unwrap();
      JsonValue::from(arr.value(row))
    }
    DataType::Date32 => {
      let arr = array.as_any().downcast_ref::<Date32Array>().unwrap();
      let days = arr.value(row);
      let timestamp = days as i64 * 86400;
      let datetime = chrono::DateTime::from_timestamp(timestamp, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
      JsonValue::String(datetime.format("%Y-%m-%d").to_string())
    }
    DataType::Date64 => {
      let arr = array.as_any().downcast_ref::<Date64Array>().unwrap();
      let millis = arr.value(row);
      let datetime = chrono::DateTime::from_timestamp_millis(millis)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
      JsonValue::String(datetime.format("%Y-%m-%d").to_string())
    }
    DataType::Time32(_) => {
      let arr = array.as_any().downcast_ref::<Time32SecondArray>().unwrap();
      JsonValue::from(arr.value(row))
    }
    DataType::Time64(_) => {
      let arr = array
        .as_any()
        .downcast_ref::<Time64MicrosecondArray>()
        .unwrap();
      JsonValue::from(arr.value(row))
    }
    DataType::Timestamp(TimeUnit::Second, _) => {
      let arr = array
        .as_any()
        .downcast_ref::<TimestampSecondArray>()
        .unwrap();
      let seconds = arr.value(row);
      let datetime = chrono::DateTime::from_timestamp(seconds, 0)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
      JsonValue::String(datetime.to_rfc3339())
    }
    DataType::Timestamp(TimeUnit::Millisecond, _) => {
      let arr = array
        .as_any()
        .downcast_ref::<TimestampMillisecondArray>()
        .unwrap();
      let millis = arr.value(row);
      let datetime = chrono::DateTime::from_timestamp_millis(millis)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
      JsonValue::String(datetime.to_rfc3339())
    }
    DataType::Timestamp(TimeUnit::Microsecond, _) => {
      let arr = array
        .as_any()
        .downcast_ref::<TimestampMicrosecondArray>()
        .unwrap();
      let micros = arr.value(row);
      let datetime = chrono::DateTime::from_timestamp_micros(micros)
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
      JsonValue::String(datetime.to_rfc3339())
    }
    DataType::Timestamp(TimeUnit::Nanosecond, _) => {
      let arr = array
        .as_any()
        .downcast_ref::<TimestampNanosecondArray>()
        .unwrap();
      let nanos = arr.value(row);
      let datetime = chrono::DateTime::from_timestamp_nanos(nanos);
      JsonValue::String(datetime.to_rfc3339())
    }
    DataType::Decimal128(_, scale) => {
      let arr = array.as_any().downcast_ref::<Decimal128Array>().unwrap();
      let value = arr.value(row);
      let decimal_value = value as f64 / 10_f64.powi(*scale as i32);
      JsonValue::from(decimal_value)
    }
    DataType::Decimal256(_, scale) => {
      let arr = array.as_any().downcast_ref::<Decimal256Array>().unwrap();
      let s = format_decimal_string(&arr.value(row).to_string(), *scale as i32);
      serde_json::from_str(&s).unwrap_or(JsonValue::String(s))
    }
    _ => arrow_cast::display::array_value_to_string(array, row)
      .map(JsonValue::String)
      .unwrap_or(JsonValue::Null),
  }
}

/// Format a stringified integer (raw decimal value) with a given scale into
/// the conventional decimal text form. Pure string manipulation — preserves
/// full precision regardless of integer width (i128, i256).
fn format_decimal_string(digits: &str, scale: i32) -> String {
  let (neg, digits) = if let Some(rest) = digits.strip_prefix('-') {
    (true, rest)
  } else {
    (false, digits)
  };
  let body = if scale <= 0 {
    let mut out = digits.to_string();
    for _ in 0..(-scale) {
      out.push('0');
    }
    out
  } else {
    let scale = scale as usize;
    if digits.len() <= scale {
      let mut frac = "0".repeat(scale - digits.len());
      frac.push_str(digits);
      format!("0.{}", frac)
    } else {
      let split = digits.len() - scale;
      format!("{}.{}", &digits[..split], &digits[split..])
    }
  };
  if neg {
    format!("-{}", body)
  } else {
    body
  }
}

fn record_batches_to_json(batches: &[RecordBatch]) -> String {
  let mut rows: Vec<JsonValue> = Vec::new();
  for batch in batches {
    let schema = batch.schema();
    let n_rows = batch.num_rows();
    for r in 0..n_rows {
      let mut obj = JsonMap::with_capacity(batch.num_columns());
      for (i, field) in schema.fields().iter().enumerate() {
        let col = batch.column(i);
        let v = field_value_to_json(col.as_ref(), r, field.data_type());
        obj.insert(field.name().clone(), v);
      }
      rows.push(JsonValue::Object(obj));
    }
  }
  serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
}

/// Convert pool-client Arrow RecordBatches (arrow v57) to JSON string.
fn pool_batches_to_json(batches: &[trex_pool_client::arrow_array::RecordBatch]) -> String {
  use trex_pool_client::arrow_array::*;
  use trex_pool_client::arrow_schema::{DataType, TimeUnit};

  let mut rows: Vec<serde_json::Value> = Vec::new();
  for batch in batches {
    let schema = batch.schema();
    for r in 0..batch.num_rows() {
      let mut obj = serde_json::Map::new();
      for (i, field) in schema.fields().iter().enumerate() {
        let col = batch.column(i);
        let v: serde_json::Value = if col.is_null(r) {
          serde_json::Value::Null
        } else {
          match col.data_type() {
            DataType::Null => serde_json::Value::Null,
            DataType::Utf8 => {
              let a = col.as_any().downcast_ref::<StringArray>().unwrap();
              serde_json::Value::String(a.value(r).to_string())
            }
            DataType::LargeUtf8 => {
              let a = col.as_any().downcast_ref::<LargeStringArray>().unwrap();
              serde_json::Value::String(a.value(r).to_string())
            }
            DataType::Binary => {
              let a = col.as_any().downcast_ref::<BinaryArray>().unwrap();
              serde_json::Value::String(general_purpose::STANDARD.encode(a.value(r)))
            }
            DataType::LargeBinary => {
              let a = col.as_any().downcast_ref::<LargeBinaryArray>().unwrap();
              serde_json::Value::String(general_purpose::STANDARD.encode(a.value(r)))
            }
            DataType::Int8 => {
              let a = col.as_any().downcast_ref::<Int8Array>().unwrap();
              serde_json::Value::from(a.value(r) as i64)
            }
            DataType::Int16 => {
              let a = col.as_any().downcast_ref::<Int16Array>().unwrap();
              serde_json::Value::from(a.value(r) as i64)
            }
            DataType::Int32 => {
              let a = col.as_any().downcast_ref::<Int32Array>().unwrap();
              serde_json::Value::from(a.value(r) as i64)
            }
            DataType::Int64 => {
              let a = col.as_any().downcast_ref::<Int64Array>().unwrap();
              serde_json::Value::from(a.value(r))
            }
            DataType::UInt8 => {
              let a = col.as_any().downcast_ref::<UInt8Array>().unwrap();
              serde_json::Value::from(a.value(r) as u64)
            }
            DataType::UInt16 => {
              let a = col.as_any().downcast_ref::<UInt16Array>().unwrap();
              serde_json::Value::from(a.value(r) as u64)
            }
            DataType::UInt32 => {
              let a = col.as_any().downcast_ref::<UInt32Array>().unwrap();
              serde_json::Value::from(a.value(r) as u64)
            }
            DataType::UInt64 => {
              let a = col.as_any().downcast_ref::<UInt64Array>().unwrap();
              serde_json::Value::from(a.value(r))
            }
            DataType::Float32 => {
              let a = col.as_any().downcast_ref::<Float32Array>().unwrap();
              serde_json::Value::from(a.value(r) as f64)
            }
            DataType::Float64 => {
              let a = col.as_any().downcast_ref::<Float64Array>().unwrap();
              serde_json::Value::from(a.value(r))
            }
            DataType::Boolean => {
              let a = col.as_any().downcast_ref::<BooleanArray>().unwrap();
              serde_json::Value::from(a.value(r))
            }
            DataType::Date32 => {
              let a = col.as_any().downcast_ref::<Date32Array>().unwrap();
              let days = a.value(r);
              let timestamp = days as i64 * 86400;
              let datetime = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH);
              serde_json::Value::String(datetime.format("%Y-%m-%d").to_string())
            }
            DataType::Date64 => {
              let a = col.as_any().downcast_ref::<Date64Array>().unwrap();
              let millis = a.value(r);
              let datetime = chrono::DateTime::from_timestamp_millis(millis)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH);
              serde_json::Value::String(datetime.format("%Y-%m-%d").to_string())
            }
            DataType::Time32(_) => {
              let a = col.as_any().downcast_ref::<Time32SecondArray>().unwrap();
              serde_json::Value::from(a.value(r) as i64)
            }
            DataType::Time64(_) => {
              let a = col.as_any().downcast_ref::<Time64MicrosecondArray>().unwrap();
              serde_json::Value::from(a.value(r))
            }
            DataType::Timestamp(TimeUnit::Second, _) => {
              let a = col.as_any().downcast_ref::<TimestampSecondArray>().unwrap();
              let datetime = chrono::DateTime::from_timestamp(a.value(r), 0)
                .unwrap_or(chrono::DateTime::UNIX_EPOCH);
              serde_json::Value::String(datetime.to_rfc3339())
            }
            DataType::Timestamp(TimeUnit::Millisecond, _) => {
              let a = col.as_any().downcast_ref::<TimestampMillisecondArray>().unwrap();
              let datetime = chrono::DateTime::from_timestamp_millis(a.value(r))
                .unwrap_or(chrono::DateTime::UNIX_EPOCH);
              serde_json::Value::String(datetime.to_rfc3339())
            }
            DataType::Timestamp(TimeUnit::Microsecond, _) => {
              let a = col.as_any().downcast_ref::<TimestampMicrosecondArray>().unwrap();
              let datetime = chrono::DateTime::from_timestamp_micros(a.value(r))
                .unwrap_or(chrono::DateTime::UNIX_EPOCH);
              serde_json::Value::String(datetime.to_rfc3339())
            }
            DataType::Timestamp(TimeUnit::Nanosecond, _) => {
              let a = col.as_any().downcast_ref::<TimestampNanosecondArray>().unwrap();
              let datetime = chrono::DateTime::from_timestamp_nanos(a.value(r));
              serde_json::Value::String(datetime.to_rfc3339())
            }
            DataType::Decimal128(_, scale) => {
              let a = col.as_any().downcast_ref::<Decimal128Array>().unwrap();
              let v = a.value(r) as f64 / 10_f64.powi(*scale as i32);
              serde_json::Value::from(v)
            }
            DataType::Decimal256(_, scale) => {
              let a = col.as_any().downcast_ref::<Decimal256Array>().unwrap();
              let s = format_decimal_string(&a.value(r).to_string(), *scale as i32);
              serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s))
            }
            _ => arrow_cast::display::array_value_to_string(col.as_ref(), r)
              .map(serde_json::Value::String)
              .unwrap_or(serde_json::Value::Null),
          }
        };
        obj.insert(field.name().clone(), v);
      }
      rows.push(serde_json::Value::Object(obj));
    }
  }
  serde_json::to_string(&rows).unwrap_or_else(|_| "[]".to_string())
}

/// Extract a human-readable message from a panic payload
fn extract_panic_message(panic_err: Box<dyn std::any::Any + Send>) -> String {
  if let Some(s) = panic_err.downcast_ref::<&str>() {
    s.to_string()
  } else if let Some(s) = panic_err.downcast_ref::<String>() {
    s.clone()
  } else {
    "Unknown panic".to_string()
  }
}

fn is_result_returning_query(sql: &str) -> bool {
  let trimmed = sql.trim_start();
  let upper = trimmed.to_uppercase();
  upper.starts_with("SELECT")
    || upper.starts_with("WITH")
    || upper.starts_with("SHOW")
    || upper.starts_with("DESCRIBE")
    || upper.starts_with("EXPLAIN")
    || upper.starts_with("TABLE")
    || upper.starts_with("VALUES")
    || upper.starts_with("FROM")
    || upper.starts_with("PRAGMA")
}

fn apply_database_to_session(session_id: u64, database: &str) {
  if database.is_empty() || database == "memory" {
    return;
  }
  let escaped = database.replace('"', "\"\"");
  let _ = trex_pool_client::session_execute(
    session_id,
    &format!("USE \"{escaped}\""),
  );
}

fn trex_type_to_string(t: &TrexType) -> String {
  match t {
    TrexType::Integer(v) => v.to_string(),
    TrexType::String(v) => v.clone(),
    TrexType::Number(v) => v.to_string(),
    TrexType::DateTime(v) => chrono::DateTime::from_timestamp_millis(*v)
      .unwrap_or(chrono::DateTime::UNIX_EPOCH)
      .format("%Y-%m-%d %H:%M:%S%.3f")
      .to_string(),
  }
}

fn execute_query(
  database: String,
  sql: String,
  params: Vec<TrexType>,
  worker_id: i32,
  session_id: u64,
) -> Result<String, TrexError> {
  // When a session is provided, route ALL queries through it (supports transactions).
  if session_id > 0 {
    apply_database_to_session(session_id, &database);
    let result = if params.is_empty() {
      trex_pool_client::session_execute(session_id, &sql)
    } else {
      let str_params: Vec<String> =
        params.iter().map(trex_type_to_string).collect();
      trex_pool_client::session_execute_params(session_id, &sql, &str_params)
    };
    return match result {
      Ok((_schema, batches)) => {
        if batches.is_empty() {
          Ok("[]".to_string())
        } else {
          Ok(pool_batches_to_json(&batches))
        }
      }
      Err(e) => Err(TrexError::Generic(e)),
    };
  }

  // Route write operations through a short-lived session.
  if !is_result_returning_query(&sql) {
    let sid = trex_pool_client::create_session()
      .map_err(TrexError::Generic)?;
    apply_database_to_session(sid, &database);
    let result = if params.is_empty() {
      trex_pool_client::session_execute(sid, &sql)
    } else {
      let str_params: Vec<String> =
        params.iter().map(trex_type_to_string).collect();
      trex_pool_client::session_execute_params(sid, &sql, &str_params)
    };
    let _ = trex_pool_client::destroy_session(sid);
    return match result {
      Ok(_) => Ok("[]".to_string()),
      Err(e) => Err(TrexError::Generic(e)),
    };
  }

  // Reads go through the local executor (supports params + database switching)
  if let Some(executor) = connection::get_query_executor() {
    let params_json = serde_json::to_string(&params)
      .map_err(|e| TrexError::Generic(format!("param serialize: {e}")))?;

    let rx = if worker_id >= 0 {
      executor.submit_to(worker_id as usize, database, sql, params_json)
    } else {
      executor.submit(database, sql, params_json)
    };

    match rx.recv() {
      Ok(query_executor::QueryResult::Success(json)) => Ok(json),
      Ok(query_executor::QueryResult::Error(msg)) => {
        Err(TrexError::Generic(msg))
      }
      Err(_) => Err(TrexError::Generic("executor channel closed".into())),
    }
  } else {
    execute_query_fallback(database, sql, params)
  }
}

fn execute_query_fallback(
  database: String,
  sql: String,
  params: Vec<TrexType>,
) -> Result<String, TrexError> {
  let result = panic::catch_unwind(AssertUnwindSafe(|| {
    execute_query_fallback_inner(database, sql, params)
  }));
  match result {
    Ok(inner) => inner,
    Err(panic_err) => {
      let msg = extract_panic_message(panic_err);
      Err(TrexError::Generic(format!("query panicked: {msg}")))
    }
  }
}

fn execute_query_fallback_inner(
  database: String,
  sql: String,
  params: Vec<TrexType>,
) -> Result<String, TrexError> {
  let conn_arc = get_active_connection();
  let conn = match conn_arc.lock() {
    Ok(g) => g,
    Err(poisoned) => {
      warn!("lock was poisoned, recovering");
      poisoned.into_inner()
    }
  };

  if let Err(e) = conn.execute(&format!("USE {database}"), []) {
    warn!(database, error = %e, "failed to switch database");
  }

  if sql.trim().is_empty() {
    return Ok("[]".to_string());
  }

  match conn.prepare(&sql) {
    Ok(mut stmt) => match stmt.query_arrow(params_from_iter(params.iter())) {
      Ok(iter) => Ok(record_batches_to_json(&iter.collect::<Vec<_>>())),
      Err(e) => Err(TrexError::Generic(format!("query exec: {e}"))),
    },
    Err(e) => {
      let mut msg = e.to_string();
      let mut source = (&e as &dyn StdError).source();
      while let Some(s) = source {
        msg = format!("{msg}: {s}");
        source = s.source();
      }
      Err(TrexError::Generic(msg))
    }
  }
}

#[op2]
#[string]
fn op_execute_query(
  #[string] database: String,
  #[string] sql: String,
  #[serde] params: Vec<TrexType>,
) -> Result<String, TrexError> {
  execute_query(database, sql, params, -1, 0)
}

#[op2(fast)]
#[smi]
fn op_acquire_worker() -> u32 {
  connection::get_query_executor()
    .map(|e| e.next_worker_id() as u32)
    .unwrap_or(0)
}

/// Persistent so connection-local state (temp tables, prepared statements)
/// survives across queries within one TrexConnection.
// Session ids are passed to/from JS as STRINGS, not numbers. Remote pool
// sessions are tagged with REMOTE_BIT (1<<63), so their u64 ids are ~2^63 —
// far beyond JS's safe-integer range (2^53). Marshalling them as JS numbers
// (f64) silently rounds e.g. REMOTE_BIT|1 down to 2^63 (= REMOTE_BIT|0), so the
// data node is asked for session 0 → "session 0 not found" on every server-only
// (non-data) node. Strings preserve the exact id.
#[op2]
#[string]
fn op_create_session() -> Result<String, TrexError> {
  trex_pool_client::create_session()
    .map(|id| id.to_string())
    .map_err(TrexError::Generic)
}

/// Destroy a pool session. Auto-rollback if a transaction is still active.
#[op2(fast)]
fn op_destroy_session(#[string] session_id: String) {
  if let Ok(id) = session_id.parse::<u64>() {
    let _ = trex_pool_client::destroy_session(id);
  }
}

/// Execute a query using a pool session for transaction isolation.
#[op2]
#[string]
fn op_execute_query_session(
  #[string] session_id: String,
  #[string] database: String,
  #[string] sql: String,
  #[serde] params: Vec<TrexType>,
) -> Result<String, TrexError> {
  let session_id = session_id.parse::<u64>().unwrap_or(0);
  execute_query(database, sql, params, -1, session_id)
}

#[op2]
#[string]
fn op_execute_query_pinned(
  #[smi] worker_id: u32,
  #[string] database: String,
  #[string] sql: String,
  #[serde] params: Vec<TrexType>,
) -> Result<String, TrexError> {
  execute_query(database, sql, params, worker_id as i32, 0)
}

pub struct QueryStreamResource {
  receiver: Arc<Mutex<mpsc::Receiver<String>>>,
}

impl Resource for QueryStreamResource {
  fn name(&self) -> std::borrow::Cow<str> {
    "QueryStreamResource".into()
  }
}

pub struct RequestResource {
  listener_id: u64,
  receiver: RefCell<Option<mpsc::Receiver<JsonValue>>>,
}

impl Resource for RequestResource {
  fn name(&self) -> std::borrow::Cow<str> {
    "RequestResource".into()
  }
}

impl Drop for RequestResource {
  fn drop(&mut self) {
    // Deregister this listener when its worker isolate is torn down.
    if let Ok(mut listeners) = REQUEST_LISTENERS.lock() {
      listeners.remove(&self.listener_id);
    }
  }
}

#[op2]
#[serde]
async fn op_req(#[serde] message: JsonValue) -> Result<JsonValue, TrexError> {
  send_request_inner(message).await
}

async fn send_request_inner(
  message: JsonValue,
) -> Result<JsonValue, TrexError> {
  let request_id = Uuid::new_v4().to_string();

  let (response_sender, response_receiver) = oneshot::channel::<JsonValue>();

  {
    let mut pending = PENDING_REQUESTS.lock().unwrap();
    pending.insert(request_id.clone(), response_sender);
  }

  let request_with_id = serde_json::json!({
    "id": request_id,
    "message": message
  });

  // Dispatch to the oldest live listener (the long-lived primary main worker),
  // failing over to newer ones and pruning closed senders.
  let delivered = {
    let mut listeners = REQUEST_LISTENERS.lock().unwrap();
    if listeners.is_empty() {
      PENDING_REQUESTS.lock().unwrap().remove(&request_id);
      return Err(TrexError::Generic("No active listeners".to_string()));
    }
    let mut ids: Vec<u64> = listeners.keys().copied().collect();
    ids.sort_unstable();
    let mut delivered = false;
    let mut dead: Vec<u64> = Vec::new();
    for id in &ids {
      if let Some(sender) = listeners.get(id) {
        match sender.try_send(request_with_id.clone()) {
          Ok(()) => {
            delivered = true;
            break;
          }
          Err(mpsc::error::TrySendError::Closed(_)) => dead.push(*id),
          Err(mpsc::error::TrySendError::Full(_)) => {}
        }
      }
    }
    for id in dead {
      listeners.remove(&id);
    }
    delivered
  };

  if !delivered {
    PENDING_REQUESTS.lock().unwrap().remove(&request_id);
    return Err(TrexError::Generic("Failed to send request".to_string()));
  }

  match tokio::time::timeout(
    std::time::Duration::from_secs(30),
    response_receiver,
  )
  .await
  {
    Ok(Ok(response)) => Ok(response),
    Ok(Err(_)) => {
      PENDING_REQUESTS.lock().unwrap().remove(&request_id);
      Err(TrexError::Generic("Request cancelled".to_string()))
    }
    Err(_) => {
      PENDING_REQUESTS.lock().unwrap().remove(&request_id);
      Err(TrexError::Generic("Request timeout".to_string()))
    }
  }
}

#[op2]
#[serde]
fn op_req_listen(state: &mut OpState) -> Result<ResourceId, TrexError> {
  let (sender, receiver) = mpsc::channel::<JsonValue>(1000);
  let listener_id = LISTENER_NEXT_ID.fetch_add(1, Ordering::Relaxed);

  {
    let mut listeners = REQUEST_LISTENERS.lock().unwrap();
    listeners.insert(listener_id, sender);
  }

  let resource = RequestResource {
    listener_id,
    receiver: RefCell::new(Some(receiver)),
  };
  Ok(state.resource_table.add(resource))
}

#[op2]
#[serde]
async fn op_req_next(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<Option<JsonValue>, TrexError> {
  let resource = state.borrow().resource_table.get::<RequestResource>(rid)?;

  let receiver = resource.receiver.borrow_mut().take();

  if let Some(mut rx) = receiver {
    let next_message = rx.recv().await;

    if next_message.is_none() {
      {
        let mut listeners = REQUEST_LISTENERS.lock().unwrap();
        listeners.remove(&resource.listener_id);
      }

      state
        .borrow_mut()
        .resource_table
        .take::<RequestResource>(rid)?;
    } else {
      resource.receiver.borrow_mut().replace(rx);
    }

    Ok(next_message)
  } else {
    Ok(None)
  }
}

#[op2]
#[serde]
fn op_req_respond(
  #[string] request_id: String,
  #[serde] response: JsonValue,
) -> Result<serde_json::Value, TrexError> {
  respond_to_request_inner(request_id, response)
}

fn respond_to_request_inner(
  request_id: String,
  response: JsonValue,
) -> Result<serde_json::Value, TrexError> {
  let mut pending = PENDING_REQUESTS.lock().unwrap();

  if let Some(sender) = pending.remove(&request_id) {
    match sender.send(response) {
      Ok(()) => Ok(serde_json::Value::Bool(true)),
      Err(_) => Ok(serde_json::Value::Bool(false)),
    }
  } else {
    Ok(serde_json::Value::Bool(false))
  }
}

fn stream_query_ref(
  conn: &Connection,
  database: &str,
  sql: &str,
  params: &[TrexType],
  sender: &mpsc::Sender<String>,
) {
  if conn.execute(&format!("USE {database}"), []).is_err() {
    return;
  }
  if let Ok(mut stmt) = conn.prepare(sql) {
    if let Ok(iter) = stmt.query_arrow(params_from_iter(params.iter())) {
      for batch in iter {
        let json = record_batches_to_json(std::slice::from_ref(&batch));
        if sender.blocking_send(json).is_err() {
          break;
        }
      }
    }
  }
}

#[op2]
#[serde]
fn op_execute_query_stream(
  state: &mut OpState,
  #[string] database: String,
  #[string] sql: String,
  #[serde] params: Vec<TrexType>,
) -> Result<ResourceId, TrexError> {
  let (sender, receiver) = mpsc::channel::<String>(1000);

  enum StreamConn {
    Pooled(Connection),
    Shared(Arc<Mutex<Connection>>),
  }

  let stream_conn = if let Some(pool) = connection::get_streaming_pool() {
    StreamConn::Pooled(pool.acquire().ok_or_else(|| {
      TrexError::Generic("no streaming connections available".into())
    })?)
  } else {
    StreamConn::Shared(get_active_connection())
  };

  let sender_for_panic = sender.clone();
  tokio::spawn(async move {
    tokio::task::spawn_blocking(move || match stream_conn {
      StreamConn::Pooled(conn) => {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
          stream_query_ref(&conn, &database, &sql, &params, &sender);
        }));
        match result {
          Ok(()) => {
            if let Some(pool) = connection::get_streaming_pool() {
              pool.release(conn);
            }
          }
          Err(e) => {
            let msg = extract_panic_message(e);
            warn!("Streaming query panicked, connection lost from pool: {msg}");
            let error_json = serde_json::json!({
              "error": format!("Query execution panicked: {}", msg)
            });
            let _ = sender_for_panic.blocking_send(error_json.to_string());
          }
        }
      }
      StreamConn::Shared(conn_arc) => {
        let guard = match conn_arc.lock() {
          Ok(g) => g,
          Err(poisoned) => {
            warn!("streaming fallback: lock was poisoned, recovering");
            poisoned.into_inner()
          }
        };
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
          stream_query_ref(&guard, &database, &sql, &params, &sender);
        }));
        if let Err(e) = result {
          let msg = extract_panic_message(e);
          warn!("Streaming query panicked: {msg}");
          let error_json = serde_json::json!({
            "error": format!("Query execution panicked: {}", msg)
          });
          let _ = sender_for_panic.blocking_send(error_json.to_string());
        }
      }
    });
  });
  let resource = QueryStreamResource {
    receiver: Arc::new(Mutex::new(receiver)),
  };
  Ok(state.resource_table.add(resource))
}

#[allow(clippy::await_holding_lock)]
#[op2]
#[string]
async fn op_execute_query_stream_next(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<Option<String>, TrexError> {
  let resource = state
    .borrow()
    .resource_table
    .get::<QueryStreamResource>(rid)?;

  let mut rx = match resource.receiver.lock() {
    Ok(guard) => guard,
    Err(poisoned) => {
      warn!("Lock was poisoned in stream_next, recovering");
      poisoned.into_inner()
    }
  };
  let next_chunk = rx.recv().await;

  if next_chunk.is_none() {
    state
      .borrow_mut()
      .resource_table
      .take::<QueryStreamResource>(rid)?;
  }
  Ok(next_chunk)
}

deno_core::extension!(
    trex,
    ops = [
        op_install_plugin,
        op_execute_query,
        op_acquire_worker,
        op_create_session,
        op_destroy_session,
        op_execute_query_session,
        op_execute_query_pinned,
        op_get_dbc,
        op_get_dbc2,
        op_set_dbc,
        op_sql_log_enabled,
        op_execute_query_stream,
        op_execute_query_stream_next,
        op_req,
        op_req_listen,
        op_req_next,
        op_req_respond,
        op_register_static_route
    ],
    // The trex JS surface is reached exclusively through
    // `ops.op_lazy_load_esm("ext:trex/trex_lib.js")` in the runtime's
    // namespaces.js -- nothing imports it eagerly. `op_lazy_load_esm`
    // resolves *only* from `lazy_loaded_esm` sources (just as
    // `core.loadExtScript` resolves only from `lazy_loaded_js`), so these
    // files must live in that bucket or the op throws "cannot be
    // lazy-loaded as it was not included in the binary" and the whole
    // `Trex` namespace silently collapses to `{}`.
    //
    // All four files go here, not just the entry point: `trex_lib.js`
    // statically imports the other three, and those imports are resolved by
    // `LazyEsmModuleLoader`, which likewise only sees `lazy_loaded_esm`
    // sources. (Same reason `ext/node` registers `internal_binding/mod.ts`
    // as `lazy_loaded_esm`.) That loader also has no `ext:`-relative
    // resolution, so the imports themselves use absolute `ext:trex/...`
    // specifiers -- see the note at the top of `js/trex_lib.js`.
    //
    // There is deliberately no `esm` / `esm_entry_point`: `trex_lib.js` has
    // no init-time side effects (it only declares exports), and an eager
    // `esm` file that no evaluated module imports fails snapshot validation
    // with `NonEvaluatedModules`.
    lazy_loaded_esm = [
        dir "js",
        "trex_lib.js",
        "dbconnection.js",
        "db_resolve.js",
        "hana_sql.js"
    ]
);

#[cfg(test)]
mod tests {
  use super::*;
  use duckdb::arrow::array::{
    BinaryArray, BooleanArray, Date32Array, Date64Array, Decimal128Array,
    Float32Array, Float64Array, Int16Array, Int32Array, Int64Array, Int8Array,
    LargeBinaryArray, LargeStringArray, StringArray, Time32SecondArray,
    Time64MicrosecondArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray,
    UInt16Array, UInt32Array, UInt64Array, UInt8Array,
  };
  use duckdb::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
  use duckdb::arrow::record_batch::RecordBatch;
  use serial_test::serial;
  use std::sync::Arc;

  fn reset_credentials() {
    *DB_CREDENTIALS.lock().unwrap() =
      String::from("{\"credentials\":[], \"publications\":{}}");
  }

  fn cleanup_request_state() {
    {
      let mut listeners = REQUEST_LISTENERS.lock().unwrap();
      listeners.clear();
    }
    {
      let mut pending = PENDING_REQUESTS.lock().unwrap();
      pending.clear();
    }
  }

  #[test]
  fn test_field_value_utf8() {
    let arr = StringArray::from(vec![Some("hello"), Some("")]);
    assert_eq!(
      field_value_to_json(&arr, 0, &DataType::Utf8),
      JsonValue::String("hello".into())
    );
    assert_eq!(
      field_value_to_json(&arr, 1, &DataType::Utf8),
      JsonValue::String("".into())
    );
  }

  #[test]
  fn test_field_value_large_utf8() {
    let arr = LargeStringArray::from(vec![Some("large")]);
    assert_eq!(
      field_value_to_json(&arr, 0, &DataType::LargeUtf8),
      JsonValue::String("large".into())
    );
  }

  #[test]
  fn test_field_value_binary() {
    let arr = BinaryArray::from(vec![Some(&[0xDE, 0xAD][..])]);
    let result = field_value_to_json(&arr, 0, &DataType::Binary);
    assert_eq!(
      result,
      JsonValue::String(general_purpose::STANDARD.encode([0xDE, 0xAD]))
    );
  }

  #[test]
  fn test_field_value_large_binary() {
    let arr = LargeBinaryArray::from(vec![Some(&[0xBE, 0xEF][..])]);
    let result = field_value_to_json(&arr, 0, &DataType::LargeBinary);
    assert_eq!(
      result,
      JsonValue::String(general_purpose::STANDARD.encode([0xBE, 0xEF]))
    );
  }

  #[test]
  fn test_field_value_null() {
    let arr = StringArray::from(vec![Option::<&str>::None]);
    assert_eq!(
      field_value_to_json(&arr, 0, &DataType::Utf8),
      JsonValue::Null
    );
  }

  #[test]
  fn test_field_value_integers() {
    let i8_arr = Int8Array::from(vec![42i8]);
    assert_eq!(
      field_value_to_json(&i8_arr, 0, &DataType::Int8),
      JsonValue::from(42i64)
    );

    let i16_arr = Int16Array::from(vec![1000i16]);
    assert_eq!(
      field_value_to_json(&i16_arr, 0, &DataType::Int16),
      JsonValue::from(1000i64)
    );

    let i32_arr = Int32Array::from(vec![100_000i32]);
    assert_eq!(
      field_value_to_json(&i32_arr, 0, &DataType::Int32),
      JsonValue::from(100_000i64)
    );

    let i64_arr = Int64Array::from(vec![9_000_000_000i64]);
    assert_eq!(
      field_value_to_json(&i64_arr, 0, &DataType::Int64),
      JsonValue::from(9_000_000_000i64)
    );
  }

  #[test]
  fn test_field_value_unsigned_integers() {
    let u8_arr = UInt8Array::from(vec![255u8]);
    assert_eq!(
      field_value_to_json(&u8_arr, 0, &DataType::UInt8),
      JsonValue::from(255u64)
    );

    let u16_arr = UInt16Array::from(vec![65535u16]);
    assert_eq!(
      field_value_to_json(&u16_arr, 0, &DataType::UInt16),
      JsonValue::from(65535u64)
    );

    let u32_arr = UInt32Array::from(vec![4_000_000_000u32]);
    assert_eq!(
      field_value_to_json(&u32_arr, 0, &DataType::UInt32),
      JsonValue::from(4_000_000_000u64)
    );

    let u64_arr = UInt64Array::from(vec![u64::MAX]);
    assert_eq!(
      field_value_to_json(&u64_arr, 0, &DataType::UInt64),
      JsonValue::from(u64::MAX)
    );
  }

  #[test]
  fn test_field_value_floats() {
    let f32_arr = Float32Array::from(vec![1.23f32]);
    let result = field_value_to_json(&f32_arr, 0, &DataType::Float32);
    let val = result.as_f64().unwrap();
    assert!((val - 1.23).abs() < 0.001);

    let f64_arr = Float64Array::from(vec![9.876_543_21f64]);
    assert_eq!(
      field_value_to_json(&f64_arr, 0, &DataType::Float64),
      JsonValue::from(9.876_543_21f64)
    );
  }

  #[test]
  fn test_field_value_boolean() {
    let arr = BooleanArray::from(vec![Some(true), Some(false)]);
    assert_eq!(
      field_value_to_json(&arr, 0, &DataType::Boolean),
      JsonValue::from(true)
    );
    assert_eq!(
      field_value_to_json(&arr, 1, &DataType::Boolean),
      JsonValue::from(false)
    );
  }

  #[test]
  fn test_field_value_date32() {
    let arr = Date32Array::from(vec![19723]);
    let result = field_value_to_json(&arr, 0, &DataType::Date32);
    assert_eq!(result, JsonValue::String("2024-01-01".into()));
  }

  #[test]
  fn test_field_value_date64() {
    let arr = Date64Array::from(vec![1703980800000i64]);
    let result = field_value_to_json(&arr, 0, &DataType::Date64);
    assert_eq!(result, JsonValue::String("2023-12-31".into()));
  }

  #[test]
  fn test_field_value_time32() {
    let arr = Time32SecondArray::from(vec![3661]);
    let result =
      field_value_to_json(&arr, 0, &DataType::Time32(TimeUnit::Second));
    assert_eq!(result, JsonValue::from(3661));
  }

  #[test]
  fn test_field_value_time64() {
    let arr = Time64MicrosecondArray::from(vec![1_000_000i64]);
    let result =
      field_value_to_json(&arr, 0, &DataType::Time64(TimeUnit::Microsecond));
    assert_eq!(result, JsonValue::from(1_000_000i64));
  }

  #[test]
  fn test_field_value_timestamp_second() {
    let arr = TimestampSecondArray::from(vec![1704067200i64]);
    let result = field_value_to_json(
      &arr,
      0,
      &DataType::Timestamp(TimeUnit::Second, None),
    );
    let s = result.as_str().unwrap();
    assert!(s.starts_with("2024-01-01T00:00:00"));
  }

  #[test]
  fn test_field_value_timestamp_millisecond() {
    let arr = TimestampMillisecondArray::from(vec![1704067200000i64]);
    let result = field_value_to_json(
      &arr,
      0,
      &DataType::Timestamp(TimeUnit::Millisecond, None),
    );
    let s = result.as_str().unwrap();
    assert!(s.starts_with("2024-01-01T00:00:00"));
  }

  #[test]
  fn test_field_value_timestamp_microsecond() {
    let arr = TimestampMicrosecondArray::from(vec![1_704_067_200_000_000i64]);
    let result = field_value_to_json(
      &arr,
      0,
      &DataType::Timestamp(TimeUnit::Microsecond, None),
    );
    let s = result.as_str().unwrap();
    assert!(s.starts_with("2024-01-01T00:00:00"));
  }

  #[test]
  fn test_field_value_timestamp_nanosecond() {
    let arr =
      TimestampNanosecondArray::from(vec![1_704_067_200_000_000_000i64]);
    let result = field_value_to_json(
      &arr,
      0,
      &DataType::Timestamp(TimeUnit::Nanosecond, None),
    );
    let s = result.as_str().unwrap();
    assert!(s.starts_with("2024-01-01T00:00:00"));
  }

  #[test]
  fn test_field_value_decimal128() {
    let arr = Decimal128Array::from(vec![12345i128])
      .with_precision_and_scale(10, 2)
      .unwrap();
    let result = field_value_to_json(&arr, 0, &DataType::Decimal128(10, 2));
    assert_eq!(result, JsonValue::from(123.45));
  }

  #[test]
  fn test_format_decimal_string_basic() {
    assert_eq!(format_decimal_string("12345", 2), "123.45");
    assert_eq!(format_decimal_string("12345", 0), "12345");
    assert_eq!(format_decimal_string("-12345", 2), "-123.45");
    assert_eq!(format_decimal_string("5", 3), "0.005");
    assert_eq!(format_decimal_string("-5", 3), "-0.005");
  }

  #[test]
  fn test_format_decimal_string_negative_scale() {
    // Negative scale = multiply by 10^|scale|
    assert_eq!(format_decimal_string("123", -2), "12300");
    assert_eq!(format_decimal_string("-7", -1), "-70");
  }

  #[test]
  fn test_format_decimal_string_zero_padding() {
    assert_eq!(format_decimal_string("1", 4), "0.0001");
    assert_eq!(format_decimal_string("100", 5), "0.00100");
  }

  #[test]
  fn test_format_decimal_string_high_precision() {
    // i256-range: would lose precision via f64. String path preserves it.
    let huge = "12345678901234567890123456789012345678";
    assert_eq!(
      format_decimal_string(huge, 10),
      "12345678901234567890123456789.0123456789"
    );
  }

  #[test]
  fn test_field_value_null_type() {
    let arr = duckdb::arrow::array::NullArray::new(1);
    let result = field_value_to_json(&arr, 0, &DataType::Null);
    assert_eq!(result, JsonValue::Null);
  }

  #[test]
  fn test_field_value_list_fallback() {
    use duckdb::arrow::array::{Int32Builder, ListBuilder};
    let mut builder = ListBuilder::new(Int32Builder::new());
    builder.values().append_value(1);
    builder.values().append_value(2);
    builder.values().append_value(3);
    builder.append(true);
    let arr = builder.finish();
    let result = field_value_to_json(&arr, 0, arr.data_type());
    let s = result.as_str().expect("list should fall back to string");
    assert!(s.contains('1') && s.contains('2') && s.contains('3'));
  }

  #[test]
  fn test_field_value_struct_fallback() {
    use duckdb::arrow::array::StructArray;
    let arr = StructArray::from(vec![
      (
        Arc::new(Field::new("x", DataType::Int32, false)),
        Arc::new(Int32Array::from(vec![1])) as duckdb::arrow::array::ArrayRef,
      ),
      (
        Arc::new(Field::new("y", DataType::Utf8, false)),
        Arc::new(StringArray::from(vec!["foo"]))
          as duckdb::arrow::array::ArrayRef,
      ),
    ]);
    let result = field_value_to_json(&arr, 0, arr.data_type());
    let s = result.as_str().expect("struct should fall back to string");
    assert!(s.contains("foo"));
  }

  #[test]
  fn test_field_value_fixed_size_binary_fallback() {
    use duckdb::arrow::array::FixedSizeBinaryArray;
    let arr =
      FixedSizeBinaryArray::try_from_iter(vec![vec![0xDE, 0xAD]].into_iter())
        .unwrap();
    let result = field_value_to_json(&arr, 0, arr.data_type());
    assert!(result.is_string());
  }

  #[test]
  fn test_record_batches_to_json_empty() {
    let result = record_batches_to_json(&[]);
    assert_eq!(result, "[]");
  }

  #[test]
  fn test_record_batches_to_json_single_row() {
    let schema = Arc::new(Schema::new(vec![
      Field::new("name", DataType::Utf8, false),
      Field::new("age", DataType::Int32, false),
    ]));
    let batch = RecordBatch::try_new(
      schema,
      vec![
        Arc::new(StringArray::from(vec!["Alice"])),
        Arc::new(Int32Array::from(vec![30])),
      ],
    )
    .unwrap();
    let result = record_batches_to_json(&[batch]);
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["name"], "Alice");
    assert_eq!(parsed[0]["age"], 30);
  }

  #[test]
  fn test_record_batches_to_json_multiple_rows() {
    let schema =
      Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]));
    let batch = RecordBatch::try_new(
      schema,
      vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
    )
    .unwrap();
    let result = record_batches_to_json(&[batch]);
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed[0]["id"], 1);
    assert_eq!(parsed[1]["id"], 2);
    assert_eq!(parsed[2]["id"], 3);
  }

  #[test]
  fn test_record_batches_to_json_multiple_batches() {
    let schema =
      Arc::new(Schema::new(vec![Field::new("v", DataType::Int32, false)]));
    let batch1 = RecordBatch::try_new(
      schema.clone(),
      vec![Arc::new(Int32Array::from(vec![10]))],
    )
    .unwrap();
    let batch2 =
      RecordBatch::try_new(schema, vec![Arc::new(Int32Array::from(vec![20]))])
        .unwrap();
    let result = record_batches_to_json(&[batch1, batch2]);
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0]["v"], 10);
    assert_eq!(parsed[1]["v"], 20);
  }

  // -------- pool_batches_to_json (session-execute path) --------

  fn pool_rb_one_col(
    name: &str,
    dt: DataType,
    nullable: bool,
    arr: duckdb::arrow::array::ArrayRef,
  ) -> RecordBatch {
    let schema = Arc::new(Schema::new(vec![Field::new(name, dt, nullable)]));
    RecordBatch::try_new(schema, vec![arr]).unwrap()
  }

  #[test]
  fn test_pool_batches_to_json_date32() {
    // Regression: previously the session-execute path silently emitted null
    // for every Date32 column.
    let arr = Arc::new(Date32Array::from(vec![19723]));
    let rb = pool_rb_one_col("d", DataType::Date32, false, arr);
    let json = pool_batches_to_json(std::slice::from_ref(&rb));
    let parsed: Vec<JsonValue> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["d"], JsonValue::String("2024-01-01".into()));
  }

  #[test]
  fn test_pool_batches_to_json_timestamp_microsecond() {
    let arr = Arc::new(TimestampMicrosecondArray::from(vec![
      1_704_067_200_000_000i64,
    ]));
    let rb = pool_rb_one_col(
      "t",
      DataType::Timestamp(TimeUnit::Microsecond, None),
      false,
      arr,
    );
    let json = pool_batches_to_json(std::slice::from_ref(&rb));
    let parsed: Vec<JsonValue> = serde_json::from_str(&json).unwrap();
    let s = parsed[0]["t"].as_str().unwrap();
    assert!(s.starts_with("2024-01-01T00:00:00"));
  }

  #[test]
  fn test_pool_batches_to_json_int_widths() {
    let schema = Arc::new(Schema::new(vec![
      Field::new("i8", DataType::Int8, false),
      Field::new("i16", DataType::Int16, false),
      Field::new("u32", DataType::UInt32, false),
      Field::new("f32", DataType::Float32, false),
    ]));
    let rb = RecordBatch::try_new(
      schema,
      vec![
        Arc::new(Int8Array::from(vec![-1])),
        Arc::new(Int16Array::from(vec![300])),
        Arc::new(UInt32Array::from(vec![100_000u32])),
        Arc::new(Float32Array::from(vec![1.5f32])),
      ],
    )
    .unwrap();
    let json = pool_batches_to_json(std::slice::from_ref(&rb));
    let parsed: Vec<JsonValue> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["i8"], -1);
    assert_eq!(parsed[0]["i16"], 300);
    assert_eq!(parsed[0]["u32"], 100_000);
    assert_eq!(parsed[0]["f32"], 1.5);
  }

  #[test]
  fn test_pool_batches_to_json_binary() {
    let arr = Arc::new(BinaryArray::from_vec(vec![b"\xDE\xAD".as_ref()]));
    let rb = pool_rb_one_col("b", DataType::Binary, false, arr);
    let json = pool_batches_to_json(std::slice::from_ref(&rb));
    let parsed: Vec<JsonValue> = serde_json::from_str(&json).unwrap();
    // base64("\xDE\xAD") = "3q0="
    assert_eq!(parsed[0]["b"], JsonValue::String("3q0=".into()));
  }

  #[test]
  fn test_pool_batches_to_json_null_value() {
    let schema =
      Arc::new(Schema::new(vec![Field::new("d", DataType::Date32, true)]));
    let rb = RecordBatch::try_new(
      schema,
      vec![Arc::new(Date32Array::from(vec![None, Some(19723)]))],
    )
    .unwrap();
    let json = pool_batches_to_json(std::slice::from_ref(&rb));
    let parsed: Vec<JsonValue> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed[0]["d"], JsonValue::Null);
    assert_eq!(parsed[1]["d"], JsonValue::String("2024-01-01".into()));
  }

  #[test]
  fn test_pool_batches_to_json_list_fallback() {
    use duckdb::arrow::array::{Int32Builder, ListBuilder};
    let mut builder = ListBuilder::new(Int32Builder::new());
    builder.values().append_value(7);
    builder.values().append_value(8);
    builder.append(true);
    let arr = builder.finish();
    let dt = arr.data_type().clone();
    let rb = pool_rb_one_col("l", dt, false, Arc::new(arr));
    let json = pool_batches_to_json(std::slice::from_ref(&rb));
    let parsed: Vec<JsonValue> = serde_json::from_str(&json).unwrap();
    let s = parsed[0]["l"].as_str().expect("list -> string fallback");
    assert!(s.contains('7') && s.contains('8'));
  }

  #[test]
  fn test_record_batches_to_json_mixed_nulls() {
    let schema = Arc::new(Schema::new(vec![
      Field::new("a", DataType::Utf8, true),
      Field::new("b", DataType::Int32, true),
    ]));
    let batch = RecordBatch::try_new(
      schema,
      vec![
        Arc::new(StringArray::from(vec![Some("x"), None])),
        Arc::new(Int32Array::from(vec![None, Some(5)])),
      ],
    )
    .unwrap();
    let result = record_batches_to_json(&[batch]);
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0]["a"], "x");
    assert!(parsed[0]["b"].is_null());
    assert!(parsed[1]["a"].is_null());
    assert_eq!(parsed[1]["b"], 5);
  }

  #[test]
  fn test_extract_panic_message_str() {
    let payload: Box<dyn std::any::Any + Send> = Box::new("boom");
    assert_eq!(extract_panic_message(payload), "boom");
  }

  #[test]
  fn test_extract_panic_message_string() {
    let payload: Box<dyn std::any::Any + Send> =
      Box::new(String::from("kaboom"));
    assert_eq!(extract_panic_message(payload), "kaboom");
  }

  #[test]
  fn test_extract_panic_message_unknown() {
    let payload: Box<dyn std::any::Any + Send> = Box::new(42i32);
    assert_eq!(extract_panic_message(payload), "Unknown panic");
  }

  #[test]
  fn test_trex_type_integer_to_sql() {
    let t = TrexType::Integer(42);
    let out = t.to_sql().unwrap();
    match out {
      ToSqlOutput::Owned(Value::BigInt(v)) => assert_eq!(v, 42),
      ToSqlOutput::Owned(Value::Int(v)) => assert_eq!(v, 42),
      other => panic!("unexpected output: {:?}", other),
    }
  }

  #[test]
  fn test_trex_type_string_to_sql() {
    let t = TrexType::String("hello".into());
    let out = t.to_sql().unwrap();
    match out {
      ToSqlOutput::Owned(Value::Text(s)) => assert_eq!(s, "hello"),
      other => panic!("unexpected output: {:?}", other),
    }
  }

  #[test]
  fn test_trex_type_number_to_sql() {
    let t = TrexType::Number(1.23);
    let out = t.to_sql().unwrap();
    match out {
      ToSqlOutput::Owned(Value::Double(v)) => {
        assert!((v - 1.23).abs() < f64::EPSILON)
      }
      other => panic!("unexpected output: {:?}", other),
    }
  }

  #[test]
  fn test_trex_type_datetime_to_sql() {
    let t = TrexType::DateTime(1704067200000);
    let out = t.to_sql().unwrap();
    match out {
      ToSqlOutput::Owned(Value::Timestamp(
        duckdb::types::TimeUnit::Millisecond,
        v,
      )) => assert_eq!(v, 1704067200000),
      other => panic!("unexpected output: {:?}", other),
    }
  }

  #[test]
  fn test_trex_type_serde_roundtrip() {
    let values = vec![
      TrexType::Integer(42),
      TrexType::String("test".into()),
      TrexType::Number(2.5),
      TrexType::DateTime(1000),
    ];
    let json = serde_json::to_string(&values).unwrap();
    let back: Vec<TrexType> = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 4);
    let json2 = serde_json::to_string(&back).unwrap();
    assert_eq!(json, json2);
  }

  #[test]
  #[serial]
  fn test_execute_query_simple_select() {
    let result =
      execute_query("memory".into(), "SELECT 1 AS val".into(), vec![], -1, 0);
    let json_str = result.unwrap();
    let parsed: Vec<JsonValue> = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["val"], 1);
  }

  #[test]
  #[serial]
  fn test_execute_query_empty_sql() {
    let result = execute_query("memory".into(), "".into(), vec![], -1, 0);
    assert_eq!(result.unwrap(), "[]");
  }

  #[test]
  #[serial]
  fn test_execute_query_create_and_select() {
    let _ = execute_query(
      "memory".into(),
      "CREATE TABLE IF NOT EXISTS test_cq_tbl (id INTEGER, name VARCHAR)"
        .into(),
      vec![],
      -1,
      0,
    );
    let _ = execute_query(
      "memory".into(),
      "INSERT INTO test_cq_tbl VALUES (1, 'Alice'), (2, 'Bob')".into(),
      vec![],
      -1,
      0,
    );
    let result = execute_query(
      "memory".into(),
      "SELECT * FROM test_cq_tbl ORDER BY id".into(),
      vec![],
      -1,
    )
    .unwrap();
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0]["name"], "Alice");
    assert_eq!(parsed[1]["name"], "Bob");
    let _ = execute_query(
      "memory".into(),
      "DROP TABLE IF EXISTS test_cq_tbl".into(),
      vec![],
      -1,
      0,
    );
  }

  #[test]
  #[serial]
  fn test_execute_query_with_params() {
    let result = execute_query(
      "memory".into(),
      "SELECT $1::INTEGER AS a, $2::VARCHAR AS b, $3::DOUBLE AS c".into(),
      vec![
        TrexType::Integer(42),
        TrexType::String("hi".into()),
        TrexType::Number(1.23),
      ],
      -1,
    )
    .unwrap();
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed[0]["a"], 42);
    assert_eq!(parsed[0]["b"], "hi");
    let c = parsed[0]["c"].as_f64().unwrap();
    assert!((c - 1.23).abs() < 0.001);
  }

  #[test]
  #[serial]
  fn test_execute_query_with_datetime_param() {
    let result = execute_query(
      "memory".into(),
      "SELECT $1::TIMESTAMP AS ts".into(),
      vec![TrexType::DateTime(1704067200000)],
      -1,
    )
    .unwrap();
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    let ts = parsed[0]["ts"].as_str().unwrap();
    assert!(ts.contains("2024-01-01"));
  }

  #[test]
  #[serial]
  fn test_execute_query_invalid_sql() {
    let result =
      execute_query("memory".into(), "NOT VALID SQL".into(), vec![], -1, 0);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(!err_msg.is_empty());
  }

  #[test]
  #[serial]
  fn test_execute_query_multiple_rows() {
    let result = execute_query(
      "memory".into(),
      "SELECT * FROM generate_series(1, 5) AS t(n)".into(),
      vec![],
      -1,
    )
    .unwrap();
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 5);
  }

  #[test]
  #[serial]
  fn test_execute_query_various_types() {
    let _ = execute_query(
      "memory".into(),
      "CREATE TABLE IF NOT EXISTS test_types (
        i INTEGER, v VARCHAR, d DOUBLE, b BOOLEAN, dt DATE, ts TIMESTAMP
      )"
      .into(),
      vec![],
      -1,
      0,
    );
    let _ = execute_query(
      "memory".into(),
      "INSERT INTO test_types VALUES (1, 'hello', 1.5, true, '2024-01-01', '2024-01-01 12:00:00')"
        .into(),
      vec![],
      -1,
      0,
    );
    let result = execute_query(
      "memory".into(),
      "SELECT * FROM test_types".into(),
      vec![],
      -1,
    )
    .unwrap();
    let parsed: Vec<JsonValue> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0]["i"], 1);
    assert_eq!(parsed[0]["v"], "hello");
    assert_eq!(parsed[0]["b"], true);
    assert!(parsed[0]["dt"].as_str().unwrap().contains("2024-01-01"));
    let _ = execute_query(
      "memory".into(),
      "DROP TABLE IF EXISTS test_types".into(),
      vec![],
      -1,
      0,
    );
  }

  fn get_dbc() -> String {
    get_dbc_inner()
  }

  fn set_dbc(dbc: String) {
    set_dbc_inner(dbc);
  }

  fn get_dbc2() -> String {
    get_dbc2_inner()
  }

  async fn send_request(message: JsonValue) -> Result<JsonValue, TrexError> {
    send_request_inner(message).await
  }

  fn respond_to_request(
    request_id: String,
    response: JsonValue,
  ) -> Result<serde_json::Value, TrexError> {
    respond_to_request_inner(request_id, response)
  }

  #[test]
  #[serial]
  fn test_get_dbc_default() {
    reset_credentials();
    let result = get_dbc();
    let parsed: JsonValue = serde_json::from_str(&result).unwrap();
    assert!(parsed["credentials"].as_array().unwrap().is_empty());
  }

  #[test]
  #[serial]
  fn test_set_and_get_dbc() {
    let creds = r#"{"credentials":[{"id":"TEST"}], "publications":{}}"#;
    set_dbc(creds.into());
    let result = get_dbc();
    assert_eq!(result, creds);
    reset_credentials();
  }

  #[test]
  #[serial]
  fn test_get_dbc2_no_env_vars() {
    reset_credentials();
    env::remove_var("TREX__SQL__HOST");
    env::remove_var("TREX__SQL__PORT");
    env::remove_var("TREX__SQL__USER");
    env::remove_var("TREX__SQL__PASSWORD");
    env::remove_var("TREX__SQL__DBNAME");
    env::remove_var("PG__HOST");
    env::remove_var("PG__FHIR_DB_NAME");
    env::remove_var("PG_USER");
    env::remove_var("PG_PASSWORD");
    env::remove_var("PG__PORT");

    let result = get_dbc2();
    let parsed: JsonValue = serde_json::from_str(&result).unwrap();
    assert!(parsed["credentials"].as_array().unwrap().is_empty());
  }

  #[test]
  #[serial]
  fn test_get_dbc2_with_trex_sql_env() {
    reset_credentials();
    env::set_var("TREX__SQL__HOST", "localhost");
    env::set_var("TREX__SQL__PORT", "5432");
    env::set_var("TREX__SQL__USER", "user1");
    env::set_var("TREX__SQL__PASSWORD", "pass1");
    env::set_var("TREX__SQL__DBNAME", "testdb");

    let result = get_dbc2();
    let parsed: JsonValue = serde_json::from_str(&result).unwrap();
    let creds = parsed["credentials"].as_array().unwrap();
    assert!(creds.iter().any(|c| c["id"] == "RESULT"));
    let result_entry = creds.iter().find(|c| c["id"] == "RESULT").unwrap();
    assert_eq!(result_entry["host"], "localhost");
    assert_eq!(result_entry["name"], "testdb");

    env::remove_var("TREX__SQL__HOST");
    env::remove_var("TREX__SQL__PORT");
    env::remove_var("TREX__SQL__USER");
    env::remove_var("TREX__SQL__PASSWORD");
    env::remove_var("TREX__SQL__DBNAME");
    reset_credentials();
  }

  #[test]
  #[serial]
  fn test_get_dbc2_with_pg_env() {
    reset_credentials();
    env::remove_var("TREX__SQL__HOST");
    env::remove_var("TREX__SQL__PORT");
    env::remove_var("TREX__SQL__USER");
    env::remove_var("TREX__SQL__PASSWORD");
    env::remove_var("TREX__SQL__DBNAME");

    env::set_var("PG__HOST", "pghost");
    env::set_var("PG__FHIR_DB_NAME", "fhirdb");
    env::set_var("PG_USER", "pguser");
    env::set_var("PG_PASSWORD", "pgpass");

    let result = get_dbc2();
    let parsed: JsonValue = serde_json::from_str(&result).unwrap();
    let creds = parsed["credentials"].as_array().unwrap();
    assert!(creds.iter().any(|c| c["id"] == "FHIR"));
    let fhir_entry = creds.iter().find(|c| c["id"] == "FHIR").unwrap();
    assert_eq!(fhir_entry["host"], "pghost");
    assert_eq!(fhir_entry["name"], "fhirdb");

    env::remove_var("PG__HOST");
    env::remove_var("PG__FHIR_DB_NAME");
    env::remove_var("PG_USER");
    env::remove_var("PG_PASSWORD");
    env::remove_var("PG__PORT");
    reset_credentials();
  }

  #[test]
  #[serial]
  fn test_get_dbc2_no_duplicate_entries() {
    let creds =
      r#"{"credentials":[{"id":"RESULT","code":"RESULT"}], "publications":{}}"#;
    set_dbc(creds.into());

    env::set_var("TREX__SQL__HOST", "localhost");
    env::set_var("TREX__SQL__PORT", "5432");
    env::set_var("TREX__SQL__USER", "user1");
    env::set_var("TREX__SQL__PASSWORD", "pass1");
    env::set_var("TREX__SQL__DBNAME", "testdb");

    let result = get_dbc2();
    let parsed: JsonValue = serde_json::from_str(&result).unwrap();
    let creds = parsed["credentials"].as_array().unwrap();
    let result_count = creds.iter().filter(|c| c["id"] == "RESULT").count();
    assert_eq!(result_count, 1, "RESULT entry should not be duplicated");

    env::remove_var("TREX__SQL__HOST");
    env::remove_var("TREX__SQL__PORT");
    env::remove_var("TREX__SQL__USER");
    env::remove_var("TREX__SQL__PASSWORD");
    env::remove_var("TREX__SQL__DBNAME");
    reset_credentials();
  }

  #[tokio::test]
  #[serial]
  async fn test_request_respond_roundtrip() {
    cleanup_request_state();

    let (tx, mut rx) = mpsc::channel::<JsonValue>(100);
    {
      let mut listeners = REQUEST_LISTENERS.lock().unwrap();
      listeners.insert(1, tx);
    }

    let response_handle = tokio::spawn(async move {
      if let Some(msg) = rx.recv().await {
        let id = msg["id"].as_str().unwrap().to_string();
        let response = serde_json::json!({"status": "ok"});
        let result = respond_to_request(id, response);
        assert!(result.is_ok());
      }
    });

    let result = send_request(serde_json::json!({"action": "test"})).await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["status"], "ok");

    response_handle.await.unwrap();
    cleanup_request_state();
  }

  #[tokio::test]
  #[serial]
  async fn test_request_no_listener() {
    cleanup_request_state();

    let result = send_request(serde_json::json!({"action": "test"})).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("No active listeners"));

    cleanup_request_state();
  }

  #[test]
  #[serial]
  fn test_request_respond_unknown_id() {
    cleanup_request_state();

    let result =
      respond_to_request("nonexistent-id".into(), serde_json::json!({}));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), serde_json::Value::Bool(false));

    cleanup_request_state();
  }

  #[tokio::test]
  #[serial]
  async fn test_request_cleanup_on_dropped_sender() {
    cleanup_request_state();

    let (tx, mut rx) = mpsc::channel::<JsonValue>(100);
    {
      let mut listeners = REQUEST_LISTENERS.lock().unwrap();
      listeners.insert(1, tx);
    }

    let handle = tokio::spawn(async move {
      let msg = rx.recv().await;
      assert!(msg.is_some());
      let id = msg.unwrap()["id"].as_str().unwrap().to_string();
      let sender = {
        let mut pending = PENDING_REQUESTS.lock().unwrap();
        pending.remove(&id)
      };
      drop(sender);
    });

    let result = send_request(serde_json::json!({"action": "test"})).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("cancelled"));

    handle.await.unwrap();
    cleanup_request_state();
  }
}
