//! Regression guard for the `ext:trex` JS registration.
//!
//! `namespaces.js` in the runtime reaches the whole trex JS surface through
//! `ops.op_lazy_load_esm("ext:trex/trex_lib.js")`, and that op resolves only
//! from the extension's `lazy_loaded_esm` bucket. While the files were
//! registered as eager `esm` the op threw, the caller's bare `catch`
//! swallowed the error, and `globalThis.Trex` silently lost every trex
//! member (`tokioChannel`, `httpClient`, `req`, `databaseManager`, ...).
//!
//! This lives in `tests/` rather than the `#[cfg(test)]` module in `lib.rs`
//! so it builds against the library alone (the inline `mod tests` does not
//! currently compile).
//!
//! It is not part of any CI job, because `trex_core` cannot be tested where it
//! sits: `ext/trex` is a bare path dependency of the `trexas` package rather
//! than a workspace member, and cargo refuses to test a non-member that has
//! dev-dependencies. To run it locally, from `plugins/runtime` (which carries
//! the `[patch.crates-io]` table the resolve depends on):
//!
//! 1. Temporarily add to `plugins/runtime/Cargo.toml`, above `[package]`:
//!    `[workspace]` / `members = ["ext/trex"]` / `exclude = ["trex-runtime"]`
//! 2. `cargo test -p trex_core --test lazy_esm`
//! 3. Revert `Cargo.toml` and `Cargo.lock`.
//!
//! Linking a test binary also needs `libtrexsql`, which is only present in the
//! docker image. Off-image, a stub archive defining the referenced
//! `duckdb_*` symbols (none are called here) satisfies the linker via
//! `RUSTFLAGS="-L native=<dir>"`.

/// Loading the entry point also proves its three static imports
/// (`ext:trex/dbconnection.js`, `ext:trex/db_resolve.js`,
/// `ext:trex/hana_sql.js`) resolve from the same bucket -- an unresolvable
/// import would fail instantiation -- and each dependency is loaded directly
/// as well, which additionally exercises the `trex_lib.js` <->
/// `dbconnection.js` import cycle.
#[test]
fn lazy_load_esm_resolves_the_trex_module_graph() {
  let tokio_runtime = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();
  let _guard = tokio_runtime.enter();

  let mut js_runtime = deno_core::JsRuntime::new(deno_core::RuntimeOptions {
    extensions: vec![trex_core::trex::init()],
    ..Default::default()
  });

  js_runtime
    .execute_script(
      "[trex:lazy_esm]",
      r#"
      const lib = Deno.core.ops.op_lazy_load_esm("ext:trex/trex_lib.js");
      for (const name of [
        "req",
        "reqRespond",
        "createRequestListener",
        "registerStaticRoute",
        "executeQueryStream",
        "TrexHttpClient",
        "DatabaseManager",
        "UserDatabaseManager",
        "TrexDB",
        "HanaDB",
        "PluginManager",
      ]) {
        if (typeof lib[name] !== "function") {
          throw new Error(`trex_lib.js is missing export ${name}`);
        }
      }

      const conn = Deno.core.ops.op_lazy_load_esm("ext:trex/dbconnection.js");
      if (typeof conn.TrexConnection !== "function") {
        throw new Error("dbconnection.js is missing export TrexConnection");
      }
      const resolve = Deno.core.ops.op_lazy_load_esm("ext:trex/db_resolve.js");
      if (typeof resolve.resolveDialect !== "function") {
        throw new Error("db_resolve.js is missing export resolveDialect");
      }
      const hana = Deno.core.ops.op_lazy_load_esm("ext:trex/hana_sql.js");
      if (typeof hana.buildHanaScanSql !== "function") {
        throw new Error("hana_sql.js is missing export buildHanaScanSql");
      }
      "#,
    )
    .expect("op_lazy_load_esm should resolve ext:trex/trex_lib.js");
}
