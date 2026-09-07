// Imports use absolute `ext:trex/...` specifiers, not relative paths.
// These modules are registered as `lazy_loaded_esm` and are resolved by
// deno_core's `LazyEsmModuleLoader`, which calls `resolve_import` directly.
// Unlike the eager `ExtModuleLoader`, it has no special handling for `ext:`
// referrers, and `ext:trex/trex_lib.js` is a cannot-be-a-base URL, so a
// relative specifier fails with "relative URL with a cannot-be-a-base base".
// Same convention as `ext/node`'s polyfills, which are lazily loaded too.
import { executeQueryStream, sqlLoggingEnabled, redactSecrets } from "ext:trex/trex_lib.js";

const NOVALUE = "NoValue"

function flattenParameter(parameters) {
    try {
    const flatList = [];
    if (parameters) {
        parameters.forEach((p) => {
            flatList.push(p.value === undefined ? null : p.value);
        });
    }
    return flatList;

    } catch(e) {
        console.log("Error in flattenParameter")
        console.log(e)
    }
}

export class TrexConnection  {

    connection;
    writeConn;
    schema;
    vocabSchemaName;
    resultSchemaName;
    dialect;
    translatefn;

     constructor(
        conn,
        writeConn,
        schemaName,
        vocabSchemaName,
        resultSchemaName,
        dialect,
        translatefn,
    ) {
        this.connection = conn
        this.writeConn = writeConn
        this.schemaName = schemaName;
        this.vocabSchemaName = vocabSchemaName;
        this.resultSchemaName = resultSchemaName;
        this.dialect = dialect;
        this.translatefn = translatefn[dialect];
    }


    parseResults(result) {
        function formatResult(value) {
            switch (typeof value) {
                case "bigint":
                    return Number(value) * 1;
                default:
                    return value;
            }
        }
        Object.keys(result).forEach((rowId) => {
            Object.keys(result[rowId]).forEach((colKey) => {
                if (
                    result[rowId][colKey] === null ||
                    typeof result[rowId][colKey] === "undefined"
                ) {
                    result[rowId][colKey] = NOVALUE;
                } else {
                    result[rowId][colKey] = formatResult(result[rowId][colKey]);
                }
            });
        });
        return result;
    }

    async atlas(
        atlas,
        cdmSchema,
        cohortId,
        callback
    ) {
        try {
            const atlasStr = (typeof atlas === 'string') ? atlas : JSON.stringify(atlas);

            const toBase64 = (s) => {
                if (typeof Buffer !== 'undefined' && Buffer.from) {
                    return Buffer.from(s, 'utf8').toString('base64');
                }
                const bytes = new TextEncoder().encode(s);
                let binary = '';
                for (const b of bytes) binary += String.fromCharCode(b);
                return btoa(binary);
            };
            const atlasB64 = toBase64(atlasStr);

            const resultSchema = this.resultSchemaName || this.schemaName;

            const cohortIdInt = parseInt(cohortId, 10);
            if (Number.isNaN(cohortIdInt)) {
                callback(new Error("Invalid cohortId: expected an integer"), null);
                return;
            }

            const optionsObj = {
                cdmSchema: cdmSchema,
                resultSchema: resultSchema,
                targetTable: "cohort",
                cohortId: cohortIdInt,
                generateStats: true
            };
            // Escape single quotes for embedding in SQL string literal.
            const options = JSON.stringify(optionsObj).replace(/'/g, "''");

            const sql = `SELECT circe_sql_render_translate(circe_json_to_sql('${atlasB64}', '${options}'), 'duckdb', '{}') AS sql`;
            const result = await this.connection.execute(sql, []);

            if (result && result.length > 0 && result[0].sql) {
                callback(null, {sql: result[0].sql});
            } else {
                callback(new Error("No SQL generated from cohort definition"), null);
            }
        } catch (err) {
            console.error(err);
            callback(new Error(err.message), null);
        }
    }

    async atlas_validate(
        cohortDefinition,
        callback
    ) {
        try {
            const cohortStr = (typeof cohortDefinition === 'string') ? cohortDefinition : JSON.stringify(cohortDefinition);

            const toBase64 = (s) => {
                if (typeof Buffer !== 'undefined' && Buffer.from) {
                    return Buffer.from(s, 'utf8').toString('base64');
                }
                const bytes = new TextEncoder().encode(s);
                let binary = '';
                for (const b of bytes) binary += String.fromCharCode(b);
                return btoa(binary);
            };
            const cohortDefinitionBase64 = toBase64(cohortStr);

            const sql = `SELECT circe_check_cohort('${cohortDefinitionBase64}') AS warnings`;
            const result = await this.connection.execute(sql, []);

            if (result && result.length > 0 && result[0].warnings) {
                const warnings = JSON.parse(result[0].warnings);
                const messages = warnings.map(w => ({
                    severity: w.severity,
                    message: w.message
                }));
                callback(null, messages);
            } else {
                callback(null, []);
            }
        } catch (err) {
            console.error(err);
            callback(new Error(err.message), null);
        }
    }

    async execute(
        sql,
        parameters,
        callback
    ) {
        try {
            let temp = sql;
            temp = this.#parseSql(temp, parameters);
            if (sqlLoggingEnabled()) {
                console.log(`Sql: ${redactSecrets(sql)}`);
                console.log(
                    `parameters: ${redactSecrets(JSON.stringify(flattenParameter(parameters)))}`
                );
                console.log("Duckdb client created");
                console.log(redactSecrets(temp));
            }
            const result = await this.connection.execute(
                temp, flattenParameter(parameters)
            );
            callback(null, result);
        } catch (err) {
            console.error(err);
            callback(err instanceof Error ? err : new Error(err?.message ?? String(err)), null);
        }
    }

    async execute_write(
        sql,
        parameters,
        callback
    ) {
        try {
            let temp = sql;
            temp = this.#parseSql(temp, parameters);
            if (sqlLoggingEnabled()) {
                console.log(`Sql: ${redactSecrets(sql)}`);
                console.log(
                    `parameters: ${redactSecrets(JSON.stringify(flattenParameter(parameters)))}`
                );
                console.log("Duckdb client created");
                console.log(redactSecrets(temp));
            }
            const result = await this.writeConn.executeWrite(
                temp, flattenParameter(parameters)
            );
            callback(null, result);
        } catch (err) {
            console.error(err);
            callback(err instanceof Error ? err : new Error(err?.message ?? String(err)), null);
        }
    }

     #parseSql(temp, parameters) {
        // Schema substitution must run before dialect translation.
        temp = this.#getSqlStatementWithSchemaName(this.schemaName, temp);
        return this.translatefn(
            temp,
            this.schemaName,
            this.vocabSchemaName,
            this.resultSchemaName,
            parameters
        );
    }

    getTranslatedSql(sql, schemaName, parameters) {
        return this.#parseSql(sql, parameters);
    }

    executeQuery(
        sql,
        parameters,
        callback
    ) {
        try {
            this.execute(sql, parameters, (err, resultSet) => {
                if (err) {
                    console.error(err);
                    callback(err, null);
                } else {
                    const result = this.parseResults(resultSet);
                    callback(null, result);
                }
            });
        } catch (err) {
            console.error(err);
            callback(err instanceof Error ? err : new Error(err?.message ?? String(err)), null);
        }
    }

    executeStreamQuery(
        sql,
        parameters,
        callback,
        schemaName = ""
    ) {
        try {
            let temp = sql;
            temp = this.#parseSql(temp, parameters);
            if (sqlLoggingEnabled()) {
                console.log(`Stream Sql: ${redactSecrets(sql)}`);
                console.log(
                    `Stream parameters: ${redactSecrets(JSON.stringify(flattenParameter(parameters)))}`
                );
                console.log("Duckdb client created for streaming");
                console.log(redactSecrets(temp));
            }

            executeQueryStream(this.connection.__database, temp, flattenParameter(parameters))
                .then(stream => {
                    callback(null, stream);
                })
                .catch(err => {
                    console.error(err);
                    callback(new Error(err.message), null);
                });
        } catch (err) {
            console.error(err);
            callback(new Error(err.message), null);
        }
    }

    executeUpdate(
        sql,
        parameters,
        callback
    ) {
        try {
            this.execute_write(sql, parameters, (err, result) => {
                if (err) {
                    console.error(err)
                    callback(err, null);
                } else {
                    callback(null, result);
                }
            });
        } catch (error) {
            callback(error, null);
        }
    }

    executeProc(
        procedure,
        parameters,
        callback
    ) {
        throw new Error("executeProc is not yet implemented");
    }

    commit(callback) {
        throw new Error("commit is not yet implemented");
    }

    setAutoCommitToFalse() {
        throw new Error("setAutoCommitToFalse is not yet implemented");
    }

    async close() {
        try {
            if (this.connection && typeof this.connection.close === 'function') {
                this.connection.close();
            }
            if (this.writeConn && this.writeConn !== this.connection && typeof this.writeConn.close === 'function') {
                this.writeConn.close();
            }
        } catch (e) {
            console.error(`Error closing TrexConnection: ${e?.message ?? e}`);
        }
    }

    executeBulkUpdate(
        sql,
        parameters,
        callback
    ) {
        throw "executeBulkUpdate is not yet implemented";
    }

    executeBulkInsert(
        sql,
        parameters,
        callback
    ) {
        throw "executeBulkInsert is not yet implemented";
    }

    setCurrentUserToDbSession(
        user,
        callback
    ) {
        callback(null, null);
    }

    setTemporalSystemTimeToDbSession(
        systemTime,
        cb
    ) {
        cb(null, null);
    }

    rollback(callback) {
        throw "rollback is not yet implemented";
    }

     #getSqlStatementWithSchemaName(
        schemaName,
        sql
    ) {
        const databaseName = this.connection.getdatabase();
        const replacement = schemaName === "" ? "" : `${databaseName}.${schemaName}.`;
        sql = sql.replace(/\$\$SCHEMA\$\$\./g, replacement);

        const vocabReplacement = this.vocabSchemaName === "" ? "" : `${databaseName}.${this.vocabSchemaName}.`;
        sql = sql.replace(/\$\$VOCAB_SCHEMA\$\$\./g, vocabReplacement);

        const resultReplacement = this.resultSchemaName === "" ? "" : `${databaseName}.${this.resultSchemaName}.`;
        sql = sql.replace(/\$\$RESULT_SCHEMA\$\$\./g, resultReplacement);

        return sql;
    }
}
