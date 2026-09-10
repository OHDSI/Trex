import { Router } from "express";
import express from "express";
import { pool } from "../db.ts";
import {
  signAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashRefreshToken,
} from "./jwt.ts";
import { hashPassword, verifyPassword } from "./password.ts";
import { authLimiter, apiLimiter } from "../middleware/rate-limit.ts";
import { isRefreshTokenExpired } from "./refresh-token-ttl.ts";
import { loadExternalProviders } from "./settings-providers.ts";
import { IDP_METADATA_KEY } from "./oidc/claims.ts";

const router = Router();
router.use(express.json());

// ── Helpers ──────────────────────────────────────────────────────────────────

interface DbUser {
  id: string;
  name: string;
  email: string;
  image: string | null;
  role: string;
  banned: boolean;
  emailVerified: boolean;
  email_confirmed_at: string | null;
  last_sign_in_at: string | null;
  mustChangePassword: boolean;
  user_metadata: Record<string, unknown>;
  app_metadata: Record<string, unknown>;
  password_hash: string | null;
  createdAt: string;
  updatedAt: string;
}

function toGoTrueUser(u: DbUser) {
  return {
    id: u.id,
    aud: "authenticated",
    role: "authenticated",
    email: u.email,
    email_confirmed_at: u.email_confirmed_at || null,
    last_sign_in_at: u.last_sign_in_at || null,
    app_metadata: {
      provider: "email",
      providers: ["email"],
      trex_role: u.role,
      ...(u.app_metadata || {}),
    },
    user_metadata: {
      name: u.name,
      image: u.image,
      must_change_password: u.mustChangePassword,
      ...(u.user_metadata || {}),
    },
    identities: [],
    created_at: u.createdAt,
    updated_at: u.updatedAt,
  };
}

// Exported for the federation callback, which finishes an upstream sign-in by
// issuing the very same session this grant issues.
export async function createTokenResponse(user: DbUser, sessionId?: string, res?: any) {
  const sid = sessionId || crypto.randomUUID();
  const accessToken = await signAccessToken(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      user_metadata: {
        name: user.name,
        image: user.image,
        must_change_password: user.mustChangePassword,
      },
    },
    sid,
  );

  const refreshToken = generateRefreshToken();
  const tokenHash = await hashRefreshToken(refreshToken);

  await pool.query(
    `INSERT INTO trexdb.refresh_token (token_hash, "userId", session_id) VALUES ($1, $2, $3)`,
    [tokenHash, user.id, sid],
  );

  const expiresAt = Math.floor(Date.now() / 1000) + 3600;

  // sb-access-token cookie lets same-origin iframes (Studio) pick up auth.
  // CSRF: SameSite=Lax is the only protection — adding SameSite=None requires an anti-CSRF token first.
  if (res) {
    const forwardedProto = res.req?.headers?.["x-forwarded-proto"];
    const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
    const secure =
      Deno.env.get("TREX_FORCE_SECURE_COOKIES") === "1" ||
      res.req?.protocol === "https" ||
      proto === "https";
    res.cookie("sb-access-token", accessToken, {
      httpOnly: true,
      sameSite: "lax",
      secure,
      path: "/",
      maxAge: 3600 * 1000,
    });
  }

  return {
    access_token: accessToken,
    token_type: "bearer",
    expires_in: 3600,
    expires_at: expiresAt,
    refresh_token: refreshToken,
    user: toGoTrueUser(user),
  };
}

async function fetchUserByEmail(email: string): Promise<DbUser | null> {
  const result = await pool.query(
    `SELECT id, name, email, image, role, banned, "emailVerified", email_confirmed_at,
            last_sign_in_at, "mustChangePassword", user_metadata, app_metadata,
            password_hash, "createdAt", "updatedAt"
     FROM trexdb."user" WHERE email = $1 AND "deletedAt" IS NULL`,
    [email],
  );
  return result.rows[0] || null;
}

async function fetchUserById(id: string): Promise<DbUser | null> {
  const result = await pool.query(
    `SELECT id, name, email, image, role, banned, "emailVerified", email_confirmed_at,
            last_sign_in_at, "mustChangePassword", user_metadata, app_metadata,
            password_hash, "createdAt", "updatedAt"
     FROM trexdb."user" WHERE id = $1 AND "deletedAt" IS NULL`,
    [id],
  );
  return result.rows[0] || null;
}

/**
 * Get password for verification. Checks user.password_hash first,
 * falls back to Better Auth's account.password (graceful migration).
 */
async function getPasswordHash(userId: string, userPasswordHash: string | null): Promise<string | null> {
  if (userPasswordHash) return userPasswordHash;

  // Fallback: Better Auth stores passwords in the account table
  const result = await pool.query(
    `SELECT password FROM trexdb.account WHERE "userId" = $1 AND "providerId" = 'credential'`,
    [userId],
  );
  return result.rows[0]?.password || null;
}

/**
 * After successful login with a legacy password, migrate the hash
 * to user.password_hash for future logins.
 */
async function migratePasswordHash(userId: string, newHash: string) {
  await pool.query(
    `UPDATE trexdb."user" SET password_hash = $1, "updatedAt" = NOW() WHERE id = $2`,
    [newHash, userId],
  );
}

// ── POST /signup ─────────────────────────────────────────────────────────────

router.post("/signup", authLimiter, async (req, res) => {
  try {
    const { email, password, data } = req.body;

    if (!email || !password) {
      res.status(422).json({ error: "signup_invalid", error_description: "Email and password are required" });
      return;
    }

    if (password.length < 8) {
      res.status(422).json({ error: "signup_invalid", error_description: "Password must be at least 8 characters" });
      return;
    }

    // Check self-registration setting
    const settingResult = await pool.query(
      `SELECT value FROM trexdb.setting WHERE key = 'auth.selfRegistration'`,
    );
    const registrationEnabled = settingResult.rows.length > 0 && settingResult.rows[0].value === true;
    if (!registrationEnabled) {
      res.status(403).json({ error: "signup_disabled", error_description: "Registration is currently disabled" });
      return;
    }

    // Check if user already exists
    const existing = await fetchUserByEmail(email);
    if (existing) {
      res.status(422).json({ error: "user_already_exists", error_description: "A user with this email already exists" });
      return;
    }

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    const userName = data?.name || email.split("@")[0];

    // Check if this is the first user
    const countResult = await pool.query('SELECT COUNT(*)::int AS count FROM trexdb."user"');
    const isFirstUser = countResult.rows[0].count === 0;
    const adminEmail = Deno.env.get("ADMIN_EMAIL");
    const shouldBeAdmin = isFirstUser || (adminEmail && email === adminEmail);
    const userRole = shouldBeAdmin ? "admin" : "user";

    await pool.query(
      `INSERT INTO trexdb."user" (id, name, email, "emailVerified", email_confirmed_at, role, password_hash, user_metadata)
       VALUES ($1, $2, $3, true, NOW(), $4, $5, $6)`,
      [userId, userName, email, userRole, passwordHash, JSON.stringify(data || {})],
    );

    if (shouldBeAdmin) {
      console.log(`[auth] Assigned admin role to ${email} (${isFirstUser ? "first user" : "ADMIN_EMAIL match"})`);
    }

    // Also create a Better Auth compatible account record for backward compat
    await pool.query(
      `INSERT INTO trexdb.account (id, "userId", "accountId", "providerId", password)
       VALUES ($1, $2, $2, 'credential', $3)
       ON CONFLICT ("providerId", "accountId") DO NOTHING`,
      [crypto.randomUUID(), userId, passwordHash],
    );

    const user = await fetchUserById(userId);
    if (!user) {
      res.status(500).json({ error: "server_error", error_description: "Failed to create user" });
      return;
    }

    const response = await createTokenResponse(user, undefined, res);

    // Update last_sign_in_at
    await pool.query(
      `UPDATE trexdb."user" SET last_sign_in_at = NOW() WHERE id = $1`,
      [userId],
    );

    res.status(200).json(response);
  } catch (err) {
    console.error("[auth] signup error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
});

// ── POST /token ──────────────────────────────────────────────────────────────

router.post("/token", authLimiter, async (req, res) => {
  const grantType = req.query.grant_type;

  if (grantType === "password") {
    return handlePasswordGrant(req, res);
  } else if (grantType === "refresh_token") {
    return handleRefreshGrant(req, res);
  }

  res.status(400).json({ error: "unsupported_grant_type", error_description: `Unsupported grant_type: ${grantType}` });
});

async function handlePasswordGrant(req: any, res: any) {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ error: "invalid_grant", error_description: "Email and password are required" });
      return;
    }

    const user = await fetchUserByEmail(email);
    if (!user) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid login credentials" });
      return;
    }

    if (user.banned) {
      res.status(400).json({ error: "user_banned", error_description: "User is banned" });
      return;
    }

    const storedHash = await getPasswordHash(user.id, user.password_hash);
    if (!storedHash) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid login credentials" });
      return;
    }

    const valid = await verifyPassword(password, storedHash);
    if (!valid) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid login credentials" });
      return;
    }

    // Migrate password hash if needed
    if (!user.password_hash && storedHash) {
      const newHash = await hashPassword(password);
      await migratePasswordHash(user.id, newHash);
    }

    // This session is a native one, so any federation block left by an earlier
    // federated sign-in stops describing it. Dropped rather than left to age:
    // the OIDC provider reads that block to decide whether to emit
    // idp_provider/idp_groups, and a stale one would have trex assert that a
    // password session came from an upstream. Also stamps last_sign_in_at,
    // which this grant already owed the row.
    await pool.query(
      `UPDATE trexdb."user"
          SET last_sign_in_at = NOW(),
              app_metadata = COALESCE(app_metadata, '{}'::jsonb) - $2::text
        WHERE id = $1`,
      [user.id, IDP_METADATA_KEY],
    );
    // The row was read before that UPDATE, so the response body would still
    // carry the block that no longer exists.
    if (user.app_metadata) delete user.app_metadata[IDP_METADATA_KEY];

    res.json(await createTokenResponse(user, undefined, res));
  } catch (err) {
    console.error("[auth] password grant error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
}

async function handleRefreshGrant(req: any, res: any) {
  try {
    const { refresh_token: refreshToken } = req.body;

    if (!refreshToken) {
      res.status(400).json({ error: "invalid_grant", error_description: "refresh_token is required" });
      return;
    }

    const tokenHash = await hashRefreshToken(refreshToken);

    // Find and revoke the old refresh token
    const result = await pool.query(
      `UPDATE trexdb.refresh_token SET revoked = true, "updatedAt" = NOW()
       WHERE token_hash = $1 AND revoked = false
       RETURNING "userId", session_id, "createdAt"`,
      [tokenHash],
    );

    if (result.rows.length === 0) {
      res.status(400).json({ error: "invalid_grant", error_description: "Invalid or revoked refresh token" });
      return;
    }

    const { userId, session_id: sessionId, createdAt } = result.rows[0];

    // Enforce an absolute lifetime: rotation alone lets a leaked-but-unused
    // token be redeemed indefinitely. The row was just revoked above, so an
    // expired token is consumed and rejected in one shot.
    if (isRefreshTokenExpired(createdAt)) {
      res.status(400).json({ error: "invalid_grant", error_description: "Refresh token expired" });
      return;
    }
    const user = await fetchUserById(userId);

    if (!user || user.banned) {
      res.status(400).json({ error: "invalid_grant", error_description: "User not found or banned" });
      return;
    }

    const response = await createTokenResponse(user, sessionId, res);
    res.json(response);
  } catch (err) {
    console.error("[auth] refresh grant error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
}

// ── POST /logout ─────────────────────────────────────────────────────────────

// Trade a Bearer access token for an sb-access-token cookie so same-origin
// iframes (which can't read the parent's localStorage) can authenticate.
router.post("/sync-cookie", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }
    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims || claims.role === "service_role" || claims.role === "anon") {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }
    const forwardedProto = req.headers?.["x-forwarded-proto"];
    const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
    const secure =
      Deno.env.get("TREX_FORCE_SECURE_COOKIES") === "1" ||
      req.protocol === "https" ||
      proto === "https";
    res.cookie("sb-access-token", token, {
      httpOnly: true,
      sameSite: "lax",
      secure,
      path: "/",
      maxAge: Math.max(0, (claims.exp || 0) * 1000 - Date.now()),
    });
    res.status(204).end();
  } catch (err) {
    console.error("[auth] sync-cookie error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

router.post("/logout", apiLimiter, async (req, res) => {
  res.clearCookie("sb-access-token", { path: "/" });
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(204).end();
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (claims?.session_id) {
      // Revoke all refresh tokens for this session
      await pool.query(
        `UPDATE trexdb.refresh_token SET revoked = true, "updatedAt" = NOW()
         WHERE session_id = $1 AND revoked = false`,
        [claims.session_id],
      );
    }

    res.status(204).end();
  } catch (err) {
    console.error("[auth] logout error:", err);
    res.status(204).end();
  }
});

// ── GET /user ────────────────────────────────────────────────────────────────

router.get("/user", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated", error_description: "Missing or invalid authorization header" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated", error_description: "Invalid or expired token" });
      return;
    }

    const user = await fetchUserById(claims.sub);
    if (!user) {
      res.status(404).json({ error: "user_not_found", error_description: "User not found" });
      return;
    }

    res.json(toGoTrueUser(user));
  } catch (err) {
    console.error("[auth] get user error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
});

// ── PUT /user ────────────────────────────────────────────────────────────────

router.put("/user", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated", error_description: "Missing or invalid authorization header" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated", error_description: "Invalid or expired token" });
      return;
    }

    const { email, password, data } = req.body;
    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIdx = 1;

    if (data?.name !== undefined) {
      updates.push(`name = $${paramIdx++}`);
      values.push(data.name);
    }

    if (data?.image !== undefined) {
      updates.push(`image = $${paramIdx++}`);
      values.push(data.image);
    }

    if (data) {
      updates.push(`user_metadata = user_metadata || $${paramIdx++}::jsonb`);
      values.push(JSON.stringify(data));
    }

    if (email) {
      updates.push(`email = $${paramIdx++}`);
      values.push(email);
    }

    if (password) {
      if (password.length < 8) {
        res.status(422).json({ error: "validation_failed", error_description: "Password must be at least 8 characters" });
        return;
      }
      const newHash = await hashPassword(password);
      updates.push(`password_hash = $${paramIdx++}`);
      values.push(newHash);

      // Also update account table for backward compat
      await pool.query(
        `UPDATE trexdb.account SET password = $1, "updatedAt" = NOW()
         WHERE "userId" = $2 AND "providerId" = 'credential'`,
        [newHash, claims.sub],
      );

      // Revoke all outstanding refresh tokens so a stolen token doesn't survive
      // a password change.
      await pool.query(
        `UPDATE trexdb.refresh_token SET revoked = true, "updatedAt" = NOW()
         WHERE "userId" = $1 AND revoked = false`,
        [claims.sub],
      );
    }

    if (updates.length > 0) {
      updates.push(`"updatedAt" = NOW()`);
      values.push(claims.sub);
      await pool.query(
        `UPDATE trexdb."user" SET ${updates.join(", ")} WHERE id = $${paramIdx}`,
        values,
      );
    }

    const user = await fetchUserById(claims.sub);
    if (!user) {
      res.status(404).json({ error: "user_not_found" });
      return;
    }

    res.json(toGoTrueUser(user));
  } catch (err) {
    console.error("[auth] update user error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
});

// ── POST /recover ────────────────────────────────────────────────────────────

router.post("/recover", async (req, res) => {
  const { email } = req.body;
  if (email) {
    console.log(`[auth] Password recovery requested for ${email}`);
  }
  // Always return success to avoid email enumeration
  res.json({});
});

// ── Custom: POST /password-changed ──────────────────────────────────────────

router.post("/password-changed", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    await pool.query(
      'UPDATE trexdb."user" SET "mustChangePassword" = false, "updatedAt" = NOW() WHERE id = $1',
      [claims.sub],
    );
    res.json({ success: true });
  } catch (err) {
    console.error("[auth] password-changed error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Custom: POST /change-password ───────────────────────────────────────────

router.post("/change-password", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      res.status(400).json({ error: "Current password and new password are required" });
      return;
    }

    if (newPassword.length < 8) {
      res.status(422).json({ error: "Password must be at least 8 characters" });
      return;
    }

    const user = await fetchUserById(claims.sub);
    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    const storedHash = await getPasswordHash(user.id, user.password_hash);
    if (!storedHash) {
      res.status(400).json({ error: "No password set for this account" });
      return;
    }

    const valid = await verifyPassword(currentPassword, storedHash);
    if (!valid) {
      res.status(400).json({ error: "Current password is incorrect" });
      return;
    }

    const newHash = await hashPassword(newPassword);
    await pool.query(
      `UPDATE trexdb."user" SET password_hash = $1, "updatedAt" = NOW() WHERE id = $2`,
      [newHash, user.id],
    );

    // Also update account table
    await pool.query(
      `UPDATE trexdb.account SET password = $1, "updatedAt" = NOW()
       WHERE "userId" = $2 AND "providerId" = 'credential'`,
      [newHash, user.id],
    );

    // Revoke all outstanding refresh tokens so a stolen token doesn't survive
    // a password change.
    await pool.query(
      `UPDATE trexdb.refresh_token SET revoked = true, "updatedAt" = NOW()
       WHERE "userId" = $1 AND revoked = false`,
      [user.id],
    );

    res.json({ success: true });
  } catch (err) {
    console.error("[auth] change-password error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Custom: GET /sessions ───────────────────────────────────────────────────

router.get("/sessions", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    // Return active refresh token sessions grouped by session_id
    const result = await pool.query(
      `SELECT DISTINCT ON (session_id)
         id, session_id, "createdAt", "updatedAt"
       FROM trexdb.refresh_token
       WHERE "userId" = $1 AND revoked = false
       ORDER BY session_id, "createdAt" DESC`,
      [claims.sub],
    );

    const sessions = result.rows.map((row: any) => ({
      id: row.id,
      token: row.session_id, // Use session_id as the session identifier
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      // These aren't stored in refresh tokens, but kept for UI compat
      ipAddress: null,
      userAgent: null,
      expiresAt: null,
    }));

    res.json(sessions);
  } catch (err) {
    console.error("[auth] sessions error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Custom: POST /revoke-session ────────────────────────────────────────────

router.post("/revoke-session", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const { session_id: targetSessionId } = req.body;
    if (!targetSessionId) {
      res.status(400).json({ error: "session_id is required" });
      return;
    }

    await pool.query(
      `UPDATE trexdb.refresh_token SET revoked = true, "updatedAt" = NOW()
       WHERE "userId" = $1 AND session_id = $2 AND revoked = false`,
      [claims.sub, targetSessionId],
    );

    res.json({ success: true });
  } catch (err) {
    console.error("[auth] revoke-session error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Custom: GET /accounts (linked accounts) ─────────────────────────────────

router.get("/accounts", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const result = await pool.query(
      `SELECT id, "providerId", "accountId", "createdAt"
       FROM trexdb.account WHERE "userId" = $1`,
      [claims.sub],
    );

    res.json(result.rows);
  } catch (err) {
    console.error("[auth] accounts error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /settings ────────────────────────────────────────────────────────────

router.get("/settings", apiLimiter, async (_req, res) => {
  try {
    // Check self-registration
    let disableSignup = true;
    try {
      const result = await pool.query(
        `SELECT value FROM trexdb.setting WHERE key = 'auth.selfRegistration'`,
      );
      disableSignup = !(result.rows.length > 0 && result.rows[0].value === true);
    } catch {
      // Default: disabled
    }

    // Providers come from sso_provider so a client can discover what is
    // actually configured, rather than a fixed list that is wrong either way.
    // Failure (missing table, DB hiccup) falls back to email-only inside
    // loadExternalProviders rather than 500ing this endpoint.
    const external = await loadExternalProviders(pool);

    res.json({
      external,
      disable_signup: disableSignup,
      mailer_autoconfirm: true,
      phone_autoconfirm: false,
      sms_provider: "",
    });
  } catch (err) {
    console.error("[auth] settings error:", err);
    res.status(500).json({ error: "server_error" });
  }
});

// ── GET /health ──────────────────────────────────────────────────────────────

router.get("/health", (_req, res) => {
  res.json({ version: "trex-gotrue-1.0.0", name: "GoTrue", description: "Trex GoTrue-compatible auth" });
});

// /admin/users is the GoTrue-compatible alias supabase-js POSTs to.
router.post(["/admin/create-user", "/admin/users"], apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    // service_role bypasses RLS/admin checks (Supabase convention).
    const callerRole = claims.app_metadata?.trex_role;
    const isServiceRole = claims.role === "service_role";
    if (callerRole !== "admin" && !isServiceRole) {
      res.status(403).json({ error: "forbidden", error_description: "Admin access required" });
      return;
    }

    const { email, password, data } = req.body;

    if (!email || !password) {
      res.status(422).json({ error: "validation_failed", error_description: "Email and password are required" });
      return;
    }

    // Check if user already exists
    const existing = await fetchUserByEmail(email);
    if (existing) {
      res.status(422).json({ error: "user_already_exists", error_description: "A user with this email already exists" });
      return;
    }

    const userId = crypto.randomUUID();
    const passwordHash = await hashPassword(password);
    const userName = data?.name || email.split("@")[0];
    const userRole = data?.role || "user";

    await pool.query(
      `INSERT INTO trexdb."user" (id, name, email, "emailVerified", email_confirmed_at, role, password_hash, user_metadata)
       VALUES ($1, $2, $3, true, NOW(), $4, $5, $6)`,
      [userId, userName, email, userRole, passwordHash, JSON.stringify(data || {})],
    );

    // Also create account record for backward compat
    await pool.query(
      `INSERT INTO trexdb.account (id, "userId", "accountId", "providerId", password)
       VALUES ($1, $2, $2, 'credential', $3)
       ON CONFLICT ("providerId", "accountId") DO NOTHING`,
      [crypto.randomUUID(), userId, passwordHash],
    );

    const user = await fetchUserById(userId);
    if (!user) {
      res.status(500).json({ error: "server_error", error_description: "Failed to create user" });
      return;
    }

    res.status(200).json(toGoTrueUser(user));
  } catch (err) {
    console.error("[auth] admin create-user error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
});

// PUT /admin/users/:id is the GoTrue-compatible admin update. Only the password
// is settable: an administrator resetting a password for someone who has lost
// it cannot supply the current one, so this is the counterpart to
// /change-password rather than a duplicate of it.
router.put("/admin/users/:id", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    // service_role bypasses RLS/admin checks (Supabase convention).
    const callerRole = claims.app_metadata?.trex_role;
    const isServiceRole = claims.role === "service_role";
    if (callerRole !== "admin" && !isServiceRole) {
      res.status(403).json({ error: "forbidden", error_description: "Admin access required" });
      return;
    }

    const { password, banned } = req.body ?? {};
    if (password === undefined && banned === undefined) {
      res.status(422).json({
        error: "validation_failed",
        error_description: "One of 'password' or 'banned' is required",
      });
      return;
    }

    if (password !== undefined && password.length < 8) {
      res.status(422).json({ error: "Password must be at least 8 characters" });
      return;
    }

    if (banned !== undefined && typeof banned !== "boolean") {
      res.status(422).json({ error: "validation_failed", error_description: "'banned' must be a boolean" });
      return;
    }

    const user = await fetchUserById(req.params.id);
    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    if (password !== undefined) {
      const newHash = await hashPassword(password);
      await pool.query(
        `UPDATE trexdb."user" SET password_hash = $1, "updatedAt" = NOW() WHERE id = $2`,
        [newHash, user.id],
      );

      // Also update account table
      await pool.query(
        `UPDATE trexdb.account SET password = $1, "updatedAt" = NOW()
         WHERE "userId" = $2 AND "providerId" = 'credential'`,
        [newHash, user.id],
      );
    }

    if (banned !== undefined) {
      await pool.query(
        `UPDATE trexdb."user" SET banned = $1, "updatedAt" = NOW() WHERE id = $2`,
        [banned, user.id],
      );
    }

    // Revoke all outstanding refresh tokens. A password reset is what an
    // administrator does when an account may be compromised, and a ban is
    // pointless if the sessions it was issued before it outlive it.
    if (password !== undefined || banned === true) {
      await pool.query(
        `UPDATE trexdb.refresh_token SET revoked = true, "updatedAt" = NOW()
         WHERE "userId" = $1 AND revoked = false`,
        [user.id],
      );
    }

    const updated = await fetchUserById(user.id);
    res.json(toGoTrueUser(updated ?? user));
  } catch (err) {
    console.error("[auth] admin set-password error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
});

// GET /admin/users/:id is the GoTrue-compatible admin read. Without it a caller
// holding only a subject has no way to resolve the account behind it.
router.get("/admin/users/:id", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    // service_role bypasses RLS/admin checks (Supabase convention).
    const callerRole = claims.app_metadata?.trex_role;
    const isServiceRole = claims.role === "service_role";
    if (callerRole !== "admin" && !isServiceRole) {
      res.status(403).json({ error: "forbidden", error_description: "Admin access required" });
      return;
    }

    const user = await fetchUserById(req.params.id);
    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    res.json(toGoTrueUser(user));
  } catch (err) {
    console.error("[auth] admin get-user error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
});

// DELETE /admin/users/:id is the GoTrue-compatible admin delete. Removing the
// account is what lets the same address be registered again afterwards, so a
// caller that deletes a user and recreates it under the same name succeeds
// rather than colliding with the account left behind.
router.delete("/admin/users/:id", apiLimiter, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    const token = authHeader.slice(7);
    const claims = await verifyAccessToken(token);
    if (!claims) {
      res.status(401).json({ error: "not_authenticated" });
      return;
    }

    // service_role bypasses RLS/admin checks (Supabase convention).
    const callerRole = claims.app_metadata?.trex_role;
    const isServiceRole = claims.role === "service_role";
    if (callerRole !== "admin" && !isServiceRole) {
      res.status(403).json({ error: "forbidden", error_description: "Admin access required" });
      return;
    }

    const user = await fetchUserById(req.params.id);
    if (!user) {
      res.status(404).json({ error: "User not found" });
      return;
    }

    // Sessions, credentials and tokens are all ON DELETE CASCADE from the user
    // row, so removing it takes the account's refresh tokens with it rather than
    // leaving any able to mint access tokens for a user that no longer exists.
    await pool.query(
      `DELETE FROM trexdb."user" WHERE id = $1`,
      [user.id],
    );

    res.status(200).json({});
  } catch (err) {
    console.error("[auth] admin delete-user error:", err);
    res.status(500).json({ error: "server_error", error_description: "Internal server error" });
  }
});

export { router as authRouter };
