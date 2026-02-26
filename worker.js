const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14;

const DEFAULT_PERMISSIONS = {
  can_view_calendar: true,
  can_view_leads: true,
  can_view_customers: true,
  can_view_messages: true,
  can_view_invoices: true,
  can_create_lead: true,
  can_create_invoice: true,
  can_manage_users: true,
  can_manage_roles: true,
  can_manage_email_settings: true,
  can_manage_payment_settings: true
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/auth/")) {
      return handleAuth(request, env, url);
    }

    if (url.pathname.startsWith("/api/")) {
      return proxyToBackend(request, env, url);
    }

    return env.ASSETS.fetch(request);
  }
};

async function handleAuth(request, env, url) {
  if (!env.DB) {
    return json({ error: "D1 database binding `DB` is not configured." }, 500);
  }

  await ensureSchema(env.DB);
  await cleanupExpiredSessions(env.DB);

  const method = request.method;
  const pathname = url.pathname;

  if (method === "GET" && pathname === "/api/auth/setup") {
    const total = await countAdmins(env.DB);
    return json({ setupRequired: total === 0 });
  }

  if (method === "POST" && pathname === "/api/auth/setup") {
    const body = await readJsonBody(request);
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    if (!username || !password) return json({ error: "Username and password are required" }, 400);
    if (password.length < 6) return json({ error: "Password must be at least 6 characters" }, 400);
    if ((await countAdmins(env.DB)) > 0) return json({ error: "Setup already completed" }, 409);

    const existing = await env.DB
      .prepare("SELECT id FROM admins WHERE lower(username)=lower(?) LIMIT 1")
      .bind(username)
      .first();
    if (existing) return json({ error: "Username already exists" }, 409);

    const createdAt = nowIso();
    const passwordHash = await hashPassword(password);
    const result = await env.DB
      .prepare(
        "INSERT INTO admins (username, password_hash, role_id, is_active, created_at, last_login) VALUES (?, ?, 1, 1, ?, NULL)"
      )
      .bind(username, passwordHash, createdAt)
      .run();

    const user = {
      id: Number(result.meta?.last_row_id),
      username,
      role_id: 1,
      role_name: "Owner",
      is_active: 1,
      last_login: null,
      created_at: createdAt,
      permissions: DEFAULT_PERMISSIONS,
      roleId: 1,
      roleName: "Owner"
    };
    return json({ success: true, user }, 201);
  }

  if (method === "POST" && pathname === "/api/auth/login") {
    const body = await readJsonBody(request);
    const username = String(body.username || "").trim();
    const password = String(body.password || "");

    const admin = await env.DB
      .prepare("SELECT * FROM admins WHERE lower(username)=lower(?) LIMIT 1")
      .bind(username)
      .first();

    if (!admin || admin.is_active === 0) return json({ error: "Invalid username or password" }, 401);
    if (!(await verifyPassword(password, admin.password_hash))) return json({ error: "Invalid username or password" }, 401);

    const token = randomHex(32);
    const createdAt = nowIso();
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

    await env.DB
      .prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
      .bind(token, admin.id, createdAt, expiresAt)
      .run();

    await env.DB.prepare("UPDATE admins SET last_login=? WHERE id=?").bind(createdAt, admin.id).run();

    const user = sanitizeUser({ ...admin, last_login: createdAt });
    return json({ success: true, token, user });
  }

  if (method === "GET" && pathname === "/api/auth/verify") {
    const auth = await requireAuth(request, env.DB);
    if (!auth) return json({ valid: false });
    return json({ valid: true, user: auth.user });
  }

  if (pathname === "/api/auth/users") {
    const auth = await requireAuth(request, env.DB);
    if (!auth) return json({ error: "Unauthorized" }, 401);

    if (method === "GET") {
      const rows = await env.DB
        .prepare("SELECT id, username, role_id, is_active, created_at, last_login FROM admins ORDER BY id ASC")
        .all();
      return json({ users: (rows.results || []).map(sanitizeUser) });
    }

    if (method === "POST") {
      const body = await readJsonBody(request);
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      const roleId = Number(body.role_id) || 1;
      if (!username || password.length < 6) return json({ error: "Username and a 6+ char password are required" }, 400);

      const existing = await env.DB
        .prepare("SELECT id FROM admins WHERE lower(username)=lower(?) LIMIT 1")
        .bind(username)
        .first();
      if (existing) return json({ error: "Username already exists" }, 409);

      const createdAt = nowIso();
      const hash = await hashPassword(password);
      const result = await env.DB
        .prepare("INSERT INTO admins (username, password_hash, role_id, is_active, created_at) VALUES (?, ?, ?, 1, ?)")
        .bind(username, hash, roleId, createdAt)
        .run();
      return json({
        success: true,
        user: sanitizeUser({
          id: Number(result.meta?.last_row_id),
          username,
          role_id: roleId,
          is_active: 1,
          created_at: createdAt,
          last_login: null
        })
      }, 201);
    }

    if (method === "PATCH" || method === "PUT") {
      const body = await readJsonBody(request);
      const id = Number(body.id);
      if (!id) return json({ error: "Missing user id" }, 400);

      const existing = await env.DB.prepare("SELECT * FROM admins WHERE id=?").bind(id).first();
      if (!existing) return json({ error: "Admin user not found" }, 404);

      const roleId = body.role_id != null ? Number(body.role_id) : existing.role_id || 1;
      const isActive = body.is_active != null ? Number(body.is_active) : existing.is_active;

      await env.DB.prepare("UPDATE admins SET role_id=?, is_active=? WHERE id=?").bind(roleId, isActive, id).run();
      return json({ success: true });
    }

    if (method === "DELETE") {
      const id = Number(url.searchParams.get("id"));
      if (!id) return json({ error: "Missing user id" }, 400);
      if (auth.user.id === id) return json({ error: "You cannot delete your own account" }, 400);

      const total = await countAdmins(env.DB);
      if (total <= 1) return json({ error: "Cannot delete the last admin account" }, 400);

      const existing = await env.DB.prepare("SELECT id FROM admins WHERE id=?").bind(id).first();
      if (!existing) return json({ error: "Admin user not found" }, 404);

      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(id).run();
      await env.DB.prepare("DELETE FROM admins WHERE id=?").bind(id).run();
      return json({ success: true });
    }
  }

  if (method === "POST" && pathname === "/api/auth/change-password") {
    const auth = await requireAuth(request, env.DB);
    if (!auth) return json({ error: "Unauthorized" }, 401);

    const body = await readJsonBody(request);
    const currentPassword = String(body.currentPassword || "");
    const newPassword = String(body.newPassword || "");

    if (!currentPassword || !newPassword) return json({ error: "Current and new password are required" }, 400);
    if (newPassword.length < 6) return json({ error: "New password must be at least 6 characters" }, 400);
    if (!(await verifyPassword(currentPassword, auth.rawAdmin.password_hash))) return json({ error: "Current password is incorrect" }, 400);

    const newHash = await hashPassword(newPassword);
    await env.DB.prepare("UPDATE admins SET password_hash=? WHERE id=?").bind(newHash, auth.user.id).run();
    return json({ success: true });
  }

  return json({ error: "Route not found" }, 404);
}

async function proxyToBackend(request, env, url) {
  const backendOrigin = String(env.BACKEND_ORIGIN || "").replace(/\/+$/, "");
  if (!backendOrigin) {
    return json({ error: "BACKEND_ORIGIN is not configured for API proxy." }, 500);
  }

  const target = new URL(url.pathname + url.search, backendOrigin);
  const headers = new Headers(request.headers);
  headers.delete("host");

  const proxyReq = new Request(target.toString(), {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    redirect: "manual"
  });

  return fetch(proxyReq);
}

async function requireAuth(request, db) {
  const authHeader = request.headers.get("authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  const row = await db
    .prepare(
      "SELECT s.token, s.expires_at, a.id, a.username, a.password_hash, a.role_id, a.is_active, a.created_at, a.last_login " +
      "FROM sessions s JOIN admins a ON a.id = s.user_id WHERE s.token=? LIMIT 1"
    )
    .bind(token)
    .first();
  if (!row) return null;

  if (new Date(row.expires_at).getTime() <= Date.now() || row.is_active === 0) {
    await db.prepare("DELETE FROM sessions WHERE token=?").bind(token).run();
    return null;
  }

  const user = sanitizeUser(row);
  return { user, rawAdmin: row, token };
}

function sanitizeUser(row) {
  const roleId = Number(row.role_id || 1);
  const roleName = roleId === 1 ? "Owner" : "Admin";
  return {
    id: Number(row.id),
    username: row.username,
    role_id: roleId,
    role_name: roleName,
    roleId,
    roleName,
    is_active: Number(row.is_active ?? 1),
    created_at: row.created_at || null,
    last_login: row.last_login || null,
    permissions: DEFAULT_PERMISSIONS
  };
}

async function countAdmins(db) {
  const row = await db.prepare("SELECT COUNT(*) AS count FROM admins").first();
  return Number(row?.count || 0);
}

async function cleanupExpiredSessions(db) {
  await db.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(nowIso()).run();
}

async function ensureSchema(db) {
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS admins (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "username TEXT NOT NULL UNIQUE, " +
      "password_hash TEXT NOT NULL, " +
      "role_id INTEGER NOT NULL DEFAULT 1, " +
      "is_active INTEGER NOT NULL DEFAULT 1, " +
      "created_at TEXT NOT NULL, " +
      "last_login TEXT" +
    ")"
  ).run();

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS sessions (" +
      "token TEXT PRIMARY KEY, " +
      "user_id INTEGER NOT NULL, " +
      "created_at TEXT NOT NULL, " +
      "expires_at TEXT NOT NULL, " +
      "FOREIGN KEY(user_id) REFERENCES admins(id) ON DELETE CASCADE" +
    ")"
  ).run();

  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)").run();
}

async function readJsonBody(request) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) return {};
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function nowIso() {
  return new Date().toISOString();
}

function randomHex(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str);
}

function base64ToBytes(b64) {
  const str = atob(b64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

async function pbkdf2(password, saltBytes, iterations = 210000, length = 32) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations
    },
    keyMaterial,
    length * 8
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const iterations = 210000;
  const hash = await pbkdf2(password, salt, iterations, 32);
  return `pbkdf2$${iterations}$${bytesToBase64(salt)}$${bytesToBase64(hash)}`;
}

async function verifyPassword(password, stored) {
  const [scheme, iterRaw, saltB64, hashB64] = String(stored || "").split("$");
  if (scheme !== "pbkdf2" || !iterRaw || !saltB64 || !hashB64) return false;

  const iterations = Number(iterRaw);
  if (!Number.isFinite(iterations) || iterations <= 0) return false;

  const salt = base64ToBytes(saltB64);
  const expected = base64ToBytes(hashB64);
  const actual = await pbkdf2(password, salt, iterations, expected.length);

  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}
