const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14;
const PASSWORD_PBKDF2_ITERATIONS = 60000;

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
    try {
      const url = new URL(request.url);

      // Admin clean URLs without redirect chains
      const adminRouteMap = {
        "/admin": "/admin/index.html",
        "/admin/": "/admin/index.html",
        "/admin/login": "/admin/login.html",
        "/admin/login/": "/admin/login.html",
        "/admin/setup": "/admin/setup.html",
        "/admin/setup/": "/admin/setup.html"
      };
      if (adminRouteMap[url.pathname]) {
        const rewritten = new URL(request.url);
        rewritten.pathname = adminRouteMap[url.pathname];
        return env.ASSETS.fetch(new Request(rewritten.toString(), request));
      }

      if (url.pathname.startsWith("/api/auth/")) {
        return handleAuth(request, env, url);
      }

      if (
        url.pathname === "/api/bookings" ||
        url.pathname === "/api/quotes" ||
        url.pathname === "/api/schedule" ||
        url.pathname === "/api/contacts" ||
        url.pathname === "/api/customers"
      ) {
        return handleCoreData(request, env, url);
      }

      if (url.pathname.startsWith("/api/")) {
        return proxyToBackend(request, env, url);
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      return json({ error: "Worker exception", detail: String(error?.message || error) }, 500);
    }
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

async function handleCoreData(request, env, url) {
  if (!env.DB) {
    return json({ error: "D1 database binding `DB` is not configured." }, 500);
  }
  await ensureSchema(env.DB);
  await cleanupExpiredSessions(env.DB);

  const method = request.method;
  const pathname = url.pathname;

  if (pathname === "/api/bookings" && method === "POST") {
    const input = await readJsonBody(request);
    const quote = buildQuoteFromInput(input);

    const quoteResult = await env.DB
      .prepare(
        "INSERT INTO quotes (name, phone, email, status, preferred_datetime, issue_description, service_type, equipment, group_size, address, admin_notes, callback_date, created_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .bind(
        quote.name,
        quote.phone,
        quote.email,
        quote.status,
        quote.preferred_datetime,
        quote.issue_description,
        quote.service_type,
        quote.equipment,
        quote.group_size,
        quote.address,
        null,
        null,
        quote.created_at
      )
      .run();
    quote.id = Number(quoteResult.meta?.last_row_id);

    const customer = await upsertCustomerFromLead(env.DB, quote);
    const job = await createScheduleJobFromBooking(env.DB, quote, customer, input);

    return json({ success: true, quote, customer, job }, 201);
  }

  if (pathname === "/api/quotes") {
    if (method === "POST") {
      const input = await readJsonBody(request);
      const quote = buildQuoteFromInput(input);
      const result = await env.DB
        .prepare(
          "INSERT INTO quotes (name, phone, email, status, preferred_datetime, issue_description, service_type, equipment, group_size, address, admin_notes, callback_date, created_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(
          quote.name,
          quote.phone,
          quote.email,
          quote.status,
          quote.preferred_datetime,
          quote.issue_description,
          quote.service_type,
          quote.equipment,
          quote.group_size,
          quote.address,
          null,
          null,
          quote.created_at
        )
        .run();
      quote.id = Number(result.meta?.last_row_id);

      // Keep booking-style quote creation in sync with contacts + schedule.
      const customer = await upsertCustomerFromLead(env.DB, quote);
      const [bookingDate, bookingTime] = splitPreferredDatetime(quote.preferred_datetime);
      if (bookingDate) {
        const jobInput = { date: bookingDate, time: bookingTime || "09:00", service_type: quote.service_type };
        await createScheduleJobFromBooking(env.DB, quote, customer, jobInput);
      }
      return json({ success: true, quote }, 201);
    }

    const auth = await requireAuth(request, env.DB);
    if (!auth) return json({ error: "Unauthorized" }, 401);

    if (method === "GET") {
      const status = url.searchParams.get("status");
      const limit = Math.min(Number(url.searchParams.get("limit") || 200), 500);
      let sql =
        "SELECT id, name, phone, email, status, preferred_datetime, issue_description, service_type, equipment, group_size, address, admin_notes, callback_date, created_at " +
        "FROM quotes";
      const bind = [];
      if (status) {
        sql += " WHERE status = ?";
        bind.push(status);
      }
      sql += " ORDER BY id DESC LIMIT ?";
      bind.push(limit);

      const rows = await env.DB.prepare(sql).bind(...bind).all();
      return json({ quotes: (rows.results || []).map(normalizeQuoteRow) });
    }

    if (method === "PATCH" || method === "PUT") {
      const body = await readJsonBody(request);
      const id = Number(body.id || url.searchParams.get("id"));
      if (!id) return json({ error: "Missing quote id" }, 400);

      const current = await env.DB.prepare("SELECT * FROM quotes WHERE id=?").bind(id).first();
      if (!current) return json({ error: "Quote not found" }, 404);

      const status = body.status != null ? String(body.status) : current.status;
      const adminNotes = body.admin_notes != null ? String(body.admin_notes) : current.admin_notes;
      const callbackDate = body.callback_date != null ? String(body.callback_date) : current.callback_date;

      await env.DB
        .prepare("UPDATE quotes SET status=?, admin_notes=?, callback_date=? WHERE id=?")
        .bind(status, adminNotes, callbackDate, id)
        .run();

      return json({ success: true });
    }
  }

  if (pathname === "/api/schedule") {
    const auth = await requireAuth(request, env.DB);
    if (!auth) return json({ error: "Unauthorized" }, 401);

    if (method === "GET") {
      const start = normalizeDateInput(url.searchParams.get("start"));
      const end = normalizeDateInput(url.searchParams.get("end"));
      const limit = Math.min(Number(url.searchParams.get("limit") || 200), 500);

      let sql =
        "SELECT job_id, entry_type, contact_name, contact_phone, title, scheduled_date, scheduled_time, time_window_end, duration_minutes, address, travel_time, description, quote_id, customer_id, status, created_at, updated_at " +
        "FROM schedule_jobs";
      const bind = [];
      if (start && end) {
        sql += " WHERE scheduled_date >= ? AND scheduled_date <= ?";
        bind.push(start, end);
      }
      sql += " ORDER BY scheduled_date ASC, COALESCE(scheduled_time, '99:99') ASC LIMIT ?";
      bind.push(limit);

      const rows = await env.DB.prepare(sql).bind(...bind).all();
      return json({ success: true, jobs: rows.results || [] });
    }

    if (method === "POST") {
      const body = await readJsonBody(request);
      const payload = normalizeSchedulePayload(body);

      const jobId = randomHex(16);
      const now = nowIso();
      await env.DB
        .prepare(
          "INSERT INTO schedule_jobs (job_id, entry_type, contact_name, contact_phone, title, scheduled_date, scheduled_time, time_window_end, duration_minutes, address, travel_time, description, quote_id, customer_id, status, created_at, updated_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(
          jobId,
          payload.entry_type,
          payload.contact_name,
          payload.contact_phone,
          payload.title,
          payload.scheduled_date,
          payload.scheduled_time,
          payload.time_window_end,
          payload.duration_minutes,
          payload.address,
          payload.travel_time,
          payload.description,
          payload.quote_id,
          payload.customer_id,
          payload.status,
          now,
          now
        )
        .run();

      return json({ success: true, job: { job_id: jobId, ...payload, created_at: now, updated_at: now } }, 201);
    }

    if (method === "PATCH") {
      const body = await readJsonBody(request);
      const jobId = String(body.job_id || "").trim();
      if (!jobId) return json({ error: "Missing job_id" }, 400);

      const current = await env.DB.prepare("SELECT * FROM schedule_jobs WHERE job_id=?").bind(jobId).first();
      if (!current) return json({ error: "Job not found" }, 404);

      const payload = normalizeSchedulePayload({ ...current, ...body });
      const now = nowIso();

      await env.DB
        .prepare(
          "UPDATE schedule_jobs SET entry_type=?, contact_name=?, contact_phone=?, title=?, scheduled_date=?, scheduled_time=?, time_window_end=?, duration_minutes=?, address=?, travel_time=?, description=?, quote_id=?, customer_id=?, status=?, updated_at=? WHERE job_id=?"
        )
        .bind(
          payload.entry_type,
          payload.contact_name,
          payload.contact_phone,
          payload.title,
          payload.scheduled_date,
          payload.scheduled_time,
          payload.time_window_end,
          payload.duration_minutes,
          payload.address,
          payload.travel_time,
          payload.description,
          payload.quote_id,
          payload.customer_id,
          payload.status,
          now,
          jobId
        )
        .run();

      return json({ success: true });
    }

    if (method === "DELETE") {
      const jobId = String(url.searchParams.get("id") || "").trim();
      if (!jobId) return json({ error: "Missing id" }, 400);
      await env.DB.prepare("DELETE FROM schedule_jobs WHERE job_id=?").bind(jobId).run();
      return json({ success: true });
    }
  }

  if (pathname === "/api/customers") {
    const auth = await requireAuth(request, env.DB);
    if (!auth) return json({ error: "Unauthorized" }, 401);

    if (method === "GET") {
      const limit = Math.min(Number(url.searchParams.get("limit") || 200), 500);
      const rows = await env.DB
        .prepare(
          "SELECT customer_id, first_name, last_name, phone_e164, email, address, city, state, zip, notes, created_at FROM customers ORDER BY customer_id DESC LIMIT ?"
        )
        .bind(limit)
        .all();
      return json({ customers: rows.results || [] });
    }

    if (method === "POST") {
      const body = await readJsonBody(request);
      const firstName = String(body.first_name || body.name || "").trim() || "Customer";
      const lastName = String(body.last_name || "").trim() || null;
      const phone = String(body.phone_e164 || body.phone || "").trim() || null;
      const email = String(body.email || "").trim().toLowerCase() || null;
      const address = String(body.address || "").trim() || null;
      const city = String(body.city || "").trim() || null;
      const state = String(body.state || "").trim() || null;
      const zip = String(body.zip || "").trim() || null;
      const notes = String(body.notes || "").trim() || null;
      const createdAt = nowIso();

      const result = await env.DB
        .prepare(
          "INSERT INTO customers (first_name, last_name, phone_e164, email, address, city, state, zip, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(firstName, lastName, phone, email, address, city, state, zip, notes, createdAt)
        .run();

      const customer = {
        customer_id: Number(result.meta?.last_row_id),
        first_name: firstName,
        last_name: lastName,
        phone_e164: phone,
        email,
        address,
        city,
        state,
        zip,
        notes,
        created_at: createdAt
      };

      return json({ success: true, customer }, 201);
    }
  }

  if (pathname === "/api/contacts" && method === "GET") {
    const auth = await requireAuth(request, env.DB);
    if (!auth) return json({ error: "Unauthorized" }, 401);

    const type = String(url.searchParams.get("type") || "all");
    const status = String(url.searchParams.get("status") || "");
    const search = String(url.searchParams.get("search") || "").trim().toLowerCase();
    const limit = Math.min(Number(url.searchParams.get("limit") || 200), 500);

    const contacts = [];

    if (type === "all" || type === "lead") {
      let sql =
        "SELECT id, name, phone, email, address, status, created_at FROM quotes " +
        (status ? "WHERE status = ? " : "") +
        "ORDER BY id DESC LIMIT ?";
      const bind = status ? [status, limit] : [limit];
      const rows = await env.DB.prepare(sql).bind(...bind).all();
      (rows.results || []).forEach((q) => {
        contacts.push({
          contact_id: `q-${q.id}`,
          quote_id: q.id,
          type: "lead",
          contact_type: "lead",
          name: q.name || "Unknown",
          phone: q.phone || null,
          email: q.email || null,
          address: q.address || null,
          city: null,
          state: null,
          status: q.status || "new",
          created_at: q.created_at || nowIso()
        });
      });
    }

    if (type === "all" || type === "customer") {
      const rows = await env.DB
        .prepare(
          "SELECT customer_id, first_name, last_name, phone_e164, email, address, city, state, created_at FROM customers ORDER BY customer_id DESC LIMIT ?"
        )
        .bind(limit)
        .all();
      (rows.results || []).forEach((c) => {
        const name = [c.first_name, c.last_name].filter(Boolean).join(" ").trim() || "Customer";
        contacts.push({
          contact_id: `c-${c.customer_id}`,
          customer_id: c.customer_id,
          type: "customer",
          contact_type: "customer",
          name,
          phone: c.phone_e164 || null,
          email: c.email || null,
          address: c.address || null,
          city: c.city || null,
          state: c.state || null,
          status: "customer",
          created_at: c.created_at || nowIso()
        });
      });
    }

    let filtered = contacts;
    if (search) {
      filtered = contacts.filter((c) =>
        [c.name, c.phone, c.email, c.address, c.city, c.state].filter(Boolean).join(" ").toLowerCase().includes(search)
      );
    }

    filtered.sort((a, b) => new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime());
    return json({ contacts: filtered.slice(0, limit) });
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

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS quotes (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "name TEXT, " +
      "phone TEXT, " +
      "email TEXT, " +
      "status TEXT, " +
      "preferred_datetime TEXT, " +
      "issue_description TEXT, " +
      "service_type TEXT, " +
      "equipment TEXT, " +
      "group_size INTEGER, " +
      "address TEXT, " +
      "admin_notes TEXT, " +
      "callback_date TEXT, " +
      "created_at TEXT" +
    ")"
  ).run();

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS customers (" +
      "customer_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "first_name TEXT, " +
      "last_name TEXT, " +
      "phone_e164 TEXT, " +
      "email TEXT, " +
      "address TEXT, " +
      "city TEXT, " +
      "state TEXT, " +
      "zip TEXT, " +
      "notes TEXT, " +
      "created_at TEXT" +
    ")"
  ).run();

  await db.prepare(
    "CREATE TABLE IF NOT EXISTS schedule_jobs (" +
      "job_id TEXT PRIMARY KEY, " +
      "entry_type TEXT, " +
      "contact_name TEXT, " +
      "contact_phone TEXT, " +
      "title TEXT, " +
      "scheduled_date TEXT, " +
      "scheduled_time TEXT, " +
      "time_window_end TEXT, " +
      "duration_minutes INTEGER, " +
      "address TEXT, " +
      "travel_time INTEGER, " +
      "description TEXT, " +
      "quote_id INTEGER, " +
      "customer_id INTEGER, " +
      "status TEXT, " +
      "created_at TEXT, " +
      "updated_at TEXT" +
    ")"
  ).run();

  await db.prepare("CREATE INDEX IF NOT EXISTS idx_quotes_status ON quotes(status)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_quotes_created_at ON quotes(created_at)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_schedule_date_time ON schedule_jobs(scheduled_date, scheduled_time)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email)").run();

  await ensureAdminColumns(db);
}

async function ensureAdminColumns(db) {
  const info = await db.prepare("PRAGMA table_info(admins)").all();
  const cols = new Set((info.results || []).map((c) => String(c.name || "").toLowerCase()));

  if (!cols.has("role_id")) {
    await db.prepare("ALTER TABLE admins ADD COLUMN role_id INTEGER NOT NULL DEFAULT 1").run();
  }
  if (!cols.has("is_active")) {
    await db.prepare("ALTER TABLE admins ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1").run();
  }
  if (!cols.has("created_at")) {
    await db.prepare("ALTER TABLE admins ADD COLUMN created_at TEXT").run();
  }
  if (!cols.has("last_login")) {
    await db.prepare("ALTER TABLE admins ADD COLUMN last_login TEXT").run();
  }
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
  const hash = await pbkdf2(password, salt, PASSWORD_PBKDF2_ITERATIONS, 32);
  return `pbkdf2$${PASSWORD_PBKDF2_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(hash)}`;
}

async function verifyPassword(password, stored) {
  try {
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
  } catch {
    return false;
  }
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

function normalizeDateInput(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;

  const us = raw.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (us) {
    const mm = String(Number(us[1])).padStart(2, "0");
    const dd = String(Number(us[2])).padStart(2, "0");
    return `${us[3]}-${mm}-${dd}`;
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return null;
  return `${parsed.getFullYear()}-${String(parsed.getMonth() + 1).padStart(2, "0")}-${String(parsed.getDate()).padStart(2, "0")}`;
}

function parseTimeTo24(timeValue) {
  if (!timeValue) return null;
  const raw = String(timeValue).trim();
  if (!raw) return null;
  if (/^\d{2}:\d{2}$/.test(raw)) return raw;
  const m = raw.match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (!m) return null;
  let hour = Number(m[1]);
  const minute = Number(m[2]);
  const ampm = m[3].toUpperCase();
  if (ampm === "PM" && hour < 12) hour += 12;
  if (ampm === "AM" && hour === 12) hour = 0;
  return `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
}

function buildQuoteFromInput(input) {
  const name =
    String(input.name || "").trim() ||
    [input.first_name, input.last_name].filter(Boolean).join(" ").trim();
  const preferredDate = normalizeDateInput(String(input.date || input.preferred_date || "").trim());
  const preferredTimeRaw = String(input.time || input.preferred_time || "").trim();
  const preferredDatetime = [preferredDate, preferredTimeRaw].filter(Boolean).join(" ").trim() || null;

  return {
    name,
    phone: String(input.phone || "").trim(),
    email: String(input.email || "").trim(),
    status: preferredDate ? "scheduled" : "new",
    preferred_datetime: preferredDatetime,
    issue_description: String(input.special_requests || input.issue_description || "").trim() || null,
    service_type: String(input.service_type || "").trim() || null,
    equipment: String(input.equipment || "").trim() || null,
    group_size: Number(input.group_size) || null,
    address: String(input.address || "").trim() || null,
    created_at: nowIso()
  };
}

function normalizeQuoteRow(q) {
  return {
    id: q.id,
    name: q.name,
    phone: q.phone,
    email: q.email,
    status: q.status,
    preferred_datetime: q.preferred_datetime,
    issue_description: q.issue_description,
    service_type: q.service_type,
    equipment: q.equipment,
    group_size: q.group_size,
    address: q.address,
    admin_notes: q.admin_notes,
    callback_date: q.callback_date,
    created_at: q.created_at
  };
}

function splitPreferredDatetime(value) {
  const raw = String(value || "").trim();
  if (!raw) return [null, null];
  const parts = raw.split(/\s+/);
  const date = normalizeDateInput(parts[0]);
  if (!date) return [null, null];
  const timeRaw = parts.slice(1).join(" ");
  const time = parseTimeTo24(timeRaw) || parseTimeTo24(parts[1]) || null;
  return [date, time];
}

async function upsertCustomerFromLead(db, lead) {
  const leadEmail = String(lead.email || "").trim().toLowerCase();
  const leadPhoneDigits = String(lead.phone || "").replace(/\D/g, "");

  if (leadEmail || leadPhoneDigits) {
    const existing = await db
      .prepare(
        "SELECT * FROM customers WHERE " +
        "(? <> '' AND lower(COALESCE(email,'')) = ?) OR " +
        "(? <> '' AND REPLACE(REPLACE(REPLACE(REPLACE(COALESCE(phone_e164,''),'+',''),'-',''),'(',''),')','') = ?) " +
        "LIMIT 1"
      )
      .bind(leadEmail, leadEmail, leadPhoneDigits, leadPhoneDigits)
      .first();
    if (existing) return existing;
  }

  const nameParts = String(lead.name || "").trim().split(/\s+/);
  const firstName = nameParts.shift() || "Customer";
  const lastName = nameParts.join(" ") || null;
  const phoneE164 = leadPhoneDigits ? (leadPhoneDigits.startsWith("1") ? `+${leadPhoneDigits}` : `+1${leadPhoneDigits}`) : null;
  const createdAt = nowIso();

  const result = await db
    .prepare(
      "INSERT INTO customers (first_name, last_name, phone_e164, email, address, city, state, zip, notes, created_at) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)"
    )
    .bind(firstName, lastName, phoneE164, leadEmail || null, lead.address || null, createdAt)
    .run();

  return {
    customer_id: Number(result.meta?.last_row_id),
    first_name: firstName,
    last_name: lastName,
    phone_e164: phoneE164,
    email: leadEmail || null,
    address: lead.address || null,
    created_at: createdAt
  };
}

async function createScheduleJobFromBooking(db, quote, customer, input) {
  const scheduledDate = normalizeDateInput(input.date);
  if (!scheduledDate) return null;

  const time24 = parseTimeTo24(input.time) || "09:00";
  const serviceLabel = String(input.service_type || "").trim() || "Booking";
  const title = `${serviceLabel} - ${quote.name}`;
  const bits = [];
  if (input.group_size) bits.push(`Group Size: ${input.group_size}`);
  if (input.equipment) bits.push(`Equipment: ${input.equipment}`);
  if (input.special_requests) bits.push(`Requests: ${input.special_requests}`);

  const job = {
    job_id: randomHex(16),
    entry_type: "diagnostic",
    contact_name: quote.name,
    contact_phone: quote.phone || null,
    title,
    scheduled_date: scheduledDate,
    scheduled_time: time24,
    time_window_end: null,
    duration_minutes: 120,
    address: quote.address || null,
    travel_time: null,
    description: bits.join(" | ") || null,
    quote_id: quote.id,
    customer_id: customer?.customer_id || null,
    status: "scheduled",
    created_at: nowIso(),
    updated_at: nowIso()
  };

  await db
    .prepare(
      "INSERT INTO schedule_jobs (job_id, entry_type, contact_name, contact_phone, title, scheduled_date, scheduled_time, time_window_end, duration_minutes, address, travel_time, description, quote_id, customer_id, status, created_at, updated_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(
      job.job_id,
      job.entry_type,
      job.contact_name,
      job.contact_phone,
      job.title,
      job.scheduled_date,
      job.scheduled_time,
      job.time_window_end,
      job.duration_minutes,
      job.address,
      job.travel_time,
      job.description,
      job.quote_id,
      job.customer_id,
      job.status,
      job.created_at,
      job.updated_at
    )
    .run();

  return job;
}

function normalizeSchedulePayload(input) {
  const entryType = String(input.entry_type || "diagnostic");
  const safeType = entryType === "roadside" ? "roadside" : "diagnostic";
  const contactName = String(input.contact_name || "").trim() || null;
  const title = String(input.title || "").trim() || (safeType === "roadside" ? "Group Session" : "Private Session");

  return {
    entry_type: safeType,
    contact_name: contactName,
    contact_phone: String(input.contact_phone || "").trim() || null,
    title,
    scheduled_date: normalizeDateInput(input.scheduled_date) || normalizeDateInput(new Date().toISOString().slice(0, 10)),
    scheduled_time: parseTimeTo24(input.scheduled_time) || "09:00",
    time_window_end: parseTimeTo24(input.time_window_end) || null,
    duration_minutes: Number(input.duration_minutes) || 120,
    address: input.address ? String(input.address).trim() : null,
    travel_time: input.travel_time != null && input.travel_time !== "" ? Number(input.travel_time) : null,
    description: String(input.description || "").trim() || null,
    quote_id: input.quote_id != null && input.quote_id !== "" ? Number(input.quote_id) : null,
    customer_id: input.customer_id != null && input.customer_id !== "" ? Number(input.customer_id) : null,
    status: String(input.status || "scheduled")
  };
}
