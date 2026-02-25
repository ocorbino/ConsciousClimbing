const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const querystring = require('querystring');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const ROOT_DIR = __dirname;
const DATA_DIR = path.join(ROOT_DIR, 'data');
const STORE_PATH = path.join(DATA_DIR, 'store.json');
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14;

const defaultStore = {
  admins: [],
  sessions: [],
  settingsRecipients: [],
  businessSettings: {
    phone: '',
    paypal_username: '',
    venmo_username: '',
    cashapp_tag: '',
    tax_rate: 0,
    parts_markup_pct: 30,
    cashapp_enabled: 'true',
    venmo_enabled: 'false',
    paypal_enabled: 'false',
    ical_feed_token: ''
  },
  quotes: [],
  customers: [],
  scheduleJobs: [],
  receipts: [],
  invoices: [],
  media: [],
  counters: { invoiceNumber: 1000 }
};

const defaultRole = {
  id: 1,
  name: 'Owner',
  permissions: {
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
  }
};

function ensureStoreFile() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(STORE_PATH)) fs.writeFileSync(STORE_PATH, JSON.stringify(defaultStore, null, 2));
}

function readStore() {
  ensureStoreFile();
  try {
    const parsed = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
    const store = {
      ...defaultStore,
      ...parsed,
      counters: { ...defaultStore.counters, ...(parsed.counters || {}) },
      businessSettings: { ...defaultStore.businessSettings, ...(parsed.businessSettings || {}) }
    };

    if (!store.businessSettings.ical_feed_token) {
      store.businessSettings.ical_feed_token = randomToken().slice(0, 24);
    }

    return store;
  } catch {
    return JSON.parse(JSON.stringify(defaultStore));
  }
}

function writeStore(store) {
  ensureStoreFile();
  fs.writeFileSync(STORE_PATH, JSON.stringify(store, null, 2));
}

function nowIso() {
  return new Date().toISOString();
}

function nextNumericId(list) {
  return list.reduce((m, row) => Math.max(m, Number(row.id) || 0), 0) + 1;
}

function randomToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split(':');
  if (!salt || !hash) return false;
  const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(testHash, 'hex'));
}

function sanitizeAdmin(admin) {
  return {
    id: admin.id,
    username: admin.username,
    last_login: admin.last_login || null,
    created_at: admin.created_at || null
  };
}

function cleanupExpiredSessions(store) {
  const now = Date.now();
  store.sessions = (store.sessions || []).filter((s) => new Date(s.expires_at).getTime() > now);
}

function getBearerToken(req) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  return authHeader.slice(7).trim();
}

function findSessionWithUser(store, token) {
  cleanupExpiredSessions(store);
  const session = (store.sessions || []).find((s) => s.token === token);
  if (!session) return null;
  const user = (store.admins || []).find((u) => u.id === session.user_id);
  if (!user) return null;
  return { session, user };
}

function requireAuth(req, res) {
  const store = readStore();
  const token = getBearerToken(req);
  const auth = findSessionWithUser(store, token);
  writeStore(store);

  if (!auth) {
    sendJson(res, 401, { error: 'Unauthorized' });
    return null;
  }

  return auth;
}

function normalizeLineItems(lineItems) {
  return (Array.isArray(lineItems) ? lineItems : [])
    .map((item) => {
      const quantity = Number(item.quantity) > 0 ? Number(item.quantity) : 1;
      const unitPriceRaw = item.unit_price != null ? item.unit_price : item.price;
      const unitPrice = Number(unitPriceRaw) >= 0 ? Number(unitPriceRaw) : 0;
      return {
        description: String(item.description || 'Item').trim(),
        quantity,
        unit_price: unitPrice,
        price: unitPrice,
        photo_url: item.photo_url || null
      };
    })
    .filter((item) => item.description && item.unit_price >= 0);
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
  if (ampm === 'PM' && hour < 12) hour += 12;
  if (ampm === 'AM' && hour === 12) hour = 0;
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function normalizeDateInput(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;

  // Already YYYY-MM-DD
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) return raw;

  // MM/DD/YYYY
  const us = raw.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (us) {
    const mm = String(Number(us[1])).padStart(2, '0');
    const dd = String(Number(us[2])).padStart(2, '0');
    const yyyy = us[3];
    return `${yyyy}-${mm}-${dd}`;
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return null;
  const yyyy = parsed.getFullYear();
  const mm = String(parsed.getMonth() + 1).padStart(2, '0');
  const dd = String(parsed.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

function dateToMs(value) {
  const normalized = normalizeDateInput(value);
  if (!normalized) return null;
  const date = new Date(`${normalized}T00:00:00`);
  if (Number.isNaN(date.getTime())) return null;
  return date.getTime();
}

function upsertCustomerFromLead(store, lead) {
  const leadEmail = String(lead.email || '').trim().toLowerCase();
  const leadPhoneDigits = String(lead.phone || '').replace(/\D/g, '');

  let customer = store.customers.find((c) => {
    const emailMatch = leadEmail && String(c.email || '').trim().toLowerCase() === leadEmail;
    const phoneMatch = leadPhoneDigits && String(c.phone_e164 || '').replace(/\D/g, '') === leadPhoneDigits;
    return emailMatch || phoneMatch;
  });

  if (customer) return customer;

  const nameParts = String(lead.name || '').trim().split(/\s+/);
  const firstName = nameParts.shift() || 'Customer';
  const lastName = nameParts.join(' ') || null;

  customer = {
    id: nextNumericId(store.customers),
    customer_id: nextNumericId(store.customers),
    first_name: firstName,
    last_name: lastName,
    phone_e164: leadPhoneDigits ? (leadPhoneDigits.startsWith('1') ? `+${leadPhoneDigits}` : `+1${leadPhoneDigits}`) : null,
    email: leadEmail || null,
    address: lead.address || null,
    city: null,
    state: null,
    zip: null,
    notes: null,
    created_at: nowIso()
  };

  store.customers.push(customer);
  return customer;
}

function createScheduleJobFromBooking(store, quote, customer, input) {
  const scheduledDate = normalizeDateInput(input.date);
  if (!scheduledDate) return null;

  const time24 = parseTimeTo24(input.time) || '09:00';
  const serviceLabel = String(input.service_type || '').trim() || 'Booking';
  const title = `${serviceLabel} - ${quote.name}`;
  const descriptionBits = [];
  if (input.group_size) descriptionBits.push(`Group Size: ${input.group_size}`);
  if (input.equipment) descriptionBits.push(`Equipment: ${input.equipment}`);
  if (input.special_requests) descriptionBits.push(`Requests: ${input.special_requests}`);

  const job = {
    job_id: crypto.randomUUID(),
    entry_type: 'job',
    contact_name: quote.name,
    contact_phone: quote.phone || null,
    title,
    scheduled_date: scheduledDate,
    scheduled_time: time24,
    time_window_end: null,
    duration_minutes: 120,
    address: quote.address || null,
    travel_time: null,
    description: descriptionBits.join(' | ') || null,
    quote_id: quote.id,
    customer_id: customer?.customer_id || customer?.id || null,
    status: 'scheduled',
    created_at: nowIso(),
    updated_at: nowIso()
  };

  store.scheduleJobs.unshift(job);
  return job;
}

function buildQuoteFromInput(store, input) {
  const name =
    String(input.name || '').trim() ||
    [input.first_name, input.last_name].filter(Boolean).join(' ').trim();

  const phone = String(input.phone || '').trim();
  const email = String(input.email || '').trim();
  const preferredDate = normalizeDateInput(String(input.date || input.preferred_date || '').trim());
  const preferredTimeRaw = String(input.time || input.preferred_time || '').trim();
  const preferredTime = parseTimeTo24(preferredTimeRaw) || preferredTimeRaw || null;
  const preferredDatetime = [preferredDate, preferredTimeRaw].filter(Boolean).join(' ').trim() || null;

  return {
    id: nextNumericId(store.quotes),
    name,
    phone,
    email,
    status: preferredDate ? 'scheduled' : 'new',
    preferred_datetime: preferredDatetime,
    issue_description: String(input.special_requests || input.issue_description || '').trim() || null,
    service_type: String(input.service_type || '').trim() || null,
    equipment: String(input.equipment || '').trim() || null,
    group_size: Number(input.group_size) || null,
    vehicle_year: input.vehicle_year || null,
    vehicle_make: input.vehicle_make || null,
    vehicle_model: input.vehicle_model || null,
    referral_source: 'booking_form',
    deals_opt_in: Boolean(input.deals_opt_in),
    address: input.address || null,
    photo_urls: JSON.stringify([]),
    created_at: nowIso(),
    _booking_date: preferredDate || null,
    _booking_time: preferredTime || null
  };
}

function toContactFromQuote(quote) {
  return {
    contact_id: `q-${quote.id}`,
    quote_id: quote.id,
    type: 'lead',
    contact_type: 'lead',
    name: quote.name || 'Unknown',
    phone: quote.phone || null,
    email: quote.email || null,
    address: quote.address || null,
    city: quote.city || null,
    state: quote.state || null,
    status: quote.status || 'new',
    created_at: quote.created_at || nowIso()
  };
}

function toContactFromCustomer(customer) {
  const fullName = [customer.first_name, customer.last_name].filter(Boolean).join(' ').trim() || 'Customer';
  return {
    contact_id: `c-${customer.customer_id || customer.id}`,
    customer_id: customer.customer_id || customer.id,
    type: 'customer',
    contact_type: 'customer',
    name: fullName,
    phone: customer.phone_e164 || null,
    email: customer.email || null,
    address: customer.address || null,
    city: customer.city || null,
    state: customer.state || null,
    status: 'customer',
    created_at: customer.created_at || nowIso()
  };
}

function calculateInvoiceAmounts(invoice) {
  const subtotal = (invoice.line_items || []).reduce((sum, item) => {
    return sum + (Number(item.quantity) || 0) * (Number(item.unit_price) || 0);
  }, 0);
  const taxAmount = Number(invoice.tax_amount) || 0;
  const total = invoice.total != null ? Number(invoice.total) : subtotal + taxAmount;
  return { subtotal, tax_amount: taxAmount, total };
}

function sendJson(res, status, data) {
  const body = Buffer.from(JSON.stringify(data));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function sendText(res, status, text, type = 'text/plain; charset=utf-8') {
  const body = Buffer.from(text);
  res.writeHead(status, {
    'Content-Type': type,
    'Content-Length': body.length
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 12 * 1024 * 1024) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const contentType = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();

      if (!raw) return resolve({});

      try {
        if (contentType === 'application/json') {
          return resolve(JSON.parse(raw));
        }
        if (contentType === 'application/x-www-form-urlencoded') {
          return resolve(querystring.parse(raw));
        }
        resolve({ raw });
      } catch (err) {
        reject(err);
      }
    });

    req.on('error', reject);
  });
}

async function handleApi(req, res, pathname, searchParams) {
  const method = req.method || 'GET';

  // Auth
  if (method === 'GET' && pathname === '/api/auth/setup') {
    const store = readStore();
    return sendJson(res, 200, { setupRequired: store.admins.length === 0 });
  }

  if (method === 'POST' && pathname === '/api/auth/setup') {
    const body = await readBody(req);
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    if (!username || !password) return sendJson(res, 400, { error: 'Username and password are required' });
    if (password.length < 6) return sendJson(res, 400, { error: 'Password must be at least 6 characters' });

    const store = readStore();
    if (store.admins.length > 0) return sendJson(res, 409, { error: 'Setup already completed' });

    const admin = {
      id: nextNumericId(store.admins),
      username,
      password_hash: hashPassword(password),
      created_at: nowIso(),
      last_login: null
    };
    store.admins.push(admin);
    writeStore(store);
    return sendJson(res, 201, { success: true, user: sanitizeAdmin(admin) });
  }

  if (method === 'POST' && pathname === '/api/auth/login') {
    const body = await readBody(req);
    const username = String(body.username || '').trim();
    const password = String(body.password || '');

    const store = readStore();
    const admin = store.admins.find((u) => u.username === username);
    if (!admin || !verifyPassword(password, admin.password_hash)) {
      return sendJson(res, 401, { error: 'Invalid username or password' });
    }

    admin.last_login = nowIso();
    cleanupExpiredSessions(store);

    const token = randomToken();
    const now = Date.now();
    store.sessions.push({
      token,
      user_id: admin.id,
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + SESSION_TTL_MS).toISOString()
    });

    writeStore(store);
    return sendJson(res, 200, { success: true, token, user: sanitizeAdmin(admin) });
  }

  if (method === 'GET' && pathname === '/api/auth/verify') {
    const store = readStore();
    const token = getBearerToken(req);
    const auth = findSessionWithUser(store, token);
    writeStore(store);
    if (!auth) return sendJson(res, 200, { valid: false });
    return sendJson(res, 200, { valid: true, user: sanitizeAdmin(auth.user) });
  }

  if (pathname === '/api/auth/users') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const store = readStore();
      return sendJson(res, 200, { users: store.admins.map(sanitizeAdmin) });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!username || password.length < 6) return sendJson(res, 400, { error: 'Username and a 6+ char password are required' });

      const store = readStore();
      if (store.admins.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
        return sendJson(res, 409, { error: 'Username already exists' });
      }

      const admin = {
        id: nextNumericId(store.admins),
        username,
        password_hash: hashPassword(password),
        created_at: nowIso(),
        last_login: null
      };
      store.admins.push(admin);
      writeStore(store);
      return sendJson(res, 201, { success: true, user: sanitizeAdmin(admin) });
    }

    if (method === 'DELETE') {
      const id = Number(searchParams.get('id'));
      if (!id) return sendJson(res, 400, { error: 'Missing user id' });

      const store = readStore();
      if (auth.user.id === id) return sendJson(res, 400, { error: 'You cannot delete your own account' });
      if (store.admins.length <= 1) return sendJson(res, 400, { error: 'Cannot delete the last admin account' });

      const before = store.admins.length;
      store.admins = store.admins.filter((u) => u.id !== id);
      store.sessions = store.sessions.filter((s) => s.user_id !== id);
      if (store.admins.length === before) return sendJson(res, 404, { error: 'Admin user not found' });

      writeStore(store);
      return sendJson(res, 200, { success: true });
    }

    if (method === 'PUT') {
      const body = await readBody(req);
      const id = Number(body.id);
      if (!id) return sendJson(res, 400, { error: 'Missing user id' });
      const store = readStore();
      const admin = store.admins.find((u) => u.id === id);
      if (!admin) return sendJson(res, 404, { error: 'Admin user not found' });
      admin.role_id = body.role_id != null ? Number(body.role_id) : admin.role_id || 1;
      writeStore(store);
      return sendJson(res, 200, { success: true, user: sanitizeAdmin(admin) });
    }
  }

  if (method === 'POST' && pathname === '/api/auth/change-password') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    const body = await readBody(req);
    const currentPassword = String(body.currentPassword || '');
    const newPassword = String(body.newPassword || '');

    const store = readStore();
    const user = store.admins.find((u) => u.id === auth.user.id);
    if (!user) return sendJson(res, 404, { error: 'Admin user not found' });

    if (!verifyPassword(currentPassword, user.password_hash)) return sendJson(res, 400, { error: 'Current password is incorrect' });
    if (newPassword.length < 6) return sendJson(res, 400, { error: 'New password must be at least 6 characters' });

    user.password_hash = hashPassword(newPassword);
    writeStore(store);
    return sendJson(res, 200, { success: true });
  }

  // Settings
  if (pathname === '/api/settings') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const store = readStore();
      return sendJson(res, 200, { recipients: store.settingsRecipients || [] });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      const email = String(body.email || '').trim().toLowerCase();
      const name = String(body.name || '').trim();

      if (!email || !email.includes('@')) return sendJson(res, 400, { error: 'Valid email is required' });

      const store = readStore();
      if (store.settingsRecipients.some((r) => r.email === email)) return sendJson(res, 409, { error: 'Email is already added' });

      const recipient = { id: nextNumericId(store.settingsRecipients), email, name: name || null, created_at: nowIso() };
      store.settingsRecipients.push(recipient);
      writeStore(store);
      return sendJson(res, 201, { success: true, recipient });
    }

    if (method === 'DELETE') {
      const id = Number(searchParams.get('id'));
      if (!id) return sendJson(res, 400, { error: 'Missing recipient id' });

      const store = readStore();
      const before = store.settingsRecipients.length;
      store.settingsRecipients = store.settingsRecipients.filter((r) => r.id !== id);
      if (store.settingsRecipients.length === before) return sendJson(res, 404, { error: 'Recipient not found' });

      writeStore(store);
      return sendJson(res, 200, { success: true });
    }
  }

  if (pathname === '/api/business-settings') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const store = readStore();
      return sendJson(res, 200, { settings: store.businessSettings || {} });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      const incoming = body.settings;
      if (!incoming || typeof incoming !== 'object') return sendJson(res, 400, { error: 'settings object is required' });

      const store = readStore();
      store.businessSettings = { ...store.businessSettings, ...incoming };
      writeStore(store);
      return sendJson(res, 200, { success: true, settings: store.businessSettings });
    }
  }

  // Bookings/quotes
  if (method === 'POST' && pathname === '/api/bookings') {
    const body = await readBody(req);
    const quoteInput = {
      ...body,
      referral_source: 'booking_form'
    };
    const store = readStore();
    const quote = buildQuoteFromInput(store, quoteInput);

    if (!quote.name || !quote.phone || !quote.email) {
      return sendText(res, 400, 'Missing required fields: first_name, last_name, phone, email');
    }

    store.quotes.unshift(quote);
    const customer = upsertCustomerFromLead(store, quote);
    const scheduleJob = createScheduleJobFromBooking(store, quote, customer, {
      date: quote._booking_date,
      time: quote._booking_time,
      service_type: quote.service_type,
      group_size: quote.group_size,
      equipment: quote.equipment,
      special_requests: quote.issue_description
    });
    delete quote._booking_date;
    delete quote._booking_time;
    writeStore(store);

    const accept = req.headers.accept || '';
    if (accept.includes('text/html')) {
      return sendText(
        res,
        200,
        `<!doctype html><html><head><meta charset="utf-8"><title>Booking Received</title></head><body style="font-family:sans-serif;padding:2rem;"><h1>Booking Request Received</h1><p>Thanks ${quote.name}. We received your request and will contact you shortly.</p><p><a href="/booking.html">Submit another request</a> | <a href="/">Back to home</a></p></body></html>`,
        'text/html; charset=utf-8'
      );
    }

    return sendJson(res, 201, { success: true, quote_id: quote.id, schedule_job_id: scheduleJob?.job_id || null });
  }

  // Public lead intake endpoint compatibility
  if (method === 'POST' && pathname === '/api/quotes') {
    const body = await readBody(req);
    const store = readStore();
    const quote = buildQuoteFromInput(store, body);

    if (!quote.name || !quote.phone || !quote.email) {
      return sendJson(res, 400, { error: 'name, phone, and email are required' });
    }

    store.quotes.unshift(quote);
    const customer = upsertCustomerFromLead(store, quote);
    const scheduleJob = createScheduleJobFromBooking(store, quote, customer, {
      date: quote._booking_date,
      time: quote._booking_time,
      service_type: quote.service_type,
      group_size: quote.group_size,
      equipment: quote.equipment,
      special_requests: quote.issue_description
    });
    delete quote._booking_date;
    delete quote._booking_time;
    writeStore(store);

    return sendJson(res, 201, { success: true, quote, schedule_job_id: scheduleJob?.job_id || null });
  }

  if (pathname === '/api/quotes') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const status = String(searchParams.get('status') || '').trim();
      const store = readStore();
      let quotes = [...store.quotes];
      if (status) quotes = quotes.filter((q) => q.status === status);
      quotes.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      return sendJson(res, 200, { quotes });
    }

    if (method === 'PATCH') {
      const body = await readBody(req);
      const id = Number(body.id);
      const status = String(body.status || '').trim();
      if (!id || !status) return sendJson(res, 400, { error: 'id and status are required' });

      const store = readStore();
      const quote = store.quotes.find((q) => q.id === id);
      if (!quote) return sendJson(res, 404, { error: 'Quote not found' });

      quote.status = status;
      quote.updated_at = nowIso();
      writeStore(store);
      return sendJson(res, 200, { success: true, quote });
    }

    if (method === 'PUT') {
      const body = await readBody(req);
      const id = Number(body.id);
      if (!id) return sendJson(res, 400, { error: 'id is required' });

      const store = readStore();
      const quote = store.quotes.find((q) => q.id === id);
      if (!quote) return sendJson(res, 404, { error: 'Quote not found' });

      const allowedFields = ['status', 'name', 'phone', 'email', 'issue_description', 'address', 'preferred_datetime'];
      for (const field of allowedFields) {
        if (body[field] !== undefined) quote[field] = body[field];
      }

      quote.updated_at = nowIso();
      writeStore(store);
      return sendJson(res, 200, { success: true, quote });
    }

    if (method === 'DELETE') {
      const id = Number(searchParams.get('id'));
      if (!id) return sendJson(res, 400, { error: 'Missing quote id' });

      const store = readStore();
      const before = store.quotes.length;
      store.quotes = store.quotes.filter((q) => q.id !== id);
      if (store.quotes.length === before) return sendJson(res, 404, { error: 'Quote not found' });

      writeStore(store);
      return sendJson(res, 200, { success: true });
    }
  }

  if (method === 'GET' && pathname.startsWith('/api/media/')) {
    const auth = requireAuth(req, res);
    if (!auth) return;

    const mediaId = pathname.split('/').pop();
    const store = readStore();
    const media = store.media.find((m) => String(m.id) === mediaId);
    if (!media) return sendJson(res, 404, { error: 'Media not found' });

    return sendJson(res, 200, { success: true, url: media.url, display_url: media.display_url || media.url });
  }

  // Customers
  if (pathname === '/api/customers') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const limit = Number(searchParams.get('limit')) || 200;
      const store = readStore();
      const customers = [...store.customers].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, limit);
      return sendJson(res, 200, { success: true, customers });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      if (!String(body.first_name || '').trim()) return sendJson(res, 400, { error: 'first_name is required' });

      const digits = String(body.phone || '').replace(/\D/g, '');
      const phoneE164 = digits ? (digits.startsWith('1') ? `+${digits}` : `+1${digits}`) : null;

      const store = readStore();
      const customer = {
        id: nextNumericId(store.customers),
        customer_id: nextNumericId(store.customers),
        first_name: String(body.first_name || '').trim(),
        last_name: String(body.last_name || '').trim() || null,
        phone_e164: phoneE164,
        email: String(body.email || '').trim() || null,
        address: String(body.address || '').trim() || null,
        city: String(body.city || '').trim() || null,
        state: String(body.state || '').trim() || null,
        zip: String(body.zip || '').trim() || null,
        notes: String(body.notes || '').trim() || null,
        created_at: nowIso()
      };

      store.customers.push(customer);
      writeStore(store);
      return sendJson(res, 201, { success: true, customer });
    }
  }

  // Receipts
  if (pathname === '/api/receipts') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const limit = Number(searchParams.get('limit')) || 100;
      const startDateStr = searchParams.get('start_date');
      const endDateStr = searchParams.get('end_date');
      const startDate = startDateStr ? new Date(startDateStr) : null;
      const endDate = endDateStr ? new Date(endDateStr) : null;

      const store = readStore();
      const byAdminId = new Map(store.admins.map((a) => [a.id, a.username]));
      let receipts = [...store.receipts];

      if (startDate && !Number.isNaN(startDate.getTime())) receipts = receipts.filter((r) => new Date(r.created_at) >= startDate);
      if (endDate && !Number.isNaN(endDate.getTime())) {
        const inclusive = new Date(endDate);
        inclusive.setHours(23, 59, 59, 999);
        receipts = receipts.filter((r) => new Date(r.created_at) <= inclusive);
      }

      receipts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      const sliced = receipts.slice(0, limit).map((r) => ({ ...r, admin_username: byAdminId.get(r.admin_user_id) || null }));
      const totals = sliced.reduce((acc, r) => {
        acc.count += 1;
        acc.sales += Number(r.total) || 0;
        acc.parts += Number(r.parts_subtotal) || 0;
        acc.labor += Number(r.labor_amount) || 0;
        return acc;
      }, { count: 0, sales: 0, parts: 0, labor: 0 });

      return sendJson(res, 200, { receipts: sliced, totals });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      const store = readStore();
      const receipt = {
        id: nextNumericId(store.receipts),
        admin_user_id: Number(body.admin_user_id) || auth.user.id,
        quote_id: body.quote_id != null ? Number(body.quote_id) : null,
        customer_name: String(body.customer_name || '').trim() || 'Customer',
        customer_phone: String(body.customer_phone || '').trim() || null,
        customer_email: String(body.customer_email || '').trim() || null,
        vehicle: String(body.vehicle || '').trim() || null,
        items: Array.isArray(body.items) ? body.items : [],
        parts_subtotal: Number(body.parts_subtotal) || 0,
        labor_amount: Number(body.labor_amount) || 0,
        tax_rate: Number(body.tax_rate) || 0,
        tax_amount: Number(body.tax_amount) || 0,
        discount_applied: Boolean(body.discount_applied),
        discount_amount: Number(body.discount_amount) || 0,
        total: Number(body.total) || 0,
        created_at: nowIso()
      };
      store.receipts.unshift(receipt);
      writeStore(store);
      return sendJson(res, 201, { success: true, id: receipt.id });
    }

    if (method === 'DELETE') {
      const id = Number(searchParams.get('id'));
      if (!id) return sendJson(res, 400, { error: 'Missing receipt id' });
      const store = readStore();
      const before = store.receipts.length;
      store.receipts = store.receipts.filter((r) => r.id !== id);
      if (store.receipts.length === before) return sendJson(res, 404, { error: 'Receipt not found' });
      writeStore(store);
      return sendJson(res, 200, { success: true });
    }
  }

  // Invoices
  if (pathname === '/api/invoices') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const id = String(searchParams.get('id') || '').trim();
      const status = String(searchParams.get('status') || '').trim();
      const limit = Number(searchParams.get('limit')) || 100;
      const store = readStore();

      if (id) {
        const invoice = store.invoices.find((inv) => String(inv.invoice_id) === id);
        if (!invoice) return sendJson(res, 404, { error: 'Invoice not found' });
        return sendJson(res, 200, { invoice: { ...invoice, line_items: Array.isArray(invoice.line_items) ? invoice.line_items : [] } });
      }

      let invoices = [...store.invoices];
      if (status) invoices = invoices.filter((inv) => inv.status === status);
      invoices.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      invoices = invoices.slice(0, limit);
      return sendJson(res, 200, { invoices });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      const lineItems = normalizeLineItems(body.line_items || []);
      if (!lineItems.length) return sendJson(res, 400, { error: 'At least one line item is required' });

      const store = readStore();
      const invoiceNumber = `INV-${store.counters.invoiceNumber}`;
      store.counters.invoiceNumber += 1;

      const invoice = {
        invoice_id: crypto.randomUUID(),
        invoice_number: invoiceNumber,
        quote_id: body.quote_id != null ? Number(body.quote_id) : null,
        customer_name: String(body.customer_name || '').trim() || 'Customer',
        customer_email: String(body.customer_email || '').trim() || null,
        customer_phone: String(body.customer_phone || '').trim() || null,
        due_date: body.due_date || null,
        issue_date: nowIso().split('T')[0],
        notes: String(body.notes || '').trim() || null,
        line_items: lineItems,
        status: String(body.status || 'draft'),
        paid_at: body.paid_at || null,
        amount_paid: 0,
        balance_due: 0,
        created_at: nowIso(),
        updated_at: nowIso()
      };

      const amounts = calculateInvoiceAmounts({ line_items: lineItems, tax_amount: body.tax_amount, total: body.total });
      invoice.subtotal = amounts.subtotal;
      invoice.tax_amount = amounts.tax_amount;
      invoice.total = amounts.total;

      if (invoice.status === 'paid') {
        invoice.amount_paid = invoice.total;
        invoice.balance_due = 0;
      } else {
        invoice.amount_paid = Number(body.amount_paid) || 0;
        invoice.balance_due = Math.max(0, invoice.total - invoice.amount_paid);
      }

      store.invoices.unshift(invoice);
      writeStore(store);
      return sendJson(res, 201, { success: true, invoice_id: invoice.invoice_id, invoice_number: invoice.invoice_number });
    }

    if (method === 'PUT') {
      const id = String(searchParams.get('id') || '').trim();
      if (!id) return sendJson(res, 400, { error: 'Missing invoice id' });

      const body = await readBody(req);
      const store = readStore();
      const invoice = store.invoices.find((inv) => String(inv.invoice_id) === id);
      if (!invoice) return sendJson(res, 404, { error: 'Invoice not found' });

      if (Array.isArray(body.line_items)) {
        const lineItems = normalizeLineItems(body.line_items);
        if (!lineItems.length) return sendJson(res, 400, { error: 'At least one line item is required' });
        invoice.line_items = lineItems;
      }

      const fields = ['quote_id', 'customer_name', 'customer_email', 'customer_phone', 'due_date', 'notes', 'status', 'paid_at'];
      for (const field of fields) {
        if (body[field] !== undefined) invoice[field] = body[field];
      }

      const amounts = calculateInvoiceAmounts({
        line_items: invoice.line_items,
        tax_amount: body.tax_amount != null ? body.tax_amount : invoice.tax_amount,
        total: body.total != null ? body.total : invoice.total
      });
      invoice.subtotal = amounts.subtotal;
      invoice.tax_amount = amounts.tax_amount;
      invoice.total = amounts.total;

      if (invoice.status === 'paid') {
        invoice.paid_at = invoice.paid_at || nowIso();
        invoice.amount_paid = invoice.total;
        invoice.balance_due = 0;
      } else {
        const paid = body.amount_paid != null ? Number(body.amount_paid) : Number(invoice.amount_paid || 0);
        invoice.amount_paid = paid;
        invoice.balance_due = Math.max(0, invoice.total - invoice.amount_paid);
      }

      invoice.updated_at = nowIso();
      writeStore(store);
      return sendJson(res, 200, { success: true, invoice });
    }

    if (method === 'DELETE') {
      const id = String(searchParams.get('id') || '').trim();
      if (!id) return sendJson(res, 400, { error: 'Missing invoice id' });
      const store = readStore();
      const before = store.invoices.length;
      store.invoices = store.invoices.filter((inv) => String(inv.invoice_id) !== id);
      if (store.invoices.length === before) return sendJson(res, 404, { error: 'Invoice not found' });
      writeStore(store);
      return sendJson(res, 200, { success: true });
    }
  }

  if (method === 'POST' && pathname === '/api/invoice-email') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    const body = await readBody(req);
    const invoiceId = String(body.invoice_id || '').trim();
    if (!invoiceId) return sendJson(res, 400, { error: 'invoice_id is required' });

    const store = readStore();
    const invoice = store.invoices.find((inv) => String(inv.invoice_id) === invoiceId);
    if (!invoice) return sendJson(res, 404, { error: 'Invoice not found' });

    if (invoice.status === 'draft') {
      invoice.status = 'sent';
      invoice.updated_at = nowIso();
      writeStore(store);
    }

    return sendJson(res, 200, { success: true, message: 'Email endpoint connected. Add provider integration when ready.' });
  }

  if (method === 'POST' && pathname === '/api/receipt-email') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    const body = await readBody(req);
    const toEmail = String(body.to_email || '').trim();
    if (!toEmail) return sendJson(res, 400, { error: 'to_email is required' });

    return sendJson(res, 200, { success: true, message: 'Receipt email endpoint connected. Add provider integration when ready.' });
  }

  // Compatibility stubs for imported admin panel routes
  if (pathname === '/api/roles') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      return sendJson(res, 200, { roles: [defaultRole] });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      const role = {
        id: Number(body.id) || 2,
        name: String(body.name || 'Custom Role'),
        permissions: body.permissions && typeof body.permissions === 'object' ? body.permissions : {}
      };
      return sendJson(res, 201, { success: true, role });
    }

    if (method === 'DELETE') {
      return sendJson(res, 200, { success: true });
    }
  }

  if (pathname === '/api/contacts') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    const store = readStore();
    const type = String(searchParams.get('type') || '').trim();
    const limit = Number(searchParams.get('limit')) || 200;

    let contacts = [
      ...store.quotes.map(toContactFromQuote),
      ...store.customers.map(toContactFromCustomer)
    ];

    if (type === 'lead' || type === 'leads') contacts = contacts.filter((c) => c.type === 'lead');
    if (type === 'customer' || type === 'customers') contacts = contacts.filter((c) => c.type === 'customer');

    contacts.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    contacts = contacts.slice(0, limit);
    return sendJson(res, 200, { success: true, contacts });
  }

  if (method === 'POST' && pathname === '/api/contacts/convert') {
    const auth = requireAuth(req, res);
    if (!auth) return;
    return sendJson(res, 200, { success: true });
  }

  if (pathname === '/api/schedule') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      const store = readStore();
      const start = String(searchParams.get('start') || '').trim();
      const end = String(searchParams.get('end') || '').trim();
      const limit = Number(searchParams.get('limit')) || 200;
      let jobs = [...(store.scheduleJobs || [])];

      const startMs = dateToMs(start);
      const endMs = dateToMs(end);

      if (startMs != null) {
        jobs = jobs.filter((j) => {
          const jobMs = dateToMs(j.scheduled_date);
          return jobMs == null || jobMs >= startMs;
        });
      }

      if (endMs != null) {
        jobs = jobs.filter((j) => {
          const jobMs = dateToMs(j.scheduled_date);
          return jobMs == null || jobMs <= endMs;
        });
      }
      jobs.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
      jobs = jobs.slice(0, limit);
      return sendJson(res, 200, { success: true, jobs });
    }

    if (method === 'POST') {
      const body = await readBody(req);
      const store = readStore();
      const job = {
        job_id: crypto.randomUUID(),
        entry_type: body.entry_type || 'job',
        contact_name: body.contact_name || '',
        contact_phone: body.contact_phone || null,
        title: body.title || 'Appointment',
        scheduled_date: body.scheduled_date || nowIso().slice(0, 10),
        scheduled_time: body.scheduled_time || null,
        time_window_end: body.time_window_end || null,
        duration_minutes: Number(body.duration_minutes) || 120,
        address: body.address || null,
        travel_time: body.travel_time != null ? Number(body.travel_time) : null,
        description: body.description || null,
        quote_id: body.quote_id != null ? Number(body.quote_id) : null,
        customer_id: body.customer_id || null,
        status: body.status || 'scheduled',
        created_at: nowIso(),
        updated_at: nowIso()
      };
      store.scheduleJobs.unshift(job);
      writeStore(store);
      return sendJson(res, 201, { success: true, job });
    }

    if (method === 'PUT' || method === 'PATCH') {
      const body = await readBody(req);
      const jobId = String(body.job_id || '').trim();
      if (!jobId) return sendJson(res, 400, { error: 'job_id is required' });

      const store = readStore();
      const job = (store.scheduleJobs || []).find((j) => String(j.job_id) === jobId);
      if (!job) return sendJson(res, 404, { error: 'Job not found' });

      const fields = [
        'entry_type', 'contact_name', 'contact_phone', 'title', 'scheduled_date',
        'scheduled_time', 'time_window_end', 'duration_minutes', 'address',
        'travel_time', 'description', 'quote_id', 'customer_id', 'status'
      ];

      for (const field of fields) {
        if (body[field] !== undefined) {
          job[field] = field === 'duration_minutes' || field === 'travel_time'
            ? (body[field] != null ? Number(body[field]) : null)
            : body[field];
        }
      }
      job.updated_at = nowIso();
      writeStore(store);
      return sendJson(res, 200, { success: true, job });
    }

    if (method === 'DELETE') {
      const jobId = String(searchParams.get('id') || '').trim();
      if (!jobId) return sendJson(res, 400, { error: 'id is required' });
      const store = readStore();
      const before = store.scheduleJobs.length;
      store.scheduleJobs = store.scheduleJobs.filter((j) => String(j.job_id) !== jobId);
      if (store.scheduleJobs.length === before) return sendJson(res, 404, { error: 'Job not found' });
      writeStore(store);
      return sendJson(res, 200, { success: true });
    }
  }

  if (method === 'GET' && pathname === '/api/schedule/ical') {
    const ics = [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'PRODID:-//ConsciousClimbing//Admin//EN',
      'CALSCALE:GREGORIAN',
      'METHOD:PUBLISH',
      'END:VCALENDAR'
    ].join('\r\n');
    return sendText(res, 200, ics, 'text/calendar; charset=utf-8');
  }

  if (pathname === '/api/messages') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') {
      return sendJson(res, 200, { success: true, messages: [], conversations: [] });
    }

    if (method === 'POST' || method === 'PATCH') {
      return sendJson(res, 200, { success: true });
    }
  }

  if (method === 'POST' && pathname === '/api/review-emails') {
    const auth = requireAuth(req, res);
    if (!auth) return;
    return sendJson(res, 200, { success: true, sent: 0 });
  }

  if (pathname === '/api/feedback') {
    const auth = requireAuth(req, res);
    if (!auth) return;

    if (method === 'GET') return sendJson(res, 200, { success: true, items: [] });
    if (method === 'POST') return sendJson(res, 200, { success: true });
  }

  return sendJson(res, 404, { error: 'Route not found' });
}

const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.pdf': 'application/pdf',
  '.txt': 'text/plain; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

function safeResolve(baseDir, requestPath) {
  const clean = decodeURIComponent(requestPath).replace(/\0/g, '');
  const rel = clean.replace(/^\/+/, '');
  const resolved = path.normalize(path.join(baseDir, rel));
  if (!resolved.startsWith(baseDir)) return null;
  return resolved;
}

function serveFile(res, filePath) {
  if (!fs.existsSync(filePath)) return false;
  const stat = fs.statSync(filePath);
  if (!stat.isFile()) return false;

  const ext = path.extname(filePath).toLowerCase();
  const type = contentTypes[ext] || 'application/octet-stream';
  const stream = fs.createReadStream(filePath);

  res.writeHead(200, {
    'Content-Type': type,
    'Content-Length': stat.size
  });

  stream.pipe(res);
  stream.on('error', () => {
    if (!res.headersSent) sendText(res, 500, 'Internal server error');
  });
  return true;
}

function serveStatic(req, res, pathname) {
  if (pathname.startsWith('/data')) return sendText(res, 403, 'Forbidden');

  if (pathname === '/Admin' || pathname.startsWith('/Admin/')) {
    const target = pathname.replace('/Admin', '/admin');
    res.writeHead(301, { Location: target || '/admin' });
    return res.end();
  }

  if (pathname === '/admin') {
    return serveFile(res, path.join(ROOT_DIR, 'admin', 'index.html')) || sendText(res, 404, 'Not found');
  }

  if (pathname.startsWith('/admin/')) {
    const adminPath = pathname.slice('/admin/'.length);
    const full = safeResolve(path.join(ROOT_DIR, 'admin'), adminPath || 'index.html');
    if (!full) return sendText(res, 403, 'Forbidden');

    if (serveFile(res, full)) return;
    return sendText(res, 404, 'Not found');
  }

  const requested = pathname === '/' ? 'index.html' : pathname.slice(1);
  const full = safeResolve(ROOT_DIR, requested);
  if (!full) return sendText(res, 403, 'Forbidden');

  if (serveFile(res, full)) return;
  return sendText(res, 404, 'Not found');
}

const server = http.createServer(async (req, res) => {
  try {
    const parsed = new URL(req.url || '/', `http://${req.headers.host || `localhost:${PORT}`}`);
    const pathname = parsed.pathname;

    if (pathname.startsWith('/api/')) {
      return await handleApi(req, res, pathname, parsed.searchParams);
    }

    return serveStatic(req, res, pathname);
  } catch (error) {
    if (!res.headersSent) {
      sendJson(res, 500, { error: 'Internal server error', detail: error.message });
    }
  }
});

ensureStoreFile();
server.listen(PORT, HOST, () => {
  console.log(`ConsciousClimbing backend listening on http://${HOST}:${PORT}`);
});
