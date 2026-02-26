CREATE TABLE IF NOT EXISTS quotes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  phone TEXT,
  email TEXT,
  status TEXT,
  preferred_datetime TEXT,
  issue_description TEXT,
  service_type TEXT,
  equipment TEXT,
  group_size INTEGER,
  address TEXT,
  admin_notes TEXT,
  callback_date TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS customers (
  customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_name TEXT,
  last_name TEXT,
  phone_e164 TEXT,
  email TEXT,
  address TEXT,
  city TEXT,
  state TEXT,
  zip TEXT,
  notes TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS schedule_jobs (
  job_id TEXT PRIMARY KEY,
  entry_type TEXT,
  contact_name TEXT,
  contact_phone TEXT,
  title TEXT,
  scheduled_date TEXT,
  scheduled_time TEXT,
  time_window_end TEXT,
  duration_minutes INTEGER,
  address TEXT,
  travel_time INTEGER,
  description TEXT,
  quote_id INTEGER,
  customer_id INTEGER,
  status TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_quotes_status ON quotes(status);
CREATE INDEX IF NOT EXISTS idx_quotes_created_at ON quotes(created_at);
CREATE INDEX IF NOT EXISTS idx_schedule_date_time ON schedule_jobs(scheduled_date, scheduled_time);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);
