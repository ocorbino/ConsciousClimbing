# ConsciousClimbing

Conscious Climbing website with an owner/admin backend.

## Run locally

1. Install dependencies:

```bash
npm install
```

2. Start the server:

```bash
npm run dev
```

3. Open the site:

- Public site: `http://localhost:3000/`
- Owner admin: `http://localhost:3000/admin/login.html`

## Admin setup flow

1. Visit `/admin/login.html`.
2. If no admin account exists yet, you will be redirected to `/admin/setup.html`.
3. Create the first owner/admin account.
4. Sign in and use the admin dashboard.

## Data storage

The backend stores data in `data/store.json` (created automatically at runtime).

Stored entities include:

- admin users and sessions
- quote/booking requests
- customers
- invoices
- receipts
- email recipients and business settings
