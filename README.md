# Pulseboard Scanner Lab

Local-only dashboard demo for testing a Node.js security scanner. It is intentionally insecure and must not be deployed to the internet or used with real data.

## Run

```bash
npm install
npm start
```

Open http://localhost:3000. Demo users are `admin / admin123` and `demo / demo`.

## Intentional findings

- `GET /?q=`: unparameterized SQLite query (SQL injection) and reflected EJS output in the search field (XSS).
- `GET /api/admin/users`: missing authorization and plaintext password disclosure.
- `GET /download?file=`: user-controlled path passed to `sendFile` (path traversal fixture).
- `POST /login`: weak hardcoded JWT secret and plaintext demo credentials.
- Global permissive CORS policy.
- Deliberately old dependency versions in `package.json` for dependency-scanner testing.

The SQLite database is created automatically at `data/dashboard.sqlite` on first start.
