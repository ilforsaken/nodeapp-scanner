const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const _ = require('lodash');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'dashboard.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// LAB INTENTION: permissive CORS is useful for scanner demonstrations.
app.use(cors());

const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    value INTEGER NOT NULL,
    change TEXT NOT NULL,
    color TEXT NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);

  db.run("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')");
  db.run("INSERT OR IGNORE INTO users (username, password, role) VALUES ('demo', 'demo', 'viewer')");
  db.run("INSERT OR IGNORE INTO metrics (id, name, value, change, color) VALUES (1, 'Active users', 1284, '+12.5%', 'purple')");
  db.run("INSERT OR IGNORE INTO metrics (id, name, value, change, color) VALUES (2, 'Revenue', 84200, '+8.2%', 'blue')");
  db.run("INSERT OR IGNORE INTO metrics (id, name, value, change, color) VALUES (3, 'Conversion rate', 6.84, '-1.4%', 'orange')");
  db.run("INSERT OR IGNORE INTO metrics (id, name, value, change, color) VALUES (4, 'Open tickets', 42, '+3.1%', 'pink')");
  db.run("INSERT OR IGNORE INTO activity (id, actor, action, created_at) VALUES (1, 'Maria Rossi', 'Published campaign Spring Launch', '2026-10-31 09:42')");
  db.run("INSERT OR IGNORE INTO activity (id, actor, action, created_at) VALUES (2, 'Luca Bianchi', 'Exported customer report', '2026-10-30 16:20')");
  db.run("INSERT OR IGNORE INTO activity (id, actor, action, created_at) VALUES (3, 'Admin', 'Changed workspace settings', '2026-10-30 11:03')");
});

// LAB INTENTION: deliberately weak secret and credentials for JWT scanner tests.
const JWT_SECRET = 'dashboard-secret-123';

app.get('/', (req, res) => {
  const q = req.query.q || '';
  // LAB INTENTION: SQL injection. Keep this query intentionally unparameterized.
  const sql = `SELECT * FROM metrics WHERE name LIKE '%${q}%'`;
  db.all(sql, (err, metrics) => {
    if (err) return res.status(500).send(err.message);
    db.all('SELECT * FROM activity ORDER BY id DESC LIMIT 6', (activityErr, activity) => {
      if (activityErr) return res.status(500).send(activityErr.message);
      // LAB INTENTION: q is rendered with EJS's unescaped tag in index.ejs (reflected XSS).
      res.render('index', { metrics, activity, q, username: req.query.user || 'Alex Morgan' });
    });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT id, username, role FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  });
});

app.get('/api/metrics', (req, res) => {
  db.all('SELECT * FROM metrics', (err, rows) => res.json({ rows, poweredBy: _.get(req.headers, 'x-powered-by', 'dashboard') }));
});

// LAB INTENTION: no authorization check on this administrative endpoint.
app.get('/api/admin/users', (req, res) => {
  db.all('SELECT id, username, password, role FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// LAB INTENTION: path traversal via user-controlled file name.
app.get('/download', (req, res) => {
  const requested = req.query.file || 'README.md';
  res.sendFile(path.join(UPLOAD_DIR, requested), { dotfiles: 'allow' }, (err) => {
    if (err && !res.headersSent) res.status(err.statusCode || 404).send('File not found');
  });
});

app.get('/health', (req, res) => res.json({ ok: true, service: 'scanner-lab-dashboard' }));

app.listen(PORT, () => {
  console.log(`Scanner lab dashboard running at http://localhost:${PORT}`);
  console.log('Demo credentials: admin/admin123 and demo/demo');
});

process.on('SIGINT', () => db.close(() => process.exit(0)));
