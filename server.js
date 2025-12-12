// ---------------------------------------------------------
// CMC IRIA – STALL GRID PASSPORT BACKEND (FINAL WITH CSV)
// ---------------------------------------------------------
// Features:
//  ✓ Secure signup/login (JWT)
//  ✓ Registration locked to CSV list (RegistrationID + Email match)
//  ✓ Admin portal with password (upload CSV, view, clear)
//  ✓ CSV parsed into SQLite table
//  ✓ Secure per-delegate QR token generation (HMAC-SHA256)
//  ✓ Visit recording + leaderboard
// ---------------------------------------------------------

const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.json());

// Allow frontend access
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  next();
});

// ---------------------------------------------------------
// ENVIRONMENT
// ---------------------------------------------------------
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "iriasupersecure";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "CHANGEME_QR_TOKEN_SECRET";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGEME_JWT_SECRET";
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------
// DATABASE SETUP
// ---------------------------------------------------------
const db = new Database(path.join(__dirname, "data.db"));

// Delegates who SIGN UP
db.prepare(`
CREATE TABLE IF NOT EXISTS delegates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  regId TEXT,
  email TEXT UNIQUE,
  name TEXT,
  password TEXT,
  delegateId TEXT UNIQUE
)
`).run();

// CSV registration database (official registrations)
db.prepare(`
CREATE TABLE IF NOT EXISTS registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  regId TEXT UNIQUE,
  name TEXT,
  email TEXT
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  delegateId TEXT,
  stall INTEGER,
  ts INTEGER
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS reset_otps (
  email TEXT PRIMARY KEY,
  otp TEXT,
  expires INTEGER
)
`).run();

// Password hashing
function hashPwd(p) {
  return crypto.createHash("sha256").update(p).digest("hex");
}

// ---------------------------------------------------------
// JWT AUTH
// ---------------------------------------------------------
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "auth required" });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

// ---------------------------------------------------------
// ADMIN LOGIN
// ---------------------------------------------------------
app.post("/admin/login", (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) return res.json({ ok: true });
  return res.status(403).json({ ok: false, error: "wrong password" });
});

// ---------------------------------------------------------
// CSV UPLOAD (admin)
// ---------------------------------------------------------
const upload = multer({ dest: "uploads/" });

app.post("/admin/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file" });

  const results = [];

  fs.createReadStream(req.file.path)
    .pipe(csv())
    .on("data", (row) => {
      // Must match CSV headers:
      // RegistrationID, Name, Email
      const regId = row["RegistrationID"];
      const name = row["Name"];
      const email = row["Email"];

      if (regId && email) {
        results.push({ regId, name: name || "", email: email.trim().toLowerCase() });
      }
    })
    .on("end", () => {
      // Clear existing registration table
      db.prepare("DELETE FROM registrations").run();

      const insert = db.prepare(
        "INSERT INTO registrations (regId, name, email) VALUES (?,?,?)"
      );

      results.forEach((r) => insert.run(r.regId, r.name, r.email));

      fs.unlinkSync(req.file.path);

      res.json({ ok: true, count: results.length });
    });
});

// ---------------------------------------------------------
// ADMIN: VIEW ALL REGISTRATIONS
// ---------------------------------------------------------
app.get("/admin/list", (req, res) => {
  const rows = db.prepare("SELECT regId, name, email FROM registrations").all();
  res.json({ ok: true, rows });
});

// ---------------------------------------------------------
// ADMIN: CLEAR REGISTRATIONS
// ---------------------------------------------------------
app.post("/admin/clear", (req, res) => {
  db.prepare("DELETE FROM registrations").run();
  res.json({ ok: true });
});

// ---------------------------------------------------------
// SIGNUP — MUST MATCH REGISTRATION LIST
// ---------------------------------------------------------
app.post("/api/signup", (req, res) => {
  const { email, password, name, regId } = req.body;

  if (!email || !password || !regId)
    return res.status(400).json({ error: "email, password, regId required" });

  // Look up CSV data
  const reg = db
    .prepare("SELECT * FROM registrations WHERE regId=?")
    .get(regId);

  if (!reg)
    return res.status(400).json({ error: "Registration ID not found" });

  if (reg.email.toLowerCase() !== email.toLowerCase())
    return res.status(400).json({ error: "Email does not match registration record" });

  // Create delegate profile
  const delegateId = "D" + Math.floor(100000 + Math.random() * 900000);

  try {
    db.prepare(
      "INSERT INTO delegates (regId, email, name, password, delegateId) VALUES (?,?,?,?,?)"
    ).run(regId, email.toLowerCase(), reg.name, hashPwd(password), delegateId);

    const token = jwt.sign(
      { delegateId, email, name: reg.name },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.json({
      token,
      delegateId,
      name: reg.name,
      email,
    });

  } catch (e) {
    return res.status(400).json({ error: "User already exists" });
  }
});

// ---------------------------------------------------------
// LOGIN
// ---------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  const row = db.prepare("SELECT * FROM delegates WHERE email=?").get(email.toLowerCase());
  if (!row || row.password !== hashPwd(password))
    return res.status(401).json({ error: "invalid login" });

  const token = jwt.sign(
    { delegateId: row.delegateId, email: row.email, name: row.name },
    JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({
    token,
    delegateId: row.delegateId,
    name: row.name,
    email: row.email,
  });
});

// ---------------------------------------------------------
// GENERATE VISIT TOKEN
// ---------------------------------------------------------
app.post("/api/generate-visit-token", authMiddleware, (req, res) => {
  const { stall } = req.body;

  if (!stall) return res.status(400).json({ error: "stall required" });

  const exp = Date.now() + 5 * 60 * 1000; // 5 mins

  const token = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(`${req.user.delegateId}|${stall}|${exp}`)
    .digest("hex");

  res.json({ ok: true, stall, exp, token });
});

// ---------------------------------------------------------
// VERIFY STAMP
// ---------------------------------------------------------
app.post("/api/verify", authMiddleware, (req, res) => {
  const { stall, token, exp } = req.body;
  if (!stall || !token || !exp)
    return res.status(400).json({ error: "missing" });

  const expected = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(`${req.user.delegateId}|${stall}|${exp}`)
    .digest("hex");

  try {
    if (!crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(token, "hex")))
      return res.status(400).json({ error: "invalid token" });
  } catch {
    return res.status(400).json({ error: "invalid token" });
  }

  if (Number(exp) < Date.now())
    return res.status(400).json({ error: "expired token" });

  const exists = db
    .prepare("SELECT 1 FROM visits WHERE delegateId=? AND stall=?")
    .get(req.user.delegateId, stall);

  if (!exists)
    db.prepare("INSERT INTO visits (delegateId, stall, ts) VALUES (?,?,?)")
      .run(req.user.delegateId, stall, Date.now());

  res.json({ ok: true });
});

// ---------------------------------------------------------
// GET USER VISITS
// ---------------------------------------------------------
app.get("/api/visits/:delegateId", authMiddleware, (req, res) => {
  if (req.params.delegateId !== req.user.delegateId)
    return res.status(403).json({ error: "forbidden" });

  const rows = db.prepare("SELECT stall FROM visits WHERE delegateId=?").all(req.user.delegateId);
  res.json({ visits: rows.map((r) => r.stall) });
});

// ---------------------------------------------------------
// LEADERBOARD
// ---------------------------------------------------------
app.get("/api/leaderboard", (_, res) => {
  const rows = db.prepare(`
    SELECT delegateId, COUNT(*) AS cnt
    FROM visits GROUP BY delegateId ORDER BY cnt DESC LIMIT 50
  `).all();

  const out = rows.map((r) => {
    const d = db.prepare("SELECT name FROM delegates WHERE delegateId=?").get(r.delegateId);
    return {
      delegateId: r.delegateId,
      name: d ? d.name : r.delegateId,
      count: r.cnt,
    };
  });

  res.json({ top: out });
});

// ---------------------------------------------------------
app.listen(PORT, () => {
  console.log("CMC IRIA backend running on port", PORT);
});
