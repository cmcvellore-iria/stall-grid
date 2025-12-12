// ---------------------------------------------------------
// CMC IRIA – STALL GRID PASSPORT BACKEND (HYBRID SECURE)
// ---------------------------------------------------------
// Features:
//  ✓ Secure signup/login (JWT)
//  ✓ Forget password + OTP reset
//  ✓ Secure per-delegate QR token generation (HMAC-SHA256)
//  ✓ SQLite database storage
//  ✓ Leaderboard
//  ✓ Visit recording (1 per stall)
// ---------------------------------------------------------

const express = require("express");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.json());

// Allow frontend to call backend from GitHub Pages / any domain
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  next();
});

// ---------------------------------------------------------
// ENV SECRETS
// ---------------------------------------------------------
const TOKEN_SECRET = process.env.TOKEN_SECRET || "CHANGEME_QR_TOKEN_SECRET";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGEME_JWT_SECRET";
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------
// DATABASE SETUP
// ---------------------------------------------------------
const db = new Database(path.join(__dirname, "data.db"));

db.prepare(`
CREATE TABLE IF NOT EXISTS delegates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  name TEXT,
  password TEXT,
  delegateId TEXT UNIQUE
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  delegateId TEXT,
  stall INTEGER,
  ts INTEGER
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS reset_otps (
  email TEXT PRIMARY KEY,
  otp TEXT,
  expires INTEGER
)`).run();

// Password hashing (simple SHA256)
function hashPwd(p) {
  return crypto.createHash("sha256").update(p).digest("hex");
}

// ---------------------------------------------------------
// JWT AUTH MIDDLEWARE
// ---------------------------------------------------------
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "auth required" });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

// ---------------------------------------------------------
// SIGNUP
// ---------------------------------------------------------
app.post("/api/signup", (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "email & password required" });

  const delegateId = "D" + Math.floor(100000 + Math.random() * 900000);

  try {
    db.prepare(
      "INSERT INTO delegates (email, name, password, delegateId) VALUES (?,?,?,?)"
    ).run(email, name || email, hashPwd(password), delegateId);

    const row = db
      .prepare("SELECT id, name, delegateId FROM delegates WHERE email=?")
      .get(email);

    const token = jwt.sign(
      {
        id: row.id,
        email,
        delegateId: row.delegateId,
        name: row.name,
      },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.json({
      token,
      delegateId: row.delegateId,
      name: row.name,
      email,
    });
  } catch (e) {
    return res.status(400).json({ error: "user exists or db error" });
  }
});

// ---------------------------------------------------------
// LOGIN
// ---------------------------------------------------------
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  const row = db
    .prepare(
      "SELECT id, email, name, password, delegateId FROM delegates WHERE email=?"
    )
    .get(email);

  if (!row || row.password !== hashPwd(password))
    return res.status(401).json({ error: "invalid login" });

  const token = jwt.sign(
    {
      id: row.id,
      email,
      delegateId: row.delegateId,
      name: row.name,
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({
    token,
    delegateId: row.delegateId,
    name: row.name,
    email,
  });
});

// ---------------------------------------------------------
// REQUEST PASSWORD RESET OTP
// ---------------------------------------------------------
app.post("/api/request-reset", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "email required" });

  const row = db
    .prepare("SELECT email FROM delegates WHERE email=?")
    .get(email);

  if (!row) return res.status(404).json({ error: "email not found" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000; // 5 minutes

  db.prepare(
    "INSERT OR REPLACE INTO reset_otps (email, otp, expires) VALUES (?,?,?)"
  ).run(email, otp, expires);

  // In production: send OTP via email/SMS.
  // For conference app: return OTP directly for display.
  res.json({ ok: true, otp });
});

// ---------------------------------------------------------
// RESET PASSWORD USING OTP
// ---------------------------------------------------------
app.post("/api/reset-password", (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword)
    return res.status(400).json({ error: "missing fields" });

  const row = db
    .prepare("SELECT otp, expires FROM reset_otps WHERE email=?")
    .get(email);

  if (!row) return res.status(400).json({ error: "no otp request found" });
  if (Date.now() > row.expires)
    return res.status(400).json({ error: "otp expired" });
  if (row.otp !== otp) return res.status(400).json({ error: "invalid otp" });

  db.prepare("UPDATE delegates SET password=? WHERE email=?").run(
    hashPwd(newPassword),
    email
  );

  db.prepare("DELETE FROM reset_otps WHERE email=?").run(email);

  res.json({ ok: true });
});

// ---------------------------------------------------------
// GENERATE PER-DELEGATE VISIT TOKEN (secure hybrid model)
// Requires auth (delegate must be logged in)
// ---------------------------------------------------------
app.post("/api/generate-visit-token", authMiddleware, (req, res) => {
  const { stall } = req.body;

  if (!stall)
    return res.status(400).json({ ok: false, error: "stall required" });

  // short lived token for scanning flow (5 minutes)
  const exp = Date.now() + 5 * 60 * 1000;

  const token = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(`${req.user.delegateId}|${stall}|${exp}`)
    .digest("hex");

  res.json({
    ok: true,
    stall,
    exp,
    token
  });
});

// ---------------------------------------------------------
// VERIFY QR TOKEN (secure)
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
    if (
      !crypto.timingSafeEqual(
        Buffer.from(expected, "hex"),
        Buffer.from(token, "hex")
      )
    )
      return res.status(400).json({ error: "invalid token" });
  } catch (_) {
    return res.status(400).json({ error: "invalid token" });
  }

  if (Number(exp) < Date.now())
    return res.status(400).json({ error: "expired token" });

  const exists = db
    .prepare("SELECT 1 FROM visits WHERE delegateId=? AND stall=?")
    .get(req.user.delegateId, stall);

  if (!exists)
    db.prepare(
      "INSERT INTO visits (delegateId, stall, ts) VALUES (?,?,?)"
    ).run(req.user.delegateId, stall, Date.now());

  res.json({ ok: true });
});

// ---------------------------------------------------------
// GET USER VISITS
// ---------------------------------------------------------
app.get("/api/visits/:delegateId", authMiddleware, (req, res) => {
  if (req.params.delegateId !== req.user.delegateId)
    return res.status(403).json({ error: "forbidden" });

  const rows = db
    .prepare("SELECT stall, ts FROM visits WHERE delegateId=?")
    .all(req.user.delegateId);

  res.json({ visits: rows.map((r) => r.stall) });
});

// ---------------------------------------------------------
// LEADERBOARD
// ---------------------------------------------------------
app.get("/api/leaderboard", (req, res) => {
  const rows = db
    .prepare(
      `
    SELECT delegateId, COUNT(*) AS cnt
    FROM visits
    GROUP BY delegateId
    ORDER BY cnt DESC
    LIMIT 50
  `
    )
    .all();

  const out = rows.map((r) => {
    const d = db
      .prepare("SELECT name FROM delegates WHERE delegateId=?")
      .get(r.delegateId);
    return {
      delegateId: r.delegateId,
      name: (d && d.name) || r.delegateId,
      count: r.cnt,
    };
  });

  res.json({ top: out });
});

// ---------------------------------------------------------
// START SERVER
// ---------------------------------------------------------
app.listen(PORT, () => {
  console.log("CMC IRIA backend running on port", PORT);
});
