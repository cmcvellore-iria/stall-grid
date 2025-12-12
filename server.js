// ---------------------------------------------------------
// CMC IRIA – STALL GRID PASSPORT BACKEND (with CSV Validation)
// ---------------------------------------------------------
// Features:
//  ✓ Secure REGISTRATION (requires RegistrationID + Email match)
//  ✓ Login + JWT
//  ✓ Forgot password + OTP
//  ✓ Secure hybrid QR model
//  ✓ CSV upload API for valid Registration List
// ---------------------------------------------------------

const express = require("express");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "5mb" }));

// CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, admin-key");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  next();
});

// ------------------------
// ENV SECRETS
// ------------------------
const TOKEN_SECRET = process.env.TOKEN_SECRET || "CHANGEME_QR_TOKEN_SECRET";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGEME_JWT_SECRET";
const ADMIN_KEY = process.env.ADMIN_KEY || "iriasupersecure";
const PORT = process.env.PORT || 3000;

// ------------------------
// DATABASE SETUP
// ------------------------
const db = new Database(path.join(__dirname, "data.db"));

// delegates
db.prepare(`
CREATE TABLE IF NOT EXISTS delegates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  name TEXT,
  password TEXT,
  delegateId TEXT UNIQUE,
  regId TEXT
)
`).run();

// visits
db.prepare(`
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  delegateId TEXT,
  stall INTEGER,
  ts INTEGER
)
`).run();

// otp
db.prepare(`
CREATE TABLE IF NOT EXISTS reset_otps (
  email TEXT PRIMARY KEY,
  otp TEXT,
  expires INTEGER
)
`).run();

// VALID REGISTRATION LIST
db.prepare(`
CREATE TABLE IF NOT EXISTS valid_regs (
  regId TEXT PRIMARY KEY,
  email TEXT
)
`).run();

function hashPwd(p) {
  return crypto.createHash("sha256").update(p).digest("hex");
}

// ------------------------
// ADMIN CSV UPLOAD
// ------------------------
app.post("/api/admin/upload-reglist", (req, res) => {
  const key = req.headers["admin-key"];
  if (key !== ADMIN_KEY) {
    return res.status(403).json({ ok: false, error: "invalid admin key" });
  }

  let csv = req.body.csv;
  if (!csv) return res.status(400).json({ ok: false, error: "csv missing" });

  // wipe previous list
  db.prepare("DELETE FROM valid_regs").run();

  // parse CSV
  let lines = csv.split(/\r?\n/);
  lines = lines.filter(l => l.trim().length > 0);
  if (lines.length < 2) {
    return res.status(400).json({ ok: false, error: "not enough rows" });
  }

  // assume header: RegistrationID,Email
  for (let i = 1; i < lines.length; i++) {
    let parts = lines[i].split(",");
    if (parts.length < 2) continue;
    const regId = parts[0].trim();
    const email = parts[1].trim().toLowerCase();
    if (!regId || !email) continue;
    db.prepare("INSERT OR REPLACE INTO valid_regs (regId, email) VALUES (?,?)")
      .run(regId, email);
  }

  res.json({ ok: true, rows: lines.length - 1 });
});

// ------------------------
// AUTH MIDDLEWARE
// ------------------------
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "auth required" });
  try {
    const user = jwt.verify(m[1], JWT_SECRET);
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid token" });
  }
}

// ------------------------
// SIGNUP
// ------------------------
app.post("/api/signup", (req, res) => {
  const { email, password, name, regId } = req.body;

  if (!email || !password || !regId)
    return res.status(400).json({ error: "email, password & registration ID required" });

  // check registration list match
  const row = db.prepare("SELECT * FROM valid_regs WHERE regId=?").get(regId);
  if (!row) {
    return res.status(400).json({ error: "Registration ID not found" });
  }

  if (row.email !== email.toLowerCase()) {
    return res.status(400).json({ error: "Email does not match registration records" });
  }

  const delegateId = "D" + Math.floor(100000 + Math.random() * 900000);

  try {
    db.prepare(`
      INSERT INTO delegates (email, name, password, delegateId, regId)
      VALUES (?,?,?,?,?)
    `).run(email.toLowerCase(), name || email, hashPwd(password), delegateId, regId);

    const token = jwt.sign(
      { email, delegateId, name: name || email },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({
      token,
      delegateId,
      name: name || email,
      email
    });
  } catch (e) {
    return res.status(400).json({ error: "User exists or DB error" });
  }
});

// ------------------------
// LOGIN
// ------------------------
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  const row = db.prepare("SELECT * FROM delegates WHERE email=?").get(email.toLowerCase());
  if (!row || row.password !== hashPwd(password)) {
    return res.status(401).json({ error: "invalid login" });
  }

  const token = jwt.sign(
    { email, delegateId: row.delegateId, name: row.name },
    JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({
    token,
    delegateId: row.delegateId,
    name: row.name,
    email
  });
});

// ------------------------
// FORGOT PASSWORD FLOW
// ------------------------
app.post("/api/request-reset", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "email required" });

  const row = db.prepare("SELECT email FROM delegates WHERE email=?").get(email.toLowerCase());
  if (!row) return res.status(404).json({ error: "email not found" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000;

  db.prepare("INSERT OR REPLACE INTO reset_otps (email, otp, expires) VALUES (?,?,?)")
    .run(email.toLowerCase(), otp, expires);

  res.json({ ok: true, otp });
});

app.post("/api/reset-password", (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword)
    return res.status(400).json({ error: "missing fields" });

  const row = db.prepare("SELECT otp, expires FROM reset_otps WHERE email=?")
    .get(email.toLowerCase());

  if (!row) return res.status(400).json({ error: "no otp request" });
  if (Date.now() > row.expires) return res.status(400).json({ error: "otp expired" });
  if (row.otp !== otp) return res.status(400).json({ error: "wrong otp" });

  db.prepare("UPDATE delegates SET password=? WHERE email=?")
    .run(hashPwd(newPassword), email.toLowerCase());

  db.prepare("DELETE FROM reset_otps WHERE email=?")
    .run(email.toLowerCase());

  res.json({ ok: true });
});

// ------------------------
// PER-DELEGATE TOKEN GEN
// ------------------------
app.post("/api/generate-visit-token", authMiddleware, (req, res) => {
  const { stall } = req.body;
  if (!stall) return res.status(400).json({ ok: false, error: "stall required" });

  const exp = Date.now() + 5 * 60 * 1000;

  const token = crypto.createHmac("sha256", TOKEN_SECRET)
    .update(`${req.user.delegateId}|${stall}|${exp}`)
    .digest("hex");

  res.json({ ok: true, stall, exp, token });
});

// ------------------------
// VERIFY VISIT
// ------------------------
app.post("/api/verify", authMiddleware, (req, res) => {
  const { stall, token, exp } = req.body;

  const expected = crypto.createHmac("sha256", TOKEN_SECRET)
    .update(`${req.user.delegateId}|${stall}|${exp}`)
    .digest("hex");

  if (expected !== token) return res.status(400).json({ error: "invalid token" });
  if (Number(exp) < Date.now()) return res.status(400).json({ error: "expired token" });

  const exists = db.prepare(`
    SELECT 1 FROM visits WHERE delegateId=? AND stall=?
  `).get(req.user.delegateId, stall);

  if (!exists) {
    db.prepare(`
      INSERT INTO visits (delegateId, stall, ts)
      VALUES (?,?,?)
    `).run(req.user.delegateId, stall, Date.now());
  }

  res.json({ ok: true });
});

// ------------------------
// GET VISITS
// ------------------------
app.get("/api/visits/:delegateId", authMiddleware, (req, res) => {
  if (req.params.delegateId !== req.user.delegateId)
    return res.status(403).json({ error: "forbidden" });

  const rows = db.prepare("SELECT stall FROM visits WHERE delegateId=?")
    .all(req.user.delegateId);

  res.json({ visits: rows.map(x => x.stall) });
});

// ------------------------
// LEADERBOARD
// ------------------------
app.get("/api/leaderboard", (req, res) => {
  const rows = db.prepare(`
    SELECT delegateId, COUNT(*) AS cnt
    FROM visits
    GROUP BY delegateId
    ORDER BY cnt DESC
    LIMIT 50
  `).all();

  const result = [];
  for (let r of rows) {
    const d = db.prepare("SELECT name FROM delegates WHERE delegateId=?").get(r.delegateId);
    result.push({
      delegateId: r.delegateId,
      name: d?.name || r.delegateId,
      count: r.cnt
    });
  }

  res.json({ top: result });
});

// ------------------------
app.listen(PORT, () => console.log("CMC IRIA backend running on", PORT));
