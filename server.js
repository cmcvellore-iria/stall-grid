// ---------------------------------------------------------
// CMC IRIA – STALL GRID PASSPORT BACKEND (SIMPLIFIED)
// ---------------------------------------------------------

const express = require("express");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const path = require("path");
require("dotenv").config();

const app = express();
app.use(express.json({ limit: "5mb" }));

/* ---------------- CORS ---------------- */
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  next();
});

/* ---------------- CONFIG ---------------- */
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_JWT";
const TOKEN_SECRET = process.env.TOKEN_SECRET || "CHANGE_ME_TOKEN";

/* ---------------- DATABASE ---------------- */
const db = new Database(path.join(__dirname, "data.db"));

db.prepare(`
CREATE TABLE IF NOT EXISTS delegates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  name TEXT,
  password TEXT
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT,
  stall INTEGER,
  ts INTEGER,
  UNIQUE(email, stall)
)
`).run();

/* ---------------- HELPERS ---------------- */
function hashPwd(p) {
  return crypto.createHash("sha256").update(p).digest("hex");
}

/* ---------------- AUTH MIDDLEWARE ---------------- */
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "auth required" });

  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "invalid token" });
  }
}

/* ---------------- SIGNUP ---------------- */
app.post("/api/signup", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "name, email, password required" });

  try {
    db.prepare(`
      INSERT INTO delegates (email, name, password)
      VALUES (?,?,?)
    `).run(email.toLowerCase(), name, hashPwd(password));

    const token = jwt.sign(
      { email: email.toLowerCase(), name },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    res.json({ token, name, email });
  } catch {
    res.status(400).json({ error: "User already exists" });
  }
});

/* ---------------- LOGIN ---------------- */
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  const row = db.prepare(
    "SELECT * FROM delegates WHERE email=?"
  ).get(email.toLowerCase());

  if (!row || row.password !== hashPwd(password)) {
    return res.status(401).json({ error: "invalid login" });
  }

  const token = jwt.sign(
    { email: row.email, name: row.name },
    JWT_SECRET,
    { expiresIn: "30d" }
  );

  res.json({ token, name: row.name, email: row.email });
});

/* ---------------- GENERATE VISIT TOKEN ---------------- */
app.post("/api/generate-visit-token", auth, (req, res) => {
  const { stall } = req.body;
  if (!stall) return res.status(400).json({ error: "stall required" });

  const exp = Date.now() + 5 * 60 * 1000;

  const token = crypto.createHmac("sha256", TOKEN_SECRET)
    .update(`${req.user.email}|${stall}|${exp}`)
    .digest("hex");

  res.json({ token, exp });
});

/* ---------------- VERIFY VISIT ---------------- */
app.post("/api/verify", auth, (req, res) => {
  const { stall, token, exp } = req.body;

  const expected = crypto.createHmac("sha256", TOKEN_SECRET)
    .update(`${req.user.email}|${stall}|${exp}`)
    .digest("hex");

  if (expected !== token)
    return res.status(400).json({ error: "invalid token" });

  if (Date.now() > exp)
    return res.status(400).json({ error: "token expired" });

  db.prepare(`
    INSERT OR IGNORE INTO visits (email, stall, ts)
    VALUES (?,?,?)
  `).run(req.user.email, stall, Date.now());

  res.json({ ok: true });
});

/* ---------------- GET VISITS ---------------- */
app.get("/api/visits", auth, (req, res) => {
  const rows = db.prepare(
    "SELECT stall FROM visits WHERE email=?"
  ).all(req.user.email);

  res.json({ visits: rows.map(r => r.stall) });
});

/* ---------------- LEADERBOARD ---------------- */
app.get("/api/leaderboard", (req, res) => {
  const rows = db.prepare(`
    SELECT email, COUNT(*) AS count
    FROM visits
    GROUP BY email
    ORDER BY count DESC
    LIMIT 50
  `).all();

  const out = rows.map(r => {
    const d = db.prepare(
      "SELECT name FROM delegates WHERE email=?"
    ).get(r.email);
    return {
      name: d?.name || r.email,
      count: r.count
    };
  });

  res.json({ top: out });
});

/* ---------------- START ---------------- */
app.listen(PORT, () =>
  console.log("CMC IRIA backend running on port", PORT)
);
