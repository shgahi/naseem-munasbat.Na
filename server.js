"use strict";

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PIN = process.env.ADMIN_PIN || "282834";
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL غير موجود. أضف قاعدة بيانات PostgreSQL أولًا.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
});

app.use(express.json({ limit: "6mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* ---------------- database ---------------- */
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id         SERIAL PRIMARY KEY,
      name       TEXT NOT NULL,
      date_text  TEXT DEFAULT '',
      location   TEXT DEFAULT '',
      map_link   TEXT DEFAULT '',
      image      TEXT DEFAULT '',
      scan_key   TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guests (
      id           SERIAL PRIMARY KEY,
      event_id     INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      name         TEXT NOT NULL,
      phone        TEXT DEFAULT '',
      token        TEXT UNIQUE NOT NULL,
      rsvp         TEXT NOT NULL DEFAULT 'pending',
      status       TEXT NOT NULL DEFAULT 'pending',
      responded_at TIMESTAMPTZ,
      used_at      TIMESTAMPTZ,
      created_at   TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS guests_event_idx ON guests(event_id);`
  );
  console.log("قاعدة البيانات جاهزة ✓");
}

/* ---------------- auth ---------------- */
function sign(value) {
  const mac = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("hex");
  return value + "." + mac;
}
function verify(signed) {
  if (!signed || signed.indexOf(".") === -1) return null;
  const idx = signed.lastIndexOf(".");
  const value = signed.slice(0, idx);
  const expected = sign(value);
  const a = Buffer.from(signed);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return value;
}
function requireAdmin(req, res, next) {
  const v = verify(req.cookies.session || "");
  if (v && v.startsWith("admin:")) return next();
  return res.status(401).json({ error: "غير مصرح" });
}
function token() {
  return crypto.randomBytes(9).toString("base64url");
}

app.post("/api/login", (req, res) => {
  const pin = String((req.body && req.body.pin) || "");
  const ok =
    pin.length === ADMIN_PIN.length &&
    crypto.timingSafeEqual(Buffer.from(pin), Buffer.from(ADMIN_PIN));
  if (!ok) return res.status(401).json({ error: "الرمز غير صحيح" });
  res.cookie("session", sign("admin:" + Date.now()), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 12,
  });
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const v = verify(req.cookies.session || "");
  res.json({ authenticated: !!(v && v.startsWith("admin:")) });
});

/* ---------------- events ---------------- */
app.get("/api/events", requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT e.id, e.name, e.date_text, e.location, e.map_link, e.scan_key,
           (e.image <> '') AS has_image,
           COUNT(g.id)::int AS total,
           COUNT(*) FILTER (WHERE g.rsvp = 'yes')::int AS yes_count,
           COUNT(*) FILTER (WHERE g.rsvp = 'no')::int AS no_count,
           COUNT(*) FILTER (WHERE g.status = 'entered')::int AS entered
    FROM events e LEFT JOIN guests g ON g.event_id = e.id
    GROUP BY e.id ORDER BY e.id DESC;
  `);
  res.json(rows);
});

app.post("/api/events", requireAdmin, async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || "").trim();
  if (!name) return res.status(400).json({ error: "اسم الحفل مطلوب" });
  const { rows } = await pool.query(
    `INSERT INTO events (name, date_text, location, map_link, scan_key)
     VALUES ($1,$2,$3,$4,$5) RETURNING id, name, scan_key;`,
    [
      name,
      String(b.dateText || "").trim(),
      String(b.location || "").trim(),
      String(b.map || "").trim(),
      token(),
    ]
  );
  res.json(rows[0]);
});

app.put("/api/events/:id", requireAdmin, async (req, res) => {
  const b = req.body || {};
  await pool.query(
    `UPDATE events SET name=COALESCE(NULLIF($2,''),name), date_text=$3,
     location=$4, map_link=$5 WHERE id=$1;`,
    [
      req.params.id,
      String(b.name || "").trim(),
      String(b.dateText || "").trim(),
      String(b.location || "").trim(),
      String(b.map || "").trim(),
    ]
  );
  res.json({ ok: true });
});

app.delete("/api/events/:id", requireAdmin, async (req, res) => {
  await pool.query(`DELETE FROM events WHERE id=$1;`, [req.params.id]);
  res.json({ ok: true });
});

app.get("/api/events/:id", requireAdmin, async (req, res) => {
  const ev = await pool.query(
    `SELECT id, name, date_text, location, map_link, scan_key,
            (image <> '') AS has_image FROM events WHERE id=$1;`,
    [req.params.id]
  );
  if (!ev.rows.length) return res.status(404).json({ error: "غير موجود" });
  const gs = await pool.query(
    `SELECT id, name, phone, token, rsvp, status, used_at
     FROM guests WHERE event_id=$1 ORDER BY id DESC;`,
    [req.params.id]
  );
  res.json({ event: ev.rows[0], guests: gs.rows });
});

app.post("/api/events/:id/image", requireAdmin, async (req, res) => {
  await pool.query(`UPDATE events SET image=$2 WHERE id=$1;`, [
    req.params.id,
    String((req.body && req.body.image) || ""),
  ]);
  res.json({ ok: true });
});

app.get("/api/events/:id/image", async (req, res) => {
  const { rows } = await pool.query(`SELECT image FROM events WHERE id=$1;`, [
    req.params.id,
  ]);
  res.json({ image: rows.length ? rows[0].image : "" });
});

/* ---------------- guests (bulk) ---------------- */
app.post("/api/events/:id/guests", requireAdmin, async (req, res) => {
  const raw = String((req.body && req.body.text) || "");
  const lines = raw.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!lines.length) return res.status(400).json({ error: "لا يوجد مدعوون" });

  const existing = await pool.query(
    `SELECT phone FROM guests WHERE event_id=$1 AND phone <> '';`,
    [req.params.id]
  );
  const seen = new Set(existing.rows.map((r) => r.phone));

  let added = 0;
  let skipped = 0;
  for (const line of lines) {
    const m = line.match(/^([+\d][\d\s\-()]*)\s+(.+)$/);
    let phone = "";
    let name = line;
    if (m) {
      phone = m[1].replace(/[\s\-()]/g, "");
      name = m[2].trim();
    }
    if (!name) {
      skipped++;
      continue;
    }
    if (phone && seen.has(phone)) {
      skipped++;
      continue;
    }
    if (phone) seen.add(phone);
    await pool.query(
      `INSERT INTO guests (event_id, name, phone, token) VALUES ($1,$2,$3,$4);`,
      [req.params.id, name, phone, token()]
    );
    added++;
  }
  res.json({ added, skipped });
});

app.delete("/api/guests/:id", requireAdmin, async (req, res) => {
  await pool.query(`DELETE FROM guests WHERE id=$1;`, [req.params.id]);
  res.json({ ok: true });
});

app.post("/api/guests/:id/reset", requireAdmin, async (req, res) => {
  await pool.query(
    `UPDATE guests SET status='pending', used_at=NULL WHERE id=$1;`,
    [req.params.id]
  );
  res.json({ ok: true });
});

/* ---------------- public invite ---------------- */
app.get("/api/invite/:token", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT g.id, g.name, g.rsvp, g.status, g.token,
            e.name AS event_name, e.date_text, e.location, e.map_link, e.id AS event_id
     FROM guests g JOIN events e ON e.id = g.event_id WHERE g.token=$1;`,
    [req.params.token]
  );
  if (!rows.length) return res.status(404).json({ error: "الدعوة غير موجودة" });
  res.json(rows[0]);
});

app.post("/api/invite/:token/rsvp", async (req, res) => {
  const answer = (req.body && req.body.answer) === "yes" ? "yes" : "no";
  const { rows } = await pool.query(
    `UPDATE guests SET rsvp=$2, responded_at=now()
     WHERE token=$1 AND status <> 'entered' RETURNING rsvp, status;`,
    [req.params.token, answer]
  );
  if (!rows.length) return res.status(400).json({ error: "تعذر تسجيل الرد" });
  res.json(rows[0]);
});

/* ---------------- reception scan ---------------- */
app.get("/api/scan/:key", async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name FROM events WHERE scan_key=$1;`,
    [req.params.key]
  );
  if (!rows.length) return res.status(404).json({ error: "رابط غير صالح" });
  res.json(rows[0]);
});

app.post("/api/scan/:key/checkin", async (req, res) => {
  const ev = await pool.query(`SELECT id, name FROM events WHERE scan_key=$1;`, [
    req.params.key,
  ]);
  if (!ev.rows.length) return res.status(404).json({ error: "رابط غير صالح" });
  const eventId = ev.rows[0].id;
  const guestToken = String((req.body && req.body.token) || "");

  // Atomic: only the first scan can flip pending -> entered
  const claim = await pool.query(
    `UPDATE guests SET status='entered', used_at=now()
     WHERE token=$1 AND event_id=$2 AND rsvp='yes' AND status='pending'
     RETURNING name, phone, used_at;`,
    [guestToken, eventId]
  );
  if (claim.rows.length) {
    return res.json({
      result: "ok",
      name: claim.rows[0].name,
      phone: claim.rows[0].phone,
    });
  }

  const found = await pool.query(
    `SELECT name, phone, rsvp, status, used_at, event_id FROM guests WHERE token=$1;`,
    [guestToken]
  );
  if (!found.rows.length) return res.json({ result: "invalid" });
  const g = found.rows[0];
  if (g.event_id !== eventId) return res.json({ result: "wrong_event" });
  if (g.status === "entered")
    return res.json({ result: "used", name: g.name, usedAt: g.used_at });
  return res.json({ result: "not_confirmed", name: g.name });
});

app.get("/api/scan/:key/search", async (req, res) => {
  const ev = await pool.query(`SELECT id FROM events WHERE scan_key=$1;`, [
    req.params.key,
  ]);
  if (!ev.rows.length) return res.status(404).json({ error: "رابط غير صالح" });
  const q = "%" + String(req.query.q || "").trim() + "%";
  const { rows } = await pool.query(
    `SELECT name, phone, token, rsvp, status FROM guests
     WHERE event_id=$1 AND (name ILIKE $2 OR phone ILIKE $2) LIMIT 8;`,
    [ev.rows[0].id, q]
  );
  res.json(rows);
});

/* ---------------- pages ---------------- */
app.get("/i/:token", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "invite.html"))
);
app.get("/s/:key", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "scan.html"))
);
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "admin.html"))
);

initDb()
  .then(() => app.listen(PORT, () => console.log("يعمل على المنفذ " + PORT)))
  .catch((e) => {
    console.error("فشل تهيئة قاعدة البيانات:", e.message);
    app.listen(PORT, () => console.log("يعمل على المنفذ " + PORT));
  });
