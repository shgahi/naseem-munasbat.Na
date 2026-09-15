"use strict";

const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PIN = String(process.env.ADMIN_PIN || "282834");
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

let dbReady = false;
let dbError = "لم تتم تهيئة قاعدة البيانات بعد";

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL)
        ? false
        : { rejectUnauthorized: false },
      max: 5,
    })
  : null;

app.use(express.json({ limit: "6mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* wraps async handlers so an error never leaves the request hanging */
const ah = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/* every /api route needs a live database */
app.use("/api", (req, res, next) => {
  if (!pool) {
    return res.status(503).json({
      error: "DATABASE_URL غير مضبوط. أضف رابط قاعدة البيانات في إعدادات الخدمة.",
    });
  }
  if (!dbReady) return res.status(503).json({ error: dbError });
  next();
});

/* ---------------- database ---------------- */
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id         SERIAL PRIMARY KEY,
      name       TEXT NOT NULL,
      date_text  TEXT NOT NULL DEFAULT '',
      location   TEXT NOT NULL DEFAULT '',
      map_link   TEXT NOT NULL DEFAULT '',
      image      TEXT NOT NULL DEFAULT '',
      scan_key   TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS guests (
      id           SERIAL PRIMARY KEY,
      event_id     INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
      name         TEXT NOT NULL,
      phone        TEXT NOT NULL DEFAULT '',
      token        TEXT UNIQUE NOT NULL,
      rsvp         TEXT NOT NULL DEFAULT 'pending',
      status       TEXT NOT NULL DEFAULT 'pending',
      responded_at TIMESTAMPTZ,
      used_at      TIMESTAMPTZ,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS guests_event_idx ON guests(event_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS guests_token_idx ON guests(token);`);
}

/* ---------------- helpers ---------------- */
function sign(value) {
  return (
    value +
    "." +
    crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex")
  );
}
function verify(signed) {
  if (!signed || signed.indexOf(".") === -1) return null;
  const value = signed.slice(0, signed.lastIndexOf("."));
  const a = Buffer.from(signed);
  const b = Buffer.from(sign(value));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return value;
}
function requireAdmin(req, res, next) {
  const v = verify(req.cookies.session || "");
  if (v && v.indexOf("admin:") === 0) return next();
  return res.status(401).json({ error: "غير مصرح" });
}
function newToken() {
  return crypto.randomBytes(9).toString("base64url");
}
function intId(v) {
  const n = parseInt(v, 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/* ---------------- auth ---------------- */
app.post("/api/login", (req, res) => {
  const pin = String((req.body && req.body.pin) || "");
  const a = Buffer.from(pin);
  const b = Buffer.from(ADMIN_PIN);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
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
  res.json({ authenticated: !!(v && v.indexOf("admin:") === 0) });
});

/* ---------------- events ---------------- */
app.get(
  "/api/events",
  requireAdmin,
  ah(async (req, res) => {
    const { rows } = await pool.query(`
      SELECT e.id, e.name, e.date_text, e.location, e.map_link, e.scan_key,
             (e.image <> '') AS has_image,
             COUNT(g.id)::int AS total,
             COALESCE(SUM(CASE WHEN g.rsvp   = 'yes'     THEN 1 ELSE 0 END),0)::int AS yes_count,
             COALESCE(SUM(CASE WHEN g.rsvp   = 'no'      THEN 1 ELSE 0 END),0)::int AS no_count,
             COALESCE(SUM(CASE WHEN g.status = 'entered' THEN 1 ELSE 0 END),0)::int AS entered
      FROM events e LEFT JOIN guests g ON g.event_id = e.id
      GROUP BY e.id, e.name, e.date_text, e.location, e.map_link, e.scan_key, e.image
      ORDER BY e.id DESC;
    `);
    res.json(rows);
  })
);

app.post(
  "/api/events",
  requireAdmin,
  ah(async (req, res) => {
    const b = req.body || {};
    const name = String(b.name || "").trim();
    if (!name) return res.status(400).json({ error: "اسم الحفل مطلوب" });
    const { rows } = await pool.query(
      `INSERT INTO events (name, date_text, location, map_link, scan_key)
       VALUES ($1,$2,$3,$4,$5) RETURNING id, name, scan_key;`,
      [
        name.slice(0, 200),
        String(b.dateText || "").trim().slice(0, 200),
        String(b.location || "").trim().slice(0, 200),
        String(b.map || "").trim().slice(0, 500),
        newToken(),
      ]
    );
    res.json(rows[0]);
  })
);

app.delete(
  "/api/events/:id",
  requireAdmin,
  ah(async (req, res) => {
    const id = intId(req.params.id);
    if (!id) return res.status(400).json({ error: "معرّف غير صالح" });
    await pool.query(`DELETE FROM events WHERE id=$1;`, [id]);
    res.json({ ok: true });
  })
);

app.get(
  "/api/events/:id",
  requireAdmin,
  ah(async (req, res) => {
    const id = intId(req.params.id);
    if (!id) return res.status(400).json({ error: "معرّف غير صالح" });
    const ev = await pool.query(
      `SELECT id, name, date_text, location, map_link, scan_key,
              (image <> '') AS has_image FROM events WHERE id=$1;`,
      [id]
    );
    if (!ev.rows.length) return res.status(404).json({ error: "غير موجود" });
    const gs = await pool.query(
      `SELECT id, name, phone, token, rsvp, status, used_at
       FROM guests WHERE event_id=$1 ORDER BY id DESC;`,
      [id]
    );
    res.json({ event: ev.rows[0], guests: gs.rows });
  })
);

app.post(
  "/api/events/:id/image",
  requireAdmin,
  ah(async (req, res) => {
    const id = intId(req.params.id);
    if (!id) return res.status(400).json({ error: "معرّف غير صالح" });
    const image = String((req.body && req.body.image) || "");
    if (image && !/^data:image\/(png|jpeg|jpg|webp);base64,/.test(image)) {
      return res.status(400).json({ error: "صيغة الصورة غير مدعومة" });
    }
    await pool.query(`UPDATE events SET image=$2 WHERE id=$1;`, [id, image]);
    res.json({ ok: true });
  })
);

/* public: the invite page needs the image */
app.get(
  "/api/public/events/:id/image",
  ah(async (req, res) => {
    const id = intId(req.params.id);
    if (!id) return res.json({ image: "" });
    const { rows } = await pool.query(`SELECT image FROM events WHERE id=$1;`, [id]);
    res.json({ image: rows.length ? rows[0].image : "" });
  })
);

/* ---------------- guests ---------------- */
app.post(
  "/api/events/:id/guests",
  requireAdmin,
  ah(async (req, res) => {
    const id = intId(req.params.id);
    if (!id) return res.status(400).json({ error: "معرّف غير صالح" });
    const lines = String((req.body && req.body.text) || "")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 2000);
    if (!lines.length) return res.status(400).json({ error: "لا يوجد مدعوون" });

    const existing = await pool.query(
      `SELECT phone FROM guests WHERE event_id=$1 AND phone <> '';`,
      [id]
    );
    const seen = new Set(existing.rows.map((r) => r.phone));

    const values = [];
    const params = [];
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
      const i = params.length;
      params.push(id, name.slice(0, 120), phone.slice(0, 25), newToken());
      values.push(`($${i + 1},$${i + 2},$${i + 3},$${i + 4})`);
      added++;
    }

    if (added) {
      await pool.query(
        `INSERT INTO guests (event_id, name, phone, token) VALUES ${values.join(",")};`,
        params
      );
    }
    res.json({ added, skipped });
  })
);

app.delete(
  "/api/guests/:id",
  requireAdmin,
  ah(async (req, res) => {
    const id = intId(req.params.id);
    if (!id) return res.status(400).json({ error: "معرّف غير صالح" });
    await pool.query(`DELETE FROM guests WHERE id=$1;`, [id]);
    res.json({ ok: true });
  })
);

app.post(
  "/api/guests/:id/reset",
  requireAdmin,
  ah(async (req, res) => {
    const id = intId(req.params.id);
    if (!id) return res.status(400).json({ error: "معرّف غير صالح" });
    await pool.query(
      `UPDATE guests SET status='pending', used_at=NULL WHERE id=$1;`,
      [id]
    );
    res.json({ ok: true });
  })
);

/* ---------------- public invite ---------------- */
app.get(
  "/api/invite/:token",
  ah(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT g.name, g.rsvp, g.status, g.token,
              e.id AS event_id, e.name AS event_name,
              e.date_text, e.location, e.map_link
       FROM guests g JOIN events e ON e.id = g.event_id WHERE g.token=$1;`,
      [String(req.params.token).slice(0, 64)]
    );
    if (!rows.length) return res.status(404).json({ error: "الدعوة غير موجودة" });
    res.json(rows[0]);
  })
);

app.post(
  "/api/invite/:token/rsvp",
  ah(async (req, res) => {
    const answer = (req.body && req.body.answer) === "yes" ? "yes" : "no";
    const { rows } = await pool.query(
      `UPDATE guests SET rsvp=$2, responded_at=now()
       WHERE token=$1 AND status <> 'entered' RETURNING rsvp, status;`,
      [String(req.params.token).slice(0, 64), answer]
    );
    if (!rows.length) return res.status(400).json({ error: "تعذر تسجيل الرد" });
    res.json(rows[0]);
  })
);

/* ---------------- reception ---------------- */
app.get(
  "/api/scan/:key",
  ah(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT id, name FROM events WHERE scan_key=$1;`,
      [String(req.params.key).slice(0, 64)]
    );
    if (!rows.length) return res.status(404).json({ error: "رابط غير صالح" });
    res.json(rows[0]);
  })
);

app.post(
  "/api/scan/:key/checkin",
  ah(async (req, res) => {
    const ev = await pool.query(`SELECT id FROM events WHERE scan_key=$1;`, [
      String(req.params.key).slice(0, 64),
    ]);
    if (!ev.rows.length) return res.status(404).json({ error: "رابط غير صالح" });
    const eventId = ev.rows[0].id;
    const guestToken = String((req.body && req.body.token) || "").slice(0, 64);

    /* atomic: only the first scan can flip pending -> entered */
    const claim = await pool.query(
      `UPDATE guests SET status='entered', used_at=now()
       WHERE token=$1 AND event_id=$2 AND rsvp='yes' AND status='pending'
       RETURNING name, phone;`,
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
      `SELECT name, rsvp, status, used_at, event_id FROM guests WHERE token=$1;`,
      [guestToken]
    );
    if (!found.rows.length) return res.json({ result: "invalid" });
    const g = found.rows[0];
    if (g.event_id !== eventId) return res.json({ result: "wrong_event" });
    if (g.status === "entered")
      return res.json({ result: "used", name: g.name, usedAt: g.used_at });
    return res.json({ result: "not_confirmed", name: g.name });
  })
);

app.get(
  "/api/scan/:key/search",
  ah(async (req, res) => {
    const ev = await pool.query(`SELECT id FROM events WHERE scan_key=$1;`, [
      String(req.params.key).slice(0, 64),
    ]);
    if (!ev.rows.length) return res.status(404).json({ error: "رابط غير صالح" });
    const q = "%" + String(req.query.q || "").trim().slice(0, 60) + "%";
    const { rows } = await pool.query(
      `SELECT name, phone, token, rsvp, status FROM guests
       WHERE event_id=$1 AND (name ILIKE $2 OR phone ILIKE $2)
       ORDER BY name LIMIT 8;`,
      [ev.rows[0].id, q]
    );
    res.json(rows);
  })
);

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

/* ---------------- errors ---------------- */
app.use((err, req, res, next) => {
  console.error("خطأ:", err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "حدث خطأ في الخادم، حاول مرة أخرى" });
});

/* ---------------- boot ---------------- */
app.listen(PORT, () => console.log("الخادم يعمل على المنفذ " + PORT));

if (pool) {
  initDb()
    .then(() => {
      dbReady = true;
      console.log("قاعدة البيانات جاهزة ✓");
    })
    .catch((e) => {
      dbError = "تعذر الاتصال بقاعدة البيانات: " + e.message;
      console.error(dbError);
    });
} else {
  console.error("تنبيه: DATABASE_URL غير مضبوط — أضفه في متغيرات البيئة.");
}
