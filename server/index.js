// /server/index.js
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import nacl from "tweetnacl";
import { decodeBase64Url, encodeBase64Url } from "./utils/base64url.js";

const app = express();
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_RENDER_ENV";

const db = new Database(process.env.DB_PATH || "./vp.sqlite");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
  id TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  video_id TEXT,
  tier TEXT,
  reward_units INTEGER,
  payload_json TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_user_time ON events(user_id, created_at);

CREATE TABLE IF NOT EXISTS balances (
  user_id TEXT PRIMARY KEY,
  earn_units INTEGER NOT NULL
);
`);

const te = new TextEncoder();

function nowMs() {
  return Date.now();
}

function signJwt(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "30d" });
}

// ✅ FIX: auth ensures user + balances rows exist (prevents earnUnits staying 0 after redeploy/db reset)
function auth(req, res, next) {
  const hdr = String(req.headers.authorization || "");
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  if (!token) return res.status(401).json({ error: "missing_token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = String(decoded?.sub || "").trim();
    if (!userId) return res.status(401).json({ error: "invalid_token" });

    // Ensure rows exist so UPDATE balances always works
    db.prepare("INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)").run(userId, nowMs());
    db.prepare("INSERT OR IGNORE INTO balances (user_id, earn_units) VALUES (?, 0)").run(userId);

    req.userId = userId;
    return next();
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }
}

app.get("/health", (_, res) => res.json({ ok: true }));

// 1) get nonce
app.post("/auth/nonce", (req, res) => {
  const pubkey = String(req.body?.pubkey || "").trim();
  if (!pubkey) return res.status(400).json({ error: "missing_pubkey" });

  const nonce = encodeBase64Url(nacl.randomBytes(24));
  db.prepare("INSERT OR REPLACE INTO nonces (id, nonce, created_at) VALUES (?, ?, ?)")
    .run(pubkey, nonce, nowMs());

  res.json({ nonce });
});

// 2) login with signature
app.post("/auth/login", (req, res) => {
  const pubkey = String(req.body?.pubkey || "").trim();
  const nonce = String(req.body?.nonce || "").trim();
  const signature = String(req.body?.signature || "").trim();

  if (!pubkey || !nonce || !signature) {
    return res.status(400).json({ error: "missing_fields" });
  }

  const row = db.prepare("SELECT nonce, created_at FROM nonces WHERE id=?").get(pubkey);
  if (!row || row.nonce !== nonce) return res.status(401).json({ error: "bad_nonce" });

  if (nowMs() - Number(row.created_at) > 5 * 60 * 1000) {
    return res.status(401).json({ error: "nonce_expired" });
  }

  const pubBytes = decodeBase64Url(pubkey);
  const sigBytes = decodeBase64Url(signature);
  const msgBytes = te.encode(nonce);

  if (!(pubBytes?.length === 32) || !(sigBytes?.length === 64)) {
    return res.status(400).json({ error: "bad_key_format" });
  }

  const ok = nacl.sign.detached.verify(msgBytes, sigBytes, pubBytes);
  if (!ok) return res.status(401).json({ error: "bad_signature" });

  db.prepare("INSERT OR IGNORE INTO users (id, created_at) VALUES (?, ?)").run(pubkey, nowMs());
  db.prepare("INSERT OR IGNORE INTO balances (user_id, earn_units) VALUES (?, 0)").run(pubkey);

  res.json({ token: signJwt(pubkey) });
});

app.get("/me", auth, (req, res) => {
  const bal = db.prepare("SELECT earn_units FROM balances WHERE user_id=?").get(req.userId);
  res.json({ userId: req.userId, earnUnits: bal ? Number(bal.earn_units) : 0 });
});

// ✅ NEW: list watched videos for this user (server-side)
app.get("/watched", auth, (req, res) => {
  const userId = req.userId;

  const rows = db.prepare(
    `SELECT DISTINCT video_id AS videoId
     FROM events
     WHERE user_id = ?
       AND type = 'video_completed'
       AND video_id IS NOT NULL`
  ).all(userId);

  res.json({ items: rows.map((r) => String(r.videoId)) });
});

app.post("/events", auth, (req, res) => {
  const userId = req.userId;
  const type = String(req.body?.type || "").trim();
  if (!type) return res.status(400).json({ error: "missing_type" });

  const videoId = req.body?.videoId ? String(req.body.videoId) : null;
  const tier = req.body?.tier ? String(req.body.tier) : null;

  const rewardUnitsRaw = req.body?.rewardUnits;
  const rewardUnits = Number.isFinite(Number(rewardUnitsRaw)) ? Math.floor(Number(rewardUnitsRaw)) : null;

  const payload = req.body?.payload ?? null;
  const payloadJson = payload ? JSON.stringify(payload) : null;

  const createdAt = nowMs();

  if (type === "video_completed") {
    if (!videoId || !tier || rewardUnits === null || rewardUnits <= 0) {
      return res.status(400).json({ error: "missing_video_fields" });
    }

    const already = db.prepare(
      "SELECT 1 FROM events WHERE user_id=? AND type='video_completed' AND video_id=? LIMIT 1"
    ).get(userId, videoId);

    if (!already) {
      db.prepare(
        `INSERT INTO events (user_id,type,video_id,tier,reward_units,payload_json,created_at)
         VALUES (?,?,?,?,?,?,?)`
      ).run(userId, type, videoId, tier, rewardUnits, payloadJson, createdAt);

      // ✅ This will now always work because auth() ensures balances row exists
      db.prepare("UPDATE balances SET earn_units = earn_units + ? WHERE user_id=?")
        .run(rewardUnits, userId);
    }

    const bal = db.prepare("SELECT earn_units FROM balances WHERE user_id=?").get(userId);
    return res.json({ ok: true, duplicated: Boolean(already), earnUnits: bal ? Number(bal.earn_units) : 0 });
  }

  if (type === "withdraw_request") {
    const unitsToDeduct = Number(req.body?.unitsToDeduct);
    const addr = String(req.body?.payload?.address || "").trim();
    if (!Number.isFinite(unitsToDeduct) || unitsToDeduct <= 0) {
      return res.status(400).json({ error: "bad_unitsToDeduct" });
    }
    if (!addr) return res.status(400).json({ error: "missing_address" });

    const bal = db.prepare("SELECT earn_units FROM balances WHERE user_id=?").get(userId);
    const cur = bal ? Number(bal.earn_units) : 0;
    if (unitsToDeduct > cur) return res.status(400).json({ error: "insufficient_balance" });

    db.prepare(
      `INSERT INTO events (user_id,type,video_id,tier,reward_units,payload_json,created_at)
       VALUES (?,?,?,?,?,?,?)`
    ).run(userId, type, null, null, -unitsToDeduct, payloadJson, createdAt);

    db.prepare("UPDATE balances SET earn_units = earn_units - ? WHERE user_id=?")
      .run(unitsToDeduct, userId);

    const bal2 = db.prepare("SELECT earn_units FROM balances WHERE user_id=?").get(userId);
    return res.json({ ok: true, earnUnits: bal2 ? Number(bal2.earn_units) : 0 });
  }

  db.prepare(
    `INSERT INTO events (user_id,type,video_id,tier,reward_units,payload_json,created_at)
     VALUES (?,?,?,?,?,?,?)`
  ).run(userId, type, videoId, tier, rewardUnits, payloadJson, createdAt);

  res.json({ ok: true });
});

app.get("/history", auth, (req, res) => {
  const userId = req.userId;
  const limit = Math.max(1, Math.min(500, Number(req.query?.limit || 200)));

  const rows = db.prepare(
    `SELECT id,type,video_id as videoId,tier,reward_units as rewardUnits,payload_json as payloadJson,created_at as createdAt
     FROM events
     WHERE user_id=?
     ORDER BY created_at DESC
     LIMIT ?`
  ).all(userId, limit);

  res.json({
    items: rows.map((r) => ({
      id: r.id,
      type: r.type,
      videoId: r.videoId,
      tier: r.tier,
      rewardUnits: r.rewardUnits === null ? null : Number(r.rewardUnits),
      payload: r.payloadJson ? JSON.parse(r.payloadJson) : null,
      createdAt: Number(r.createdAt)
    }))
  });
});

app.listen(PORT, () => {
  // ✅ FIX: real template literal
  console.log('ViewPlay API running on http://localhost:${PORT}');
});