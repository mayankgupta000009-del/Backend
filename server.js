const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// http.Server wraps the Express app so a WebSocketServer can share
// the same port — no separate service/process needed, works fine on
// Render's free tier exactly like the rest of this app.
const server = http.createServer(app);

// ═══════════════════════════════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════════════════════════════

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

async function initDB() {
    // ── Devices — issued write-scoped tokens ──────────────────────
    // Replaces the old single shared API key for app writes.
    // Each installed app registers once and gets its own token.
    // Losing one device's token only exposes that device's ability
    // to write data — never read/delete access to anyone else's data.
    //
    // linked_phone: set via POST /api/devices/link-phone once the
    // user enters their own number in-app. Lets GET
    // /api/trips/active-for-guardian look up "is anyone tracking me
    // as their guardian?" from the caller's own device token, with
    // no phone number ever passed in a URL/query param (avoids a
    // phone-number enumeration endpoint).
    await pool.query(`
        CREATE TABLE IF NOT EXISTS devices (
            id            BIGSERIAL PRIMARY KEY,
            device_token  TEXT UNIQUE NOT NULL,
            device_model  TEXT,
            platform      TEXT,
            linked_phone  TEXT,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            revoked       BOOLEAN NOT NULL DEFAULT false
        );
    `);

    // Backfill for installs that created the table before linked_phone existed
    await pool.query(`ALTER TABLE devices ADD COLUMN IF NOT EXISTS linked_phone TEXT;`);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_devices_token
        ON devices (device_token);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_devices_linked_phone
        ON devices (linked_phone);
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS sos_events (
            id          BIGSERIAL PRIMARY KEY,
            session_id  TEXT UNIQUE NOT NULL,
            event       TEXT NOT NULL,
            timestamp   TIMESTAMPTZ NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            device_name TEXT,
            device_ip   TEXT,
            latitude    DOUBLE PRECISION,
            longitude   DOUBLE PRECISION,
            maps_link   TEXT
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS live_locations (
            id          BIGSERIAL PRIMARY KEY,
            session_id  TEXT NOT NULL,
            latitude    DOUBLE PRECISION NOT NULL,
            longitude   DOUBLE PRECISION NOT NULL,
            maps_link   TEXT,
            device_name TEXT,
            device_ip   TEXT,
            timestamp   TIMESTAMPTZ NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_live_locations_session
        ON live_locations (session_id, received_at DESC);
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS witnesses (
            id                   BIGSERIAL PRIMARY KEY,
            session_id           TEXT NOT NULL,
            rssi                 INTEGER NOT NULL,
            estimated_distance_m TEXT,
            witness_latitude     DOUBLE PRECISION,
            witness_longitude    DOUBLE PRECISION,
            timestamp            TIMESTAMPTZ NOT NULL,
            received_at          TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_witnesses_session
        ON witnesses (session_id, received_at DESC);
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS suspects (
            id                   BIGSERIAL PRIMARY KEY,
            session_id           TEXT NOT NULL,
            rssi                 INTEGER NOT NULL,
            estimated_distance_m TEXT,
            android_id           TEXT,
            device_model         TEXT,
            device_brand         TEXT,
            android_version      TEXT,
            imei                 TEXT,
            suspect_latitude     DOUBLE PRECISION,
            suspect_longitude    DOUBLE PRECISION,
            gps_accuracy_m       DOUBLE PRECISION,
            ip_address           TEXT,
            timestamp            TIMESTAMPTZ NOT NULL,
            received_at          TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_suspects_session
        ON suspects (session_id, received_at DESC);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_suspects_android_id
        ON suspects (android_id);
    `);

    // ── Trips — proactive "share my walk" tracking ─────────────────
    // Separate from sos_events/live_locations, which are emergency-
    // only. A trip starts the moment Protection Mode turns on with a
    // destination, and is expected to be short-lived and low-stakes —
    // guardian_phones is a plain TEXT[] since these are the user's
    // own emergency contacts, already stored client-side; nothing
    // here is collected about anyone who hasn't opted in.
    await pool.query(`
        CREATE TABLE IF NOT EXISTS trips (
            id                     BIGSERIAL PRIMARY KEY,
            session_id             TEXT UNIQUE NOT NULL,
            device_id              BIGINT REFERENCES devices(id),
            destination_address    TEXT,
            destination_latitude   DOUBLE PRECISION,
            destination_longitude  DOUBLE PRECISION,
            start_latitude         DOUBLE PRECISION,
            start_longitude        DOUBLE PRECISION,
            current_latitude       DOUBLE PRECISION,
            current_longitude      DOUBLE PRECISION,
            progress_percent       DOUBLE PRECISION,
            eta_minutes            INTEGER,
            guardian_phones        TEXT[] NOT NULL DEFAULT '{}',
            status                 TEXT NOT NULL DEFAULT 'active',
            started_at             TIMESTAMPTZ NOT NULL,
            ended_at               TIMESTAMPTZ,
            last_update_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
            created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_trips_session
        ON trips (session_id);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_trips_guardian_phones
        ON trips USING GIN (guardian_phones);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_trips_status
        ON trips (status);
    `);

    console.log('✅ Database ready — 6 tables (devices, sos_events, live_locations, witnesses, suspects, trips)');
}

// ═══════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ── Timing-safe string compare ───────────────────────────────────
// Avoids leaking key length/content via response-time differences.
function safeEqual(a, b) {
    const bufA = Buffer.from(String(a || ''));
    const bufB = Buffer.from(String(b || ''));
    if (bufA.length !== bufB.length) {
        // Still run a compare of equal-length buffers so the
        // early-return itself doesn't create an observable timing gap
        // for the common case of a wrong-length guess.
        crypto.timingSafeEqual(bufA, bufA);
        return false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
}

// ── ADMIN KEY auth ────────────────────────────────────────────────
// Used ONLY for the dashboard (index.html), entered manually by an
// operator via prompt() — never shipped inside the mobile app.
// Guards: GET/DELETE on sos_events, GET on witnesses, GET on suspects.
function requireAdminKey(req, res, next) {
    if (!process.env.API_KEY) {
        console.error('⚠️  API_KEY not set on server');
        return res.status(500).json({ error: 'Server misconfigured' });
    }
    const key = req.headers['x-api-key'];
    if (!safeEqual(key, process.env.API_KEY)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// ── DEVICE TOKEN auth ─────────────────────────────────────────────
// Used by the mobile app for all write endpoints (sos, location,
// witness, suspect POSTs). Each device gets its own token from
// POST /api/register-device — never a shared secret baked into
// every install. A leaked device token only allows writes from
// that one device identity, never reads of anyone else's data.
async function requireDeviceToken(req, res, next) {
    const token = req.headers['x-device-token'];
    if (!token) {
        return res.status(401).json({ error: 'Missing device token' });
    }
    try {
        const result = await pool.query(
            `SELECT id, revoked FROM devices WHERE device_token = $1`,
            [token]
        );
        const device = result.rows[0];
        if (!device || device.revoked) {
            return res.status(401).json({ error: 'Invalid or revoked device token' });
        }
        req.deviceId = device.id;
        // Fire-and-forget last_seen update — don't block the request on it
        pool.query(`UPDATE devices SET last_seen_at = now() WHERE id = $1`, [device.id])
            .catch((e) => console.error('⚠️  last_seen update failed:', e.message));
        next();
    } catch (e) {
        console.error('❌ Device token check failed:', e.message);
        return res.status(500).json({ error: 'Server error' });
    }
}

// ── Simple rate limiter (no external package needed) ─────────────
// Tracks requests per IP per minute for write endpoints.
const rateLimitMap = new Map();
function rateLimit(maxPerMinute) {
    return (req, res, next) => {
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
            || req.socket?.remoteAddress || 'unknown';
        const now = Date.now();
        const windowMs = 60 * 1000;

        const entry = rateLimitMap.get(ip);
        if (!entry || now - entry.start > windowMs) {
            rateLimitMap.set(ip, { count: 1, start: now });
            return next();
        }

        entry.count++;
        if (entry.count > maxPerMinute) {
            return res.status(429).json({ error: 'Too many requests' });
        }
        next();
    };
}

// Prune rate-limit entries whose window has fully expired.
setInterval(() => {
    const now = Date.now();
    const windowMs = 60 * 1000;
    for (const [ip, entry] of rateLimitMap.entries()) {
        if (now - entry.start > windowMs) rateLimitMap.delete(ip);
    }
}, 5 * 60 * 1000);

// ── Session ID validation ─────────────────────────────────────────
// New sessions are expected to be UUID v4 (see sos_service.dart).
// Legacy "SOS_<timestamp>" values are still accepted for backward
// compatibility with already-installed app versions, but new
// clients should always send a UUID.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LEGACY_SESSION_RE = /^SOS_\d{10,}$/;
function isValidSessionId(id) {
    return typeof id === 'string' &&
        id.length <= 64 &&
        (UUID_RE.test(id) || LEGACY_SESSION_RE.test(id));
}

// ═══════════════════════════════════════════════════════════════════
// DEVICE REGISTRATION
// ═══════════════════════════════════════════════════════════════════

// POST /api/register-device — app calls this once on first launch
// (or whenever it has no stored token). Returns a fresh device token.
// No auth required to call this — it's how a device gets credentials
// in the first place — but it's rate-limited to prevent abuse.
app.post('/api/register-device', rateLimit(10), async (req, res) => {
    const { device_model, platform } = req.body || {};

    const deviceToken = crypto.randomBytes(32).toString('hex');

    try {
        const result = await pool.query(
            `INSERT INTO devices (device_token, device_model, platform)
             VALUES ($1, $2, $3)
             RETURNING id`,
            [deviceToken, device_model || null, platform || null]
        );

        console.log(`📱 Device registered — id: ${result.rows[0].id} model: ${device_model}`);
        return res.status(200).json({ device_token: deviceToken });
    } catch (e) {
        console.error('❌ POST /api/register-device:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// POST /api/devices/:id/revoke — admin-only, e.g. if a token leaks
app.post('/api/devices/:id/revoke', requireAdminKey, async (req, res) => {
    try {
        await pool.query(`UPDATE devices SET revoked = true WHERE id = $1`, [req.params.id]);
        return res.json({ success: true });
    } catch (e) {
        console.error('❌ POST /api/devices/:id/revoke:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ── Phone normalization ──────────────────────────────────────────
// Contacts get typed/saved in inconsistent formats ("+91 98765
// 43210", "9876543210", "098765-43210"). Strip everything but
// digits, and drop a leading "0" or "91" country-code prefix so two
// different-looking strings for the same Indian number still match
// when we compare a guardian's linked phone against a trip's
// guardian_phones list. Not a full E.164 parser — good enough for
// exact-match lookups, not for validating a number is real.
function normalizePhone(phone) {
    if (!phone) return null;
    let digits = String(phone).replace(/\D/g, '');
    if (digits.length > 10 && digits.startsWith('91')) {
        digits = digits.slice(digits.length - 10);
    }
    if (digits.length === 11 && digits.startsWith('0')) {
        digits = digits.slice(1);
    }
    return digits || null;
}

// POST /api/devices/link-phone — "this device belongs to phone X"
// Lets GET /api/trips/active-for-guardian look up trips by the
// caller's own registered number, without ever accepting a phone
// number as a URL/query parameter (which would let anyone probe
// arbitrary numbers to see if someone is being tracked).
app.post('/api/devices/link-phone', requireDeviceToken, rateLimit(10), async (req, res) => {
    const { phone } = req.body || {};
    const normalized = normalizePhone(phone);
    if (!normalized) {
        return res.status(400).json({ error: 'Invalid phone number' });
    }
    try {
        await pool.query(
            `UPDATE devices SET linked_phone = $1 WHERE id = $2`,
            [normalized, req.deviceId]
        );
        return res.json({ success: true });
    } catch (e) {
        console.error('❌ POST /api/devices/link-phone:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// SOS EVENTS
// ═══════════════════════════════════════════════════════════════════

// POST /api/sos — app writes when SOS triggers (device-token auth)
app.post('/api/sos', requireDeviceToken, rateLimit(30), async (req, res) => {
    const { event, session_id, timestamp, device_name,
        device_ip, latitude, longitude, maps_link } = req.body;

    if (!event || !timestamp) {
        return res.status(400).json({ error: 'Missing required fields: event, timestamp' });
    }
    if (session_id && !isValidSessionId(session_id)) {
        return res.status(400).json({ error: 'Invalid session_id format' });
    }

    const sessionId = session_id || crypto.randomUUID();

    try {
        const result = await pool.query(
            `INSERT INTO sos_events
                (session_id, event, timestamp, device_name, device_ip, latitude, longitude, maps_link)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (session_id) DO UPDATE SET
                event        = EXCLUDED.event,
                timestamp    = EXCLUDED.timestamp,
                received_at  = now(),
                device_name  = EXCLUDED.device_name,
                device_ip    = EXCLUDED.device_ip,
                latitude     = EXCLUDED.latitude,
                longitude    = EXCLUDED.longitude,
                maps_link    = EXCLUDED.maps_link
             RETURNING id`,
            [sessionId, event, timestamp,
                device_name || 'Unknown', device_ip || 'Unknown',
                latitude || null, longitude || null, maps_link || null]
        );

        console.log(`🚨 SOS — session: ${sessionId} | device: ${device_name} | GPS: ${latitude}, ${longitude}`);
        return res.status(200).json({ success: true, id: result.rows[0].id, session_id: sessionId });
    } catch (e) {
        console.error('❌ POST /api/sos:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/sos — dashboard reads all events (admin key — victim privacy)
app.get('/api/sos', requireAdminKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, event, timestamp, received_at,
                    device_name, device_ip, latitude, longitude, maps_link
             FROM sos_events
             ORDER BY received_at DESC
             LIMIT 200`
        );
        res.json(result.rows);
    } catch (e) {
        console.error('❌ GET /api/sos:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// DELETE /api/sos/:id — dashboard admin action (admin key only)
app.delete('/api/sos/:id', requireAdminKey, async (req, res) => {
    try {
        await pool.query('DELETE FROM sos_events WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (e) {
        console.error('❌ DELETE /api/sos:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// LIVE LOCATIONS
// ═══════════════════════════════════════════════════════════════════

// POST /api/location — app writes every 10 seconds during SOS
app.post('/api/location', requireDeviceToken, rateLimit(120), async (req, res) => {
    const { session_id, latitude, longitude, maps_link,
        device_name, device_ip, timestamp } = req.body;

    if (!session_id || latitude == null || longitude == null) {
        return res.status(400).json({ error: 'Missing session_id, latitude, or longitude' });
    }
    if (!isValidSessionId(session_id)) {
        return res.status(400).json({ error: 'Invalid session_id format' });
    }

    const mapsLink = maps_link || `https://maps.google.com/?q=${latitude},${longitude}`;

    try {
        await pool.query(
            `INSERT INTO live_locations
                (session_id, latitude, longitude, maps_link, device_name, device_ip, timestamp)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [session_id, latitude, longitude, mapsLink,
                device_name || 'Unknown', device_ip || 'Unknown',
                timestamp || new Date().toISOString()]
        );

        // Keep only latest 50 points per session — saves database space
        await pool.query(
            `DELETE FROM live_locations
             WHERE session_id = $1
             AND id NOT IN (
                 SELECT id FROM live_locations
                 WHERE session_id = $1
                 ORDER BY received_at DESC
                 LIMIT 50
             )`,
            [session_id]
        );

        console.log(`📍 LOCATION — ${session_id} | ${latitude}, ${longitude}`);
        return res.status(200).json({ success: true });
    } catch (e) {
        console.error('❌ POST /api/location:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/location/:sessionId — track.html reads this (public — needed
// for the SMS tracking link to work with no login). Session IDs are now
// random UUIDs (see isValidSessionId), so this is no longer brute-forceable
// the way a millisecond-timestamp session id was.
app.get('/api/location/:sessionId', async (req, res) => {
    if (!isValidSessionId(req.params.sessionId)) {
        return res.status(400).json({ error: 'Invalid session id' });
    }
    try {
        const result = await pool.query(
            `SELECT session_id, latitude, longitude, maps_link,
                    device_name, device_ip, timestamp, received_at
             FROM live_locations
             WHERE session_id = $1
             ORDER BY received_at DESC
             LIMIT 1`,
            [req.params.sessionId]
        );
        res.json(result.rows[0] || null);
    } catch (e) {
        console.error('❌ GET /api/location/:id:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/location/:sessionId/history — track.html history section (public)
app.get('/api/location/:sessionId/history', async (req, res) => {
    if (!isValidSessionId(req.params.sessionId)) {
        return res.status(400).json({ error: 'Invalid session id' });
    }
    try {
        const result = await pool.query(
            `SELECT latitude, longitude, maps_link, timestamp, received_at
             FROM live_locations
             WHERE session_id = $1
             ORDER BY received_at DESC
             LIMIT 10`,
            [req.params.sessionId]
        );
        res.json(result.rows);
    } catch (e) {
        console.error('❌ GET /api/location/:id/history:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/location — all sessions latest point (dashboard, admin key)
app.get('/api/location', requireAdminKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT DISTINCT ON (session_id)
                    session_id, latitude, longitude, maps_link,
                    device_name, device_ip, timestamp, received_at
             FROM live_locations
             ORDER BY session_id, received_at DESC`
        );
        res.json(result.rows);
    } catch (e) {
        console.error('❌ GET /api/location:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// WITNESSES
// Kavach users with protection ON who were nearby during SOS.
// Their phones detect the BLE beacon and report here (opt-in, since
// scanning only runs when that user turned Protection on themselves).
// ═══════════════════════════════════════════════════════════════════

// POST /api/witness — witness phone reports (device-token auth)
app.post('/api/witness', requireDeviceToken, rateLimit(60), async (req, res) => {
    const { session_id, rssi, estimated_distance_m,
        witness_latitude, witness_longitude, timestamp } = req.body;

    if (!session_id || rssi == null) {
        return res.status(400).json({ error: 'Missing session_id or rssi' });
    }
    if (!isValidSessionId(session_id)) {
        return res.status(400).json({ error: 'Invalid session_id format' });
    }
    if (typeof rssi !== 'number' || rssi > 0 || rssi < -120) {
        return res.status(400).json({ error: 'Invalid rssi value' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO witnesses
                (session_id, rssi, estimated_distance_m, witness_latitude, witness_longitude, timestamp)
             VALUES ($1,$2,$3,$4,$5,$6)
             RETURNING id`,
            [session_id, rssi, estimated_distance_m || null,
                witness_latitude || null, witness_longitude || null,
                timestamp || new Date().toISOString()]
        );

        console.log(`📡 WITNESS — session: ${session_id} | RSSI: ${rssi} dBm | GPS: ${witness_latitude}, ${witness_longitude}`);
        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) {
        console.error('❌ POST /api/witness:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/witness/:sessionId — dashboard reads witnesses for one SOS
app.get('/api/witness/:sessionId', requireAdminKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m,
                    witness_latitude, witness_longitude, timestamp, received_at
             FROM witnesses
             WHERE session_id = $1
             ORDER BY rssi DESC, received_at ASC`,
            [req.params.sessionId]
        );
        return res.json({
            session_id: req.params.sessionId,
            witness_count: result.rows.length,
            witnesses: result.rows,
        });
    } catch (e) {
        console.error('❌ GET /api/witness/:id:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/witness — all witness records (dashboard overview)
app.get('/api/witness', requireAdminKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m,
                    witness_latitude, witness_longitude, timestamp, received_at
             FROM witnesses
             ORDER BY received_at DESC
             LIMIT 200`
        );
        return res.json(result.rows);
    } catch (e) {
        console.error('❌ GET /api/witness:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// SUSPECTS
// Kept functionally unchanged from the existing schema/endpoints —
// only the auth model changes here (device-token for writes, admin
// key for reads), consistent with the rest of this file.
// ═══════════════════════════════════════════════════════════════════

// POST /api/suspect — reporting device authenticates with its own
// device token now, instead of the old shared static key.
app.post('/api/suspect', requireDeviceToken, rateLimit(60), async (req, res) => {
    const {
        session_id, rssi, estimated_distance_m,
        android_id, device_model, device_brand, android_version, imei,
        suspect_latitude, suspect_longitude, gps_accuracy_m, timestamp,
    } = req.body;

    if (!session_id || rssi == null) {
        return res.status(400).json({ error: 'Missing session_id or rssi' });
    }
    if (!isValidSessionId(session_id)) {
        return res.status(400).json({ error: 'Invalid session_id format' });
    }

    const ip_address =
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.socket?.remoteAddress ||
        req.ip || null;

    try {
        const result = await pool.query(
            `INSERT INTO suspects
                (session_id, rssi, estimated_distance_m,
                 android_id, device_model, device_brand, android_version,
                 imei, suspect_latitude, suspect_longitude, gps_accuracy_m,
                 ip_address, timestamp)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             RETURNING id`,
            [session_id, rssi, estimated_distance_m || null,
                android_id || null, device_model || null,
                device_brand || null, android_version || null, imei || null,
                suspect_latitude || null, suspect_longitude || null,
                gps_accuracy_m || null, ip_address,
                timestamp || new Date().toISOString()]
        );

        console.log(
            `🕵️  SUSPECT — session: ${session_id}`,
            `| RSSI: ${rssi} dBm (~${estimated_distance_m}m)`,
            `| Device: ${device_model}`,
            `| IP: ${ip_address}`
        );

        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) {
        console.error('❌ POST /api/suspect:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/suspect/:sessionId — admin key only (police-facing data)
app.get('/api/suspect/:sessionId', requireAdminKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m,
                    android_id, device_model, device_brand, android_version,
                    imei, suspect_latitude, suspect_longitude, gps_accuracy_m,
                    ip_address, timestamp, received_at
             FROM suspects
             WHERE session_id = $1
             ORDER BY rssi DESC, received_at ASC`,
            [req.params.sessionId]
        );
        return res.json({
            session_id: req.params.sessionId,
            suspect_count: result.rows.length,
            note: 'Android ID is unique per device. IP is traceable via ISP with legal order.',
            suspects: result.rows,
        });
    } catch (e) {
        console.error('❌ GET /api/suspect/:id:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/suspect — admin key only
app.get('/api/suspect', requireAdminKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m,
                    android_id, device_model, device_brand,
                    imei, suspect_latitude, suspect_longitude,
                    ip_address, timestamp, received_at
             FROM suspects
             ORDER BY received_at DESC
             LIMIT 500`
        );
        return res.json({ total: result.rows.length, suspects: result.rows });
    } catch (e) {
        console.error('❌ GET /api/suspect:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// TRIPS
// Proactive "share my walk" tracking — starts when Protection Mode
// turns on with a destination, not when something goes wrong.
// ═══════════════════════════════════════════════════════════════════

// Ownership check shared by the location-update and end endpoints:
// only the device that created a trip may update it. Session IDs are
// unguessable UUIDs already, but this closes the gap where a device
// token, if it ever leaked, could be used to tamper with someone
// else's trip rather than just spoof new data under its own identity.
async function loadOwnedTrip(sessionId, deviceId) {
    const result = await pool.query(
        `SELECT id, device_id, status FROM trips WHERE session_id = $1`,
        [sessionId]
    );
    const trip = result.rows[0];
    if (!trip) return { trip: null, owned: false };
    return { trip, owned: trip.device_id === deviceId };
}

// POST /api/trips — create a trip (device-token auth)
app.post('/api/trips', requireDeviceToken, rateLimit(10), async (req, res) => {
    const {
        session_id, destination_address,
        destination_latitude, destination_longitude,
        start_latitude, start_longitude,
        guardian_phones, started_at,
    } = req.body;

    if (!session_id || destination_latitude == null || destination_longitude == null) {
        return res.status(400).json({
            error: 'Missing session_id, destination_latitude, or destination_longitude',
        });
    }
    if (!isValidSessionId(session_id)) {
        return res.status(400).json({ error: 'Invalid session_id format' });
    }

    const normalizedGuardians = Array.isArray(guardian_phones)
        ? guardian_phones.map(normalizePhone).filter(Boolean)
        : [];

    try {
        await pool.query(
            `INSERT INTO trips
                (session_id, device_id, destination_address,
                 destination_latitude, destination_longitude,
                 start_latitude, start_longitude,
                 current_latitude, current_longitude,
                 guardian_phones, status, started_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$6,$7,$8,'active',$9)
             ON CONFLICT (session_id) DO NOTHING`,
            [session_id, req.deviceId, destination_address || null,
                destination_latitude, destination_longitude,
                start_latitude || null, start_longitude || null,
                normalizedGuardians,
                started_at || new Date().toISOString()]
        );

        console.log(`🚶 TRIP started — session: ${session_id} → "${destination_address}"`);
        return res.status(200).json({ success: true, session_id });
    } catch (e) {
        console.error('❌ POST /api/trips:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// POST /api/trips/:sessionId/location — periodic update while active
app.post('/api/trips/:sessionId/location', requireDeviceToken, rateLimit(30), async (req, res) => {
    const { latitude, longitude, progress_percent, eta_minutes } = req.body;
    if (latitude == null || longitude == null) {
        return res.status(400).json({ error: 'Missing latitude or longitude' });
    }

    try {
        const { trip, owned } = await loadOwnedTrip(req.params.sessionId, req.deviceId);
        if (!trip) return res.status(404).json({ error: 'Trip not found' });
        if (!owned) return res.status(403).json({ error: 'Not your trip' });
        if (trip.status !== 'active') {
            return res.status(409).json({ error: `Trip already ${trip.status}` });
        }

        await pool.query(
            `UPDATE trips SET
                current_latitude = $1, current_longitude = $2,
                progress_percent = $3, eta_minutes = $4,
                last_update_at = now()
             WHERE session_id = $5`,
            [latitude, longitude, progress_percent ?? null, eta_minutes ?? null,
                req.params.sessionId]
        );

        // Push straight to any guardian currently watching — this is
        // what makes the map glide live instead of waiting for their
        // next poll. No-ops instantly if nobody's watching.
        broadcastTripUpdate(req.params.sessionId, {
            type: 'location',
            session_id: req.params.sessionId,
            latitude,
            longitude,
            progress_percent: progress_percent ?? null,
            eta_minutes: eta_minutes ?? null,
            timestamp: new Date().toISOString(),
        });

        return res.status(200).json({ success: true });
    } catch (e) {
        console.error('❌ POST /api/trips/:id/location:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// POST /api/trips/:sessionId/end — mark completed/cancelled
app.post('/api/trips/:sessionId/end', requireDeviceToken, rateLimit(10), async (req, res) => {
    const { status } = req.body;
    const finalStatus = status === 'completed' ? 'completed' : 'cancelled';

    try {
        const { trip, owned } = await loadOwnedTrip(req.params.sessionId, req.deviceId);
        if (!trip) return res.status(404).json({ error: 'Trip not found' });
        if (!owned) return res.status(403).json({ error: 'Not your trip' });

        await pool.query(
            `UPDATE trips SET status = $1, ended_at = now() WHERE session_id = $2`,
            [finalStatus, req.params.sessionId]
        );

        broadcastTripUpdate(req.params.sessionId, {
            type: 'ended',
            session_id: req.params.sessionId,
            status: finalStatus,
        });

        console.log(`🏁 TRIP ended — session: ${req.params.sessionId} status: ${finalStatus}`);
        return res.status(200).json({ success: true });
    } catch (e) {
        console.error('❌ POST /api/trips/:id/end:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ── Trip data cleanup ────────────────────────────────────────────
// Trips are NOT kept permanently. A finished trip's row (and every
// GPS point that came with it) stays queryable for a short grace
// window — long enough for the guardian's trip_track.html tab, still
// open from during the walk, to render the final "Arrived safely" /
// "Trip ended" state — then it's deleted outright. This is different
// from sos_events/live_locations (real emergencies), which are kept
// so the person and police can refer back to what happened.
const TRIP_GRACE_PERIOD_MINUTES = 10;
// Also auto-expire any trip that never got a proper /end call (app
// killed, phone died, etc.) rather than leaving it "active" forever —
// mirrors TripService's own 4-hour client-side safety cap, with margin.
const TRIP_ABANDONED_HOURS = 6;

async function cleanupOldTrips() {
    try {
        const abandoned = await pool.query(
            `UPDATE trips SET status = 'cancelled', ended_at = now()
             WHERE status = 'active' AND last_update_at < now() - interval '${TRIP_ABANDONED_HOURS} hours'`
        );
        if (abandoned.rowCount > 0) {
            console.log(`🧹 Auto-expired ${abandoned.rowCount} abandoned trip(s)`);
        }

        const deleted = await pool.query(
            `DELETE FROM trips
             WHERE status != 'active'
             AND ended_at < now() - interval '${TRIP_GRACE_PERIOD_MINUTES} minutes'`
        );
        if (deleted.rowCount > 0) {
            console.log(`🧹 Deleted ${deleted.rowCount} finished trip(s) — no permanent trip storage`);
        }
    } catch (e) {
        console.error('❌ Trip cleanup failed:', e.message);
    }
}

setInterval(cleanupOldTrips, 5 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════
// LIVE TRIP WEBSOCKET — instant push instead of polling
//
// Same architecture Rapido/Uber/Swiggy use for live captain tracking:
// the traveling phone still POSTs its position over plain HTTP (see
// POST /api/trips/:sessionId/location below) — nothing changes there.
// What's new is that the moment that POST lands, the server pushes it
// straight to any guardian's browser that's watching that trip, over
// a WebSocket, instead of making them wait for their next poll.
//
// trip_track.html falls back to its existing HTTP polling if the
// WebSocket connection fails for any reason (corporate proxy blocking
// it, brief network hiccup, etc.) — this is additive, not a
// replacement, so nothing breaks for anyone on a restrictive network.
// ═══════════════════════════════════════════════════════════════════

const wss = new WebSocketServer({ server, path: '/ws/trip' });

// sessionId -> Set of WebSocket clients currently watching that trip
const tripSubscribers = new Map();

wss.on('connection', (ws) => {
    ws.subscribedSessionId = null;

    ws.on('message', (raw) => {
        let msg;
        try {
            msg = JSON.parse(raw.toString());
        } catch {
            return;
        }

        if (msg.type === 'subscribe' && isValidSessionId(msg.session_id)) {
            // A client only ever watches one trip at a time in this
            // app, but guard against a stale subscription anyway.
            if (ws.subscribedSessionId) {
                tripSubscribers.get(ws.subscribedSessionId)?.delete(ws);
            }
            ws.subscribedSessionId = msg.session_id;
            if (!tripSubscribers.has(msg.session_id)) {
                tripSubscribers.set(msg.session_id, new Set());
            }
            tripSubscribers.get(msg.session_id).add(ws);
        }
    });

    ws.on('close', () => {
        if (ws.subscribedSessionId) {
            const set = tripSubscribers.get(ws.subscribedSessionId);
            set?.delete(ws);
            if (set && set.size === 0) tripSubscribers.delete(ws.subscribedSessionId);
        }
    });
});

// Sends a message to every browser currently watching this session.
// Silently does nothing if nobody is watching — this is the common
// case (guardian hasn't opened the link yet, or already closed it).
function broadcastTripUpdate(sessionId, payload) {
    const subs = tripSubscribers.get(sessionId);
    if (!subs || subs.size === 0) return;
    const message = JSON.stringify(payload);
    for (const client of subs) {
        if (client.readyState === 1 /* OPEN */) {
            try { client.send(message); } catch (_) { }
        }
    }
}


app.get('/api/trips/:sessionId', async (req, res) => {
    if (!isValidSessionId(req.params.sessionId)) {
        return res.status(400).json({ error: 'Invalid session id' });
    }
    try {
        const result = await pool.query(
            `SELECT session_id, destination_address,
                    destination_latitude, destination_longitude,
                    current_latitude, current_longitude,
                    progress_percent, eta_minutes, status,
                    started_at, ended_at, last_update_at
             FROM trips WHERE session_id = $1`,
            [req.params.sessionId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Trip not found' });
        }
        return res.json(result.rows[0]);
    } catch (e) {
        console.error('❌ GET /api/trips/:id:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/trips/active-for-guardian — device-token auth, no phone
// param. Looks up the CALLING device's own linked_phone (set via
// POST /api/devices/link-phone) and returns any active trip where
// that phone is listed as a guardian. This is what home_screen.dart
// calls on app resume to decide whether to show a local notification.
app.get('/api/trips/active-for-guardian', requireDeviceToken, rateLimit(30), async (req, res) => {
    try {
        const deviceResult = await pool.query(
            `SELECT linked_phone FROM devices WHERE id = $1`,
            [req.deviceId]
        );
        const linkedPhone = deviceResult.rows[0]?.linked_phone;
        if (!linkedPhone) {
            return res.json({ trips: [] }); // no linked number — nothing to show
        }

        const result = await pool.query(
            `SELECT session_id, destination_address,
                    current_latitude, current_longitude,
                    progress_percent, eta_minutes, started_at
             FROM trips
             WHERE status = 'active' AND $1 = ANY(guardian_phones)
             ORDER BY started_at DESC`,
            [linkedPhone]
        );

        return res.json({ trips: result.rows });
    } catch (e) {
        console.error('❌ GET /api/trips/active-for-guardian:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// STATIC ROUTES
// ═══════════════════════════════════════════════════════════════════

app.get('/track/:sessionId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'track.html'));
});

app.get('/trip/:sessionId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'trip_track.html'));
});

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', uptime: Math.floor(process.uptime()), db: 'connected' });
    } catch (e) {
        res.status(503).json({ status: 'error', db: 'disconnected' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════════

initDB().then(() => {
    server.listen(PORT, () => {
        console.log(`\n✅ Kavach Server on port ${PORT}`);
        console.log(`   Dashboard        : http://localhost:${PORT}`);
        console.log(`   Register device  : POST /api/register-device (no auth)`);
        console.log(`   SOS              : POST /api/sos       (device token)`);
        console.log(`   Location         : POST /api/location  (device token)`);
        console.log(`   Witnesses        : GET  /api/witness   (admin key)`);
        console.log(`   Suspects         : GET  /api/suspect   (admin key)`);
        console.log(`   Trips            : POST /api/trips     (device token)`);
        console.log(`   Trip tracking    : GET  /trip/:sessionId (public)`);
        console.log(`   Live trip push   : WS   /ws/trip (public, subscribe by session_id)\n`);
        if (!process.env.API_KEY) {
            console.warn('⚠️  API_KEY env var not set — admin dashboard reads/deletes will be rejected');
        }
    });
}).catch(err => {
    console.error('❌ Database init failed:', err.message);
    process.exit(1);
});