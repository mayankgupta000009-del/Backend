const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════════════════════════════

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

async function initDB() {
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

    console.log('✅ Database ready — 4 tables (sos_events, live_locations, witnesses, suspects)');
}

// ═══════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ── API key auth ─────────────────────────────────────────────────
// All write endpoints (POST/DELETE) require x-api-key header.
// GET /api/sos and GET /api/location are public (for tracking links).
// GET /api/suspect and GET /api/witness require key (police data).
function requireApiKey(req, res, next) {
    const key = req.headers['x-api-key'];
    if (!process.env.API_KEY) {
        console.error('⚠️  API_KEY not set on server');
        return res.status(500).json({ error: 'Server misconfigured' });
    }
    if (key !== process.env.API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// ── Simple rate limiter (no external package needed) ─────────────
// Tracks requests per IP per minute for write endpoints.
// Prevents database spam if API key leaks.
const rateLimitMap = new Map();
function rateLimit(maxPerMinute) {
    return (req, res, next) => {
        const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
            || req.socket?.remoteAddress || 'unknown';
        const now = Date.now();
        const windowMs = 60 * 1000;

        if (!rateLimitMap.has(ip)) {
            rateLimitMap.set(ip, { count: 1, start: now });
            return next();
        }

        const entry = rateLimitMap.get(ip);
        if (now - entry.start > windowMs) {
            // Reset window
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

// Clean up rate limit map every 5 minutes to prevent memory growth
setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of rateLimitMap.entries()) {
        if (now - entry.start > 60 * 1000) rateLimitMap.delete(ip);
    }
}, 5 * 60 * 1000);

// ═══════════════════════════════════════════════════════════════════
// SOS EVENTS
// ═══════════════════════════════════════════════════════════════════

// POST /api/sos — app writes when SOS triggers
app.post('/api/sos', requireApiKey, rateLimit(30), async (req, res) => {
    const { event, session_id, timestamp, device_name,
        device_ip, latitude, longitude, maps_link } = req.body;

    if (!event || !timestamp) {
        return res.status(400).json({ error: 'Missing required fields: event, timestamp' });
    }

    const sessionId = session_id || `SOS_${Date.now()}`;

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
        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) {
        console.error('❌ POST /api/sos:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/sos — dashboard reads all events (requires key — victim privacy)
app.get('/api/sos', requireApiKey, async (req, res) => {
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

// DELETE /api/sos/:id — dashboard admin action
app.delete('/api/sos/:id', requireApiKey, async (req, res) => {
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
app.post('/api/location', requireApiKey, rateLimit(120), async (req, res) => {
    const { session_id, latitude, longitude, maps_link,
        device_name, device_ip, timestamp } = req.body;

    if (!session_id || latitude == null || longitude == null) {
        return res.status(400).json({ error: 'Missing session_id, latitude, or longitude' });
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

// GET /api/location/:sessionId — track.html reads this (public — needed for tracking link)
app.get('/api/location/:sessionId', async (req, res) => {
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

// GET /api/location — all sessions latest point (dashboard, requires key)
app.get('/api/location', requireApiKey, async (req, res) => {
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
// Their phones detect the BLE beacon and silently report here.
// ═══════════════════════════════════════════════════════════════════

// POST /api/witness — witness phone silently reports
app.post('/api/witness', requireApiKey, rateLimit(60), async (req, res) => {
    const { session_id, rssi, estimated_distance_m,
        witness_latitude, witness_longitude, timestamp } = req.body;

    if (!session_id || rssi == null) {
        return res.status(400).json({ error: 'Missing session_id or rssi' });
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

// GET /api/witness/:sessionId — police/dashboard reads witnesses for one SOS
app.get('/api/witness/:sessionId', requireApiKey, async (req, res) => {
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
app.get('/api/witness', requireApiKey, async (req, res) => {
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
// Any phone with Kavach installed that was within 5-10m of victim
// when SOS fired. Silently fingerprinted. Police panel only.
// Requires API key on ALL endpoints — this is sensitive data.
// ═══════════════════════════════════════════════════════════════════

// POST /api/suspect — suspect phone silently reports (native KavachService.kt)
app.post('/api/suspect', requireApiKey, rateLimit(60), async (req, res) => {
    const {
        session_id, rssi, estimated_distance_m,
        android_id, device_model, device_brand, android_version, imei,
        suspect_latitude, suspect_longitude, gps_accuracy_m, timestamp,
    } = req.body;

    if (!session_id || rssi == null) {
        return res.status(400).json({ error: 'Missing session_id or rssi' });
    }

    // Server captures real public IP from HTTP request headers
    // Works correctly behind Render's reverse proxy
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
            `| Android ID: ${android_id}`,
            `| IMEI: ${imei || 'n/a (Android 10+)'}`,
            `| GPS: ${suspect_latitude}, ${suspect_longitude}`,
            `| IP: ${ip_address}`
        );

        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) {
        console.error('❌ POST /api/suspect:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET /api/suspect/:sessionId — all suspects for one SOS session (police use)
app.get('/api/suspect/:sessionId', requireApiKey, async (req, res) => {
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

// GET /api/suspect — all suspect records across all sessions (admin overview)
app.get('/api/suspect', requireApiKey, async (req, res) => {
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
// STATIC ROUTES
// ═══════════════════════════════════════════════════════════════════

// Live tracking page — public (contact receives SMS with this link)
app.get('/track/:sessionId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'track.html'));
});

// Health check — used by UptimeRobot to keep Render warm
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
    app.listen(PORT, () => {
        console.log(`\n✅ Kavach Server on port ${PORT}`);
        console.log(`   Dashboard : http://localhost:${PORT}`);
        console.log(`   SOS       : POST /api/sos  (key required)`);
        console.log(`   Location  : POST /api/location  (key required)`);
        console.log(`   Witnesses : GET  /api/witness   (key required)`);
        console.log(`   Suspects  : GET  /api/suspect   (key required)\n`);
        if (!process.env.API_KEY) {
            console.warn('⚠️  API_KEY env var not set — all writes will be rejected');
        }
    });
}).catch(err => {
    console.error('❌ Database init failed:', err.message);
    process.exit(1);
});