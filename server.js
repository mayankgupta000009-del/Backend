const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════════════
// DATABASE — Supabase PostgreSQL
//
// DATABASE_URL is set as an environment variable on Render.
// NEVER hardcode the connection string here.
//
// Supabase requires SSL but uses a self-signed-style cert chain that
// Node rejects by default — rejectUnauthorized: false is the standard
// fix recommended by Supabase docs for this exact case.
// ═══════════════════════════════════════════════════════════════════

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

// Create tables on startup if they don't exist
async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS sos_events (
            id BIGSERIAL PRIMARY KEY,
            session_id TEXT UNIQUE NOT NULL,
            event TEXT NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            device_name TEXT,
            device_ip TEXT,
            latitude DOUBLE PRECISION,
            longitude DOUBLE PRECISION,
            maps_link TEXT
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS live_locations (
            id BIGSERIAL PRIMARY KEY,
            session_id TEXT NOT NULL,
            latitude DOUBLE PRECISION NOT NULL,
            longitude DOUBLE PRECISION NOT NULL,
            maps_link TEXT,
            device_name TEXT,
            device_ip TEXT,
            timestamp TIMESTAMPTZ NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    // Index for fast "latest location per session" lookups
    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_live_locations_session
        ON live_locations (session_id, received_at DESC);
    `);

    console.log('✅ Database tables ready');
}

// ═══════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ── API key authentication ───────────────────────────────────────
// Protects write endpoints (/api/sos, /api/location) from fake SOS
// spam. The Flutter app sends this in the x-api-key header.
//
// API_KEY is set as an environment variable on Render.
// Generate a strong random key, e.g.:
//   node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
//
// GET endpoints (dashboard, tracking page) remain public —
// they don't need the key.
function requireApiKey(req, res, next) {
    const key = req.headers['x-api-key'];
    if (!process.env.API_KEY) {
        // Fail safe: if no API_KEY configured on server, block writes
        // rather than silently allowing unauthenticated access.
        console.error('⚠️ API_KEY not set on server — rejecting write');
        return res.status(500).json({ error: 'Server misconfigured' });
    }
    if (key !== process.env.API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// ═══════════════════════════════════════════════════════════════════
// POST /api/sos — Initial SOS trigger
//
// Uses ON CONFLICT to handle duplicate session_id (e.g. retries).
// ═══════════════════════════════════════════════════════════════════

app.post('/api/sos', requireApiKey, async (req, res) => {
    const { event, session_id, timestamp, device_name,
        device_ip, latitude, longitude, maps_link } = req.body;

    if (!event || !timestamp) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const sessionId = session_id || `SOS_${Date.now()}`;

    try {
        const result = await pool.query(
            `INSERT INTO sos_events
                (session_id, event, timestamp, device_name, device_ip,
                 latitude, longitude, maps_link)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (session_id) DO UPDATE SET
                event = EXCLUDED.event,
                timestamp = EXCLUDED.timestamp,
                received_at = now(),
                device_name = EXCLUDED.device_name,
                device_ip = EXCLUDED.device_ip,
                latitude = EXCLUDED.latitude,
                longitude = EXCLUDED.longitude,
                maps_link = EXCLUDED.maps_link
             RETURNING id`,
            [sessionId, event, timestamp, device_name || 'Unknown',
                device_ip || 'Unknown', latitude || null, longitude || null,
                maps_link || null]
        );

        console.log('🚨 SOS RECEIVED:', sessionId,
            '| Device:', device_name,
            '| Location:', latitude, longitude);

        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) {
        console.error('❌ /api/sos error:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// POST /api/location — Live location update (every 10s from app)
// ═══════════════════════════════════════════════════════════════════

app.post('/api/location', requireApiKey, async (req, res) => {
    const { session_id, latitude, longitude,
        maps_link, device_name, device_ip, timestamp } = req.body;

    if (!session_id || latitude == null || longitude == null) {
        return res.status(400).json({ error: 'Missing fields' });
    }

    const mapsLink = maps_link || `https://maps.google.com/?q=${latitude},${longitude}`;

    try {
        await pool.query(
            `INSERT INTO live_locations
                (session_id, latitude, longitude, maps_link,
                 device_name, device_ip, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [session_id, latitude, longitude, mapsLink,
                device_name || 'Unknown', device_ip || 'Unknown',
                timestamp || new Date().toISOString()]
        );

        // Trim old history for this session — keep latest 50 points
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

        console.log('📍 LOCATION UPDATE:', session_id,
            '| Lat:', latitude, '| Lng:', longitude);

        return res.status(200).json({ success: true });
    } catch (e) {
        console.error('❌ /api/location error:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// GET /api/sos — All SOS events (newest first)
// ═══════════════════════════════════════════════════════════════════

app.get('/api/sos', async (req, res) => {
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
        console.error('❌ /api/sos GET error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// GET /api/location/:sessionId — Latest location for session
// ═══════════════════════════════════════════════════════════════════

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
        console.error('❌ /api/location/:id error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// GET /api/location/:sessionId/history — Last N points for a session
// New endpoint — track.html can use this for the history list instead
// of accumulating client-side across polls.
// ═══════════════════════════════════════════════════════════════════

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
        console.error('❌ /api/location/:id/history error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// GET /api/location — All latest locations (one per session)
// ═══════════════════════════════════════════════════════════════════

app.get('/api/location', async (req, res) => {
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
        console.error('❌ /api/location GET error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// GET /track/:sessionId — Live tracking page (public, no key needed)
// ═══════════════════════════════════════════════════════════════════

app.get('/track/:sessionId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'track.html'));
});

// ═══════════════════════════════════════════════════════════════════
// DELETE /api/sos/:id — requires API key (dashboard admin action)
// ═══════════════════════════════════════════════════════════════════

app.delete('/api/sos/:id', requireApiKey, async (req, res) => {
    try {
        await pool.query(`DELETE FROM sos_events WHERE id = $1`, [req.params.id]);
        res.json({ success: true });
    } catch (e) {
        console.error('❌ DELETE /api/sos error:', e.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// GET /health — keep-alive endpoint (no auth)
//
// Render free tier spins down after ~15 min idle. Ping this from
// an external monitor (UptimeRobot, cron-job.org — free) every
// 10 minutes to keep the server warm for real emergencies.
// ═══════════════════════════════════════════════════════════════════

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok', uptime: process.uptime(), db: 'connected' });
    } catch (e) {
        res.status(503).json({ status: 'error', db: 'disconnected' });
    }
});

// ═══════════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════════

initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`✅ Kavach Server running on port ${PORT}`);
        console.log(`📊 Dashboard: http://localhost:${PORT}`);
        console.log(`🚨 SOS endpoint: http://localhost:${PORT}/api/sos`);
        console.log(`📍 Location endpoint: http://localhost:${PORT}/api/location`);
        if (!process.env.API_KEY) {
            console.warn('⚠️ API_KEY not set — write endpoints will reject all requests');
        }
    });
}).catch(err => {
    console.error('❌ Database init failed:', err.message);
    process.exit(1);
});
