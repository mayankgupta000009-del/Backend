const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

async function initDB() {
    // ── SOS Events ───────────────────────────────────────────────
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

    // ── Live Locations ───────────────────────────────────────────
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

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_live_locations_session
        ON live_locations (session_id, received_at DESC);
    `);

    // ── Witnesses — Kavach users nearby during SOS ────────────────
    await pool.query(`
        CREATE TABLE IF NOT EXISTS witnesses (
            id           BIGSERIAL PRIMARY KEY,
            session_id   TEXT NOT NULL,
            rssi         INTEGER NOT NULL,
            estimated_distance_m  TEXT,
            witness_latitude      DOUBLE PRECISION,
            witness_longitude     DOUBLE PRECISION,
            timestamp    TIMESTAMPTZ NOT NULL,
            received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_witnesses_session
        ON witnesses (session_id, received_at DESC);
    `);

    // ── Suspects — device fingerprints of nearby phones ──────────
    // SEPARATE from all other tables — police panel only
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

    console.log('✅ Database tables ready (sos_events, live_locations, witnesses, suspects)');
}

// ── Middleware ────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

function requireApiKey(req, res, next) {
    const key = req.headers['x-api-key'];
    if (!process.env.API_KEY) {
        console.error('⚠️ API_KEY not set on server — rejecting write');
        return res.status(500).json({ error: 'Server misconfigured' });
    }
    if (key !== process.env.API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// ═══════════════════════════════════════════════════════════════════
// SOS EVENTS
// ═══════════════════════════════════════════════════════════════════

app.post('/api/sos', requireApiKey, async (req, res) => {
    const { event, session_id, timestamp, device_name,
        device_ip, latitude, longitude, maps_link } = req.body;
    if (!event || !timestamp) return res.status(400).json({ error: 'Missing fields' });
    const sessionId = session_id || `SOS_${Date.now()}`;
    try {
        const result = await pool.query(
            `INSERT INTO sos_events
                (session_id, event, timestamp, device_name, device_ip, latitude, longitude, maps_link)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (session_id) DO UPDATE SET
                event=EXCLUDED.event, timestamp=EXCLUDED.timestamp, received_at=now(),
                device_name=EXCLUDED.device_name, device_ip=EXCLUDED.device_ip,
                latitude=EXCLUDED.latitude, longitude=EXCLUDED.longitude, maps_link=EXCLUDED.maps_link
             RETURNING id`,
            [sessionId, event, timestamp, device_name || 'Unknown', device_ip || 'Unknown',
                latitude || null, longitude || null, maps_link || null]
        );
        console.log('🚨 SOS RECEIVED:', sessionId, '| Device:', device_name, '| Location:', latitude, longitude);
        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) {
        console.error('❌ /api/sos error:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

app.get('/api/sos', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, event, timestamp, received_at,
                    device_name, device_ip, latitude, longitude, maps_link
             FROM sos_events ORDER BY received_at DESC LIMIT 200`
        );
        res.json(result.rows);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.delete('/api/sos/:id', requireApiKey, async (req, res) => {
    try {
        await pool.query(`DELETE FROM sos_events WHERE id = $1`, [req.params.id]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// ═══════════════════════════════════════════════════════════════════
// LIVE LOCATIONS
// ═══════════════════════════════════════════════════════════════════

app.post('/api/location', requireApiKey, async (req, res) => {
    const { session_id, latitude, longitude, maps_link, device_name, device_ip, timestamp } = req.body;
    if (!session_id || latitude == null || longitude == null)
        return res.status(400).json({ error: 'Missing fields' });
    const mapsLink = maps_link || `https://maps.google.com/?q=${latitude},${longitude}`;
    try {
        await pool.query(
            `INSERT INTO live_locations (session_id, latitude, longitude, maps_link, device_name, device_ip, timestamp)
             VALUES ($1,$2,$3,$4,$5,$6,$7)`,
            [session_id, latitude, longitude, mapsLink, device_name || 'Unknown', device_ip || 'Unknown',
                timestamp || new Date().toISOString()]
        );
        await pool.query(
            `DELETE FROM live_locations WHERE session_id=$1 AND id NOT IN (
                SELECT id FROM live_locations WHERE session_id=$1 ORDER BY received_at DESC LIMIT 50
             )`, [session_id]
        );
        console.log('📍 LOCATION UPDATE:', session_id, '| Lat:', latitude, '| Lng:', longitude);
        return res.status(200).json({ success: true });
    } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/location/:sessionId', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT session_id, latitude, longitude, maps_link, device_name, device_ip, timestamp, received_at
             FROM live_locations WHERE session_id=$1 ORDER BY received_at DESC LIMIT 1`,
            [req.params.sessionId]
        );
        res.json(result.rows[0] || null);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/location/:sessionId/history', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT latitude, longitude, maps_link, timestamp, received_at
             FROM live_locations WHERE session_id=$1 ORDER BY received_at DESC LIMIT 10`,
            [req.params.sessionId]
        );
        res.json(result.rows);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/location', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT DISTINCT ON (session_id) session_id, latitude, longitude, maps_link,
                    device_name, device_ip, timestamp, received_at
             FROM live_locations ORDER BY session_id, received_at DESC`
        );
        res.json(result.rows);
    } catch (e) { res.status(500).json({ error: 'Database error' }); }
});

// ═══════════════════════════════════════════════════════════════════
// WITNESSES — Kavach users who were nearby during SOS
// ═══════════════════════════════════════════════════════════════════

app.post('/api/witness', requireApiKey, async (req, res) => {
    const { session_id, rssi, estimated_distance_m, witness_latitude, witness_longitude, timestamp } = req.body;
    if (!session_id || rssi == null) return res.status(400).json({ error: 'Missing session_id or rssi' });
    if (typeof rssi !== 'number' || rssi > 0 || rssi < -120) return res.status(400).json({ error: 'Invalid rssi value' });
    try {
        const result = await pool.query(
            `INSERT INTO witnesses (session_id, rssi, estimated_distance_m, witness_latitude, witness_longitude, timestamp)
             VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
            [session_id, rssi, estimated_distance_m || null, witness_latitude || null,
                witness_longitude || null, timestamp || new Date().toISOString()]
        );
        console.log(`📡 WITNESS — session: ${session_id} | RSSI: ${rssi} dBm | GPS: ${witness_latitude}, ${witness_longitude}`);
        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/witness/:sessionId', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m, witness_latitude, witness_longitude, timestamp, received_at
             FROM witnesses WHERE session_id=$1 ORDER BY rssi DESC, received_at ASC`,
            [req.params.sessionId]
        );
        return res.json({ session_id: req.params.sessionId, witness_count: result.rows.length, witnesses: result.rows });
    } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/witness', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m, witness_latitude, witness_longitude, timestamp, received_at
             FROM witnesses ORDER BY received_at DESC LIMIT 200`
        );
        return res.json(result.rows);
    } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

// ═══════════════════════════════════════════════════════════════════
// SUSPECTS — silent device fingerprints (SEPARATE POLICE PANEL)
//
// Person 2's phone silently reports here when it detects the
// victim's SOS beacon within 5-10m. Zero UI on Person 2's phone.
// Police query this with API key — completely separate from normal SOS.
// ═══════════════════════════════════════════════════════════════════

app.post('/api/suspect', requireApiKey, async (req, res) => {
    const {
        session_id, rssi, estimated_distance_m,
        android_id, device_model, device_brand, android_version, imei,
        suspect_latitude, suspect_longitude, gps_accuracy_m, timestamp,
    } = req.body;

    if (!session_id || rssi == null) return res.status(400).json({ error: 'Missing session_id or rssi' });

    // Server captures real public IP automatically from the HTTP request
    const ip_address =
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.socket?.remoteAddress ||
        req.ip || null;

    try {
        const result = await pool.query(
            `INSERT INTO suspects
                (session_id, rssi, estimated_distance_m, android_id, device_model,
                 device_brand, android_version, imei, suspect_latitude, suspect_longitude,
                 gps_accuracy_m, ip_address, timestamp)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             RETURNING id`,
            [session_id, rssi, estimated_distance_m || null, android_id || null, device_model || null,
                device_brand || null, android_version || null, imei || null,
                suspect_latitude || null, suspect_longitude || null, gps_accuracy_m || null,
                ip_address, timestamp || new Date().toISOString()]
        );

        console.log(
            `🕵️ SUSPECT LOGGED — session: ${session_id}`,
            `| RSSI: ${rssi} dBm (~${estimated_distance_m}m)`,
            `| Device: ${device_model}`,
            `| Android ID: ${android_id}`,
            `| IMEI: ${imei || 'unavailable (Android 10+)'}`,
            `| GPS: ${suspect_latitude}, ${suspect_longitude}`,
            `| IP: ${ip_address}`
        );

        return res.status(200).json({ success: true, id: result.rows[0].id });
    } catch (e) {
        console.error('❌ /api/suspect POST error:', e.message);
        return res.status(500).json({ error: 'Database error' });
    }
});

// GET all suspects for one SOS session — POLICE USE (API key required)
app.get('/api/suspect/:sessionId', requireApiKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m, android_id,
                    device_model, device_brand, android_version, imei,
                    suspect_latitude, suspect_longitude, gps_accuracy_m,
                    ip_address, timestamp, received_at
             FROM suspects WHERE session_id=$1 ORDER BY rssi DESC, received_at ASC`,
            [req.params.sessionId]
        );
        return res.json({
            session_id: req.params.sessionId,
            suspect_count: result.rows.length,
            note: 'Android IDs and IPs traceable via manufacturer and ISP respectively',
            suspects: result.rows,
        });
    } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

// GET all suspect records — admin panel (API key required)
app.get('/api/suspect', requireApiKey, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, session_id, rssi, estimated_distance_m, android_id,
                    device_model, device_brand, imei, suspect_latitude, suspect_longitude,
                    ip_address, timestamp, received_at
             FROM suspects ORDER BY received_at DESC LIMIT 500`
        );
        return res.json({ total: result.rows.length, suspects: result.rows });
    } catch (e) { return res.status(500).json({ error: 'Database error' }); }
});

// ═══════════════════════════════════════════════════════════════════
// STATIC PAGES + HEALTH
// ═══════════════════════════════════════════════════════════════════

app.get('/track/:sessionId', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'track.html'));
});

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
        console.log(`📊 Dashboard:   http://localhost:${PORT}`);
        console.log(`🚨 SOS:         http://localhost:${PORT}/api/sos`);
        console.log(`📍 Location:    http://localhost:${PORT}/api/location`);
        console.log(`📡 Witnesses:   http://localhost:${PORT}/api/witness`);
        console.log(`🕵️  Suspects:    http://localhost:${PORT}/api/suspect  [API key required]`);
        if (!process.env.API_KEY) {
            console.warn('⚠️ API_KEY not set — write endpoints will reject all requests');
        }
    });
}).catch(err => {
    console.error('❌ Database init failed:', err.message);
    process.exit(1);
});
