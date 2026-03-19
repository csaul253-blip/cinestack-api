const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const seedbox = require('./seedbox');
const axios = require('axios');

const JWT_SECRET = process.env.JWT_SECRET || 'cinestack-dev-secret';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

// ─── Auth Routes ────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { email, password, display_name, role } = req.body;
  try {
    const countResult = await pool.query('SELECT COUNT(*) FROM users');
    const isFirstUser = parseInt(countResult.rows[0].count) === 0;
    const assignedRole = isFirstUser ? 'admin' : (role || 'user');

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, role, display_name) VALUES ($1, $2, $3, $4) RETURNING id, email, role, display_name',
      [email, hash, assignedRole, display_name || null]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    res.status(500).json({ error: err.message });
  }
});
app.get('/api/auth/demo', async (req, res) => {
  try {
    const result = await pool.query("SELECT id, email, display_name, role FROM users WHERE email = 'demo@cinestack.app'");
    if (!result.rows[0]) return res.status(404).json({ error: 'Demo user not found' });
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '2h' });
    res.json({ token, display_name: user.display_name });
  } catch (err) {
    res.status(500).json({ error: 'Demo login failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, display_name: user.display_name || null } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Profile Routes ──────────────────────────────────────────────

app.patch('/api/auth/profile', requireAuth, async (req, res) => {
  const { display_name } = req.body
  try {
    const result = await pool.query(
      'UPDATE users SET display_name = $1 WHERE id = $2 RETURNING id, email, role, display_name',
      [display_name, req.user.id]
    )
    res.json({ user: result.rows[0] })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id])
    const user = result.rows[0]
    const valid = await bcrypt.compare(currentPassword, user.password_hash)
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' })
    const hash = await bcrypt.hash(newPassword, 10)
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id])
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ─── Waitlist Route ──────────────────────────────────────────────

app.post('/api/waitlist', async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    // Save to PostgreSQL
    await pool.query(
      'INSERT INTO waitlist (email, name) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING',
      [email, name || '']
    );

    // Add to Listmonk
    await fetch('http://localhost:9000/api/subscribers', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(process.env.LISTMONK_API_USER + ':' + process.env.LISTMONK_API_TOKEN).toString('base64'),
      },
      body: JSON.stringify({
        email,
        name: name || email,
        status: 'enabled',
        lists: [3],
      }),
    });

    res.json({ success: true });
  } catch (err) {
    // Still succeed if Listmonk fails — email is saved in DB
    res.json({ success: true });
  }
});

// ─── Auth Middleware ─────────────────────────────────────────────

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Settings helper ──────────────────────────────────────────────────────────
async function getSettings() {
  try {
    const result = await pool.query('SELECT key, value FROM settings')
    const settings = {}
    result.rows.forEach(row => {
      try { settings[row.key] = JSON.parse(row.value) }
      catch { settings[row.key] = row.value }
    })
    return settings
  } catch {
    return {}
  }
}

// ─── Radarr / Sonarr helpers ──────────────────────────────────────────────────

async function radarrGet(path) {
  const s = await getSettings()
  const url = s.radarrUrl || process.env.RADARR_URL
  const key = s.radarrApiKey || process.env.RADARR_API_KEY
  const res = await fetch(`${url}/api/v3${path}`, {
    headers: { 'X-Api-Key': key }
  })
  return res.json()
}
async function radarrPost(path, body) {
  const s = await getSettings()
  const url = s.radarrUrl || process.env.RADARR_URL
  const key = s.radarrApiKey || process.env.RADARR_API_KEY
  const res = await fetch(`${url}/api/v3${path}`, {
    method: 'POST',
    headers: { 'X-Api-Key': key, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  return res.json()
}
async function sonarrGet(path) {
  const s = await getSettings()
  const url = s.sonarrUrl || process.env.SONARR_URL
  const key = s.sonarrApiKey || process.env.SONARR_API_KEY
  const res = await fetch(`${url}/api/v3${path}`, {
    headers: { 'X-Api-Key': key }
  })
  return res.json()
}
async function sonarrPost(path, body) {
  const s = await getSettings()
  const url = s.sonarrUrl || process.env.SONARR_URL
  const key = s.sonarrApiKey || process.env.SONARR_API_KEY
  const res = await fetch(`${url}/api/v3${path}`, {
    method: 'POST',
    headers: { 'X-Api-Key': key, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  return res.json()
}

async function addToRadarr(title, tmdbId) {
  try {
    // Get first quality profile and root folder
    const [profiles, rootFolders] = await Promise.all([
      radarrGet('/qualityprofile'),
      radarrGet('/rootfolder')
    ]);

    if (!profiles.length || !rootFolders.length) {
      console.error('Radarr: no quality profiles or root folders configured');
      return null;
    }

    // Check if already in Radarr
    const lookup = await radarrGet(`/movie/lookup/tmdb?tmdbId=${tmdbId}`);
    if (lookup.id) {
      console.log(`Radarr: ${title} already exists (id ${lookup.id})`);
      return lookup.id;
    }

    // Add the movie
    const movie = await radarrPost('/movie', {
      tmdbId,
      title,
      qualityProfileId: profiles[0].id,
      rootFolderPath: rootFolders[0].path,
      monitored: true,
      addOptions: { searchForMovie: true }
    });

    console.log(`Radarr: added ${title} (id ${movie.id})`);
    return movie.id;
  } catch (err) {
    console.error('Radarr error:', err.message);
    return null;
  }
}

async function addToSonarr(title, tmdbId) {
  try {
    const [profiles, rootFolders] = await Promise.all([
      sonarrGet('/qualityprofile'),
      sonarrGet('/rootfolder')
    ]);

    if (!profiles.length || !rootFolders.length) {
      console.error('Sonarr: no quality profiles or root folders configured');
      return null;
    }

    // Lookup series by title (Sonarr uses TVDB, so we search by name)
    const results = await sonarrGet(`/series/lookup?term=${encodeURIComponent(title)}`);
    if (!results.length) {
      console.error(`Sonarr: no results for "${title}"`);
      return null;
    }

    const match = results[0];

    // Check if already in Sonarr
    if (match.id) {
      console.log(`Sonarr: ${title} already exists (id ${match.id})`);
      return match.id;
    }

    // Add the series
    const series = await sonarrPost('/series', {
      ...match,
      qualityProfileId: profiles[0].id,
      rootFolderPath: rootFolders[0].path,
      monitored: true,
      addOptions: { searchForMissingEpisodes: true }
    });

    console.log(`Sonarr: added ${title} (id ${series.id})`);
    return series.id;
  } catch (err) {
    console.error('Sonarr error:', err.message);
    return null;
  }
}

// ─── Health ───────────────────────────────────────────────────────────────────

app.get('/api/setup/status', async (req, res) => {
  const result = await pool.query(
    `SELECT value FROM settings WHERE key = 'setup_complete'`
  );
  res.json({ complete: result.rows.length > 0 && result.rows[0].value === 'true' });
});

app.post('/api/setup/test-connection', async (req, res) => {
  const { type, url, apiKey } = req.body;
  if (!url || !apiKey) {
    return res.status(400).json({ success: false, error: 'URL and API key are required.' });
  }
  try {
    await axios.get(`${url}/api/v1/system/status`, {
      headers: { 'X-Api-Key': apiKey },
      timeout: 5000,
    });
    res.json({ success: true });
  } catch (err) {
    const msg = err.response
      ? `HTTP ${err.response.status} — check your URL and API key`
      : err.code === 'ECONNREFUSED'
      ? 'Connection refused — is the service running?'
      : err.message;
    res.json({ success: false, error: msg });
  }
});

app.post('/api/setup/save', async (req, res) => {
  const allowed = [
    'radarr_url', 'radarr_api_key',
    'sonarr_url', 'sonarr_api_key',
    'prowlarr_url', 'prowlarr_api_key',
    'jellyfin_url', 'jellyfin_api_key',
  ];
  try {
    const entries = Object.entries(req.body).filter(([key]) => allowed.includes(key));
    for (const [key, value] of entries) {
      await pool.query(
        `INSERT INTO settings (key, value, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, value]
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/setup/complete', async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO settings (key, value, updated_at)
       VALUES ('setup_complete', 'true', NOW())
       ON CONFLICT (key) DO UPDATE SET value = 'true', updated_at = NOW()`
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    // Also check Radarr + Sonarr
    const [radarr, sonarr] = await Promise.allSettled([
      radarrGet('/system/status'),
      sonarrGet('/system/status')
    ]);

    res.json({
      status: 'ok',
      database: 'connected',
      radarr: radarr.status === 'fulfilled' ? 'connected' : 'unreachable',
      sonarr: sonarr.status === 'fulfilled' ? 'connected' : 'unreachable',
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ─── Requests ─────────────────────────────────────────────────────────────────
app.get('/api/requests', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM requests ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/requests', async (req, res) => {
  const { title, type, tmdb_id, poster_path } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create request
    const reqResult = await client.query(
      'INSERT INTO requests (title, type, status, progress, tmdb_id, poster_path) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [title, type, 'pending', 0, tmdb_id, poster_path]
    );
    const request = reqResult.rows[0];

    // Create download entry
    const fileSizeMB = Math.floor(Math.random() * 6000) + 800;
    const fileSize = fileSizeMB > 1024
      ? `${(fileSizeMB / 1024).toFixed(1)} GB`
      : `${fileSizeMB} MB`;

    await client.query(
      `INSERT INTO downloads (title, type, status, progress, speed, eta, file_size, tmdb_id, poster_path, request_id)
       VALUES ($1, $2, 'queued', 0, null, null, $3, $4, $5, $6)`,
      [title, type, fileSize, tmdb_id, poster_path, request.id]
    );

    await client.query('COMMIT');

    // Send to Radarr or Sonarr (non-blocking — don't fail the request if this errors)
    if (type === 'movie') {
      addToRadarr(title, tmdb_id).catch(err => console.error('addToRadarr failed:', err));
    } else {
      addToSonarr(title, tmdb_id).catch(err => console.error('addToSonarr failed:', err));
    }

    res.json(request);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.delete('/api/requests/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM requests WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Settings ─────────────────────────────────────────────────────────────────

app.get('/api/settings', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT key, value FROM settings')
    const settings = {}
    result.rows.forEach(row => {
      try { settings[row.key] = JSON.parse(row.value) }
      catch { settings[row.key] = row.value }
    })
    res.json(settings)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/settings', requireAuth, async (req, res) => {
  try {
    const entries = Object.entries(req.body)
    for (const [key, value] of entries) {
      await pool.query(
        `INSERT INTO settings (key, value, updated_at)
         VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
        [key, JSON.stringify(value)]
      )
    }
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ─── Seedbox ──────────────────────────────────────────────────────────────────

app.get('/api/settings/seedbox', requireAuth, async (req, res) => {
  try {
    const cfg = await seedbox.getSeedboxConfig();
    res.json(seedbox.publicConfig(cfg));
  } catch (err) {
    console.error('GET /api/settings/seedbox error');
    res.status(500).json({ error: 'Failed to load seedbox settings' });
  }
});

app.post('/api/settings/seedbox', requireAuth, async (req, res) => {
  try {
    await seedbox.saveSeedboxConfig(req.body);
    seedbox.stopPoller();
    if (req.body.enabled === true || req.body.enabled === 'true') {
      seedbox.startPoller(60);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/settings/seedbox error');
    res.status(400).json({ error: err.message || 'Failed to save seedbox settings' });
  }
});

app.get('/api/seedbox/status', requireAuth, (req, res) => {
  res.json(seedbox.getState());
});

app.post('/api/seedbox/test', requireAuth, async (req, res) => {
  try {
    const { host, port, username, password, remotePath } = req.body;
    const result = await seedbox.testConnection({ host, port, username, password, remotePath });
    res.json(result);
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message || 'Connection failed' });
  }
});

// ─── Jellyfin ─────────────────────────────────────────────────────────────────
app.get('/api/jellyfin/find', async (req, res) => {
  const { tmdb_id, type } = req.query
  const itemType = type === 'tv' ? 'Series' : 'Movie'
  try {
    const response = await fetch(
      `${process.env.JELLYFIN_URL}/Items?AnyProviderIdEquals=tmdb.${tmdb_id}&IncludeItemTypes=${itemType}&Recursive=true`,
      { headers: { 'X-Emby-Token': process.env.JELLYFIN_API_KEY } }
    )
    const data = await response.json()
    const item = data.Items?.[0]
    if (item) {
      res.json({ found: true, jellyfin_id: item.Id })
    } else {
      res.json({ found: false })
    }
  } catch (err) {
    res.json({ found: false })
  }
})

app.get('/api/jellyfin/movies', async (req, res) => {
  try {
    const response = await fetch(
      `${process.env.JELLYFIN_URL}/Items?IncludeItemTypes=Movie&Recursive=true&Fields=Overview,ProviderIds,BackdropImageTags,ImageTags`,
      { headers: { 'X-Emby-Token': process.env.JELLYFIN_API_KEY } }
    )
    const data = await response.json()
    res.json(data.Items || [])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/jellyfin/tv', async (req, res) => {
  try {
    const response = await fetch(
      `${process.env.JELLYFIN_URL}/Items?IncludeItemTypes=Series&Recursive=true&Fields=Overview,ProviderIds,BackdropImageTags,ImageTags`,
      { headers: { 'X-Emby-Token': process.env.JELLYFIN_API_KEY } }
    )
    const data = await response.json()
    res.json(data.Items || [])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ─── Downloads ────────────────────────────────────────────────────────────────
app.get('/api/downloads', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM downloads ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/downloads/:id', async (req, res) => {
  const { status, progress, speed, eta } = req.body;
  try {
    const result = await pool.query(
      `UPDATE downloads SET status = COALESCE($1, status), progress = COALESCE($2, progress),
       speed = COALESCE($3, speed), eta = COALESCE($4, eta) WHERE id = $5 RETURNING *`,
      [status, progress, speed, eta, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/downloads/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM downloads WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Real Download Queue Poller ───────────────────────────────────────────────
async function syncDownloadQueue() {
  try {
    const [radarrRes, sonarrRes] = await Promise.allSettled([
      radarrGet('/queue?pageSize=100&includeUnknownMovieItems=false'),
      sonarrGet('/queue?pageSize=100&includeUnknownSeriesItems=false'),
    ]);

    const radarrRecords = radarrRes.status === 'fulfilled' ? (radarrRes.value?.records || []) : [];
    const sonarrRecords = sonarrRes.status === 'fulfilled' ? (sonarrRes.value?.records || []) : [];
    const allRecords = [...radarrRecords, ...sonarrRecords];

    const dbResult = await pool.query(
      "SELECT * FROM downloads WHERE status NOT IN ('completed', 'failed')"
    );
    const dbDownloads = dbResult.rows;
    const matchedIds = new Set();

    for (const record of allRecords) {
      const dbMatch = dbDownloads.find(dl => {
        const recordTitle = (record.title || record.series?.title || '').toLowerCase();
        const dlTitle = (dl.title || '').toLowerCase();
        return dlTitle && recordTitle && (
          recordTitle.includes(dlTitle) || dlTitle.includes(recordTitle)
        );
      });

      if (!dbMatch) continue;
      matchedIds.add(dbMatch.id);

      const size = record.size || 0;
      const sizeleft = record.sizeleft || 0;
      const progress = size > 0 ? Math.round(((size - sizeleft) / size) * 100) : 0;

      let speed = null;
      if (record.timeleft && sizeleft > 0) {
        const parts = record.timeleft.split(':').map(Number);
        const secondsLeft = (parts[0] * 3600) + (parts[1] * 60) + (parts[2] || 0);
        if (secondsLeft > 0) {
          const mbps = (sizeleft / secondsLeft / 1024 / 1024).toFixed(1);
          speed = `${mbps} MB/s`;
        }
      }

      let eta = null;
      if (record.timeleft) {
        const parts = record.timeleft.split(':').map(Number);
        const h = parts[0], m = parts[1], s = parts[2] || 0;
        if (h > 0) eta = `${h}h ${m}m`;
        else if (m > 0) eta = `${m}m ${s}s`;
        else eta = `${s}s`;
      }

      const tracked = record.trackedDownloadState || '';
      const status = record.status || '';
      let csStatus = 'downloading';
      if (tracked === 'importPending' || tracked === 'imported') csStatus = 'completed';
      else if (status === 'paused') csStatus = 'queued';
      else if (tracked === 'downloadFailed' || status === 'failed') csStatus = 'failed';

      await pool.query(
        `UPDATE downloads SET progress = $1, speed = $2, eta = $3, status = $4 WHERE id = $5`,
        [progress, speed, eta, csStatus, dbMatch.id]
      );

      if (csStatus === 'completed' && dbMatch.request_id) {
        await pool.query(
          "UPDATE requests SET status = 'available', progress = 100 WHERE id = $1",
          [dbMatch.request_id]
        );
      }
    }

    const unmatched = dbDownloads.filter(
      dl => !matchedIds.has(dl.id) && dl.status === 'downloading' && dl.progress > 0
    );
    for (const dl of unmatched) {
      await pool.query(
        "UPDATE downloads SET status = 'completed', progress = 100, speed = NULL, eta = NULL WHERE id = $1",
        [dl.id]
      );
      if (dl.request_id) {
        await pool.query(
          "UPDATE requests SET status = 'available', progress = 100 WHERE id = $1",
          [dl.request_id]
        );
      }
    }

  } catch (err) {
    console.error('[Queue Poller] Error:', err.message);
  }
}

setInterval(syncDownloadQueue, 10000);

// TMDB proxy
app.get('/api/tmdb/*path', async (req, res) => {
  try {
    const tmdbPath = Array.isArray(req.params.path) ? req.params.path.join('/') : req.params.path;
    const query = new URLSearchParams(req.query).toString();
    const url = `https://api.themoviedb.org/3/${tmdbPath}${query ? '?' + query : ''}`;
    const response = await axios.get(url, {
      headers: {
        Authorization: `Bearer ${process.env.TMDB_API_TOKEN}`,
        accept: 'application/json',
      },
    });
    res.json(response.data);
  } catch (err) {
    const status = err.response?.status || 500;
    const message = err.response?.data?.status_message || 'TMDB proxy error';
    res.status(status).json({ error: message });
  }
});
async function runMigrations() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'user',
      display_name VARCHAR(255),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS requests (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      type VARCHAR(50) NOT NULL,
      status VARCHAR(50) DEFAULT 'pending',
      progress INTEGER DEFAULT 0,
      tmdb_id INTEGER,
      poster_path VARCHAR(255),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS downloads (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      type VARCHAR(50) NOT NULL,
      status VARCHAR(50) DEFAULT 'queued',
      progress INTEGER DEFAULT 0,
      speed VARCHAR(50),
      eta VARCHAR(50),
      file_size VARCHAR(50),
      tmdb_id INTEGER,
      poster_path VARCHAR(255),
      request_id INTEGER REFERENCES requests(id),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS waitlist (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      name VARCHAR(255),
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS settings (
      id SERIAL PRIMARY KEY,
      key VARCHAR(255) UNIQUE NOT NULL,
      value TEXT,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('Migrations complete.');
}
const PORT = process.env.PORT || 3004;
runMigrations().then(() => {
  app.listen(PORT, () => {
    console.log(`CineStack API running on port ${PORT}`);
    seedbox.init(pool);
    seedbox.startPoller(60);
  });
}).catch(err => {
  console.error('Migration failed:', err);
  process.exit(1);
});
