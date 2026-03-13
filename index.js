const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');

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

// ─── Radarr / Sonarr helpers ──────────────────────────────────────────────────

async function radarrGet(path) {
  const res = await fetch(`${process.env.RADARR_URL}/api/v3${path}`, {
    headers: { 'X-Api-Key': process.env.RADARR_API_KEY }
  });
  return res.json();
}

async function radarrPost(path, body) {
  const res = await fetch(`${process.env.RADARR_URL}/api/v3${path}`, {
    method: 'POST',
    headers: { 'X-Api-Key': process.env.RADARR_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

async function sonarrGet(path) {
  const res = await fetch(`${process.env.SONARR_URL}/api/v3${path}`, {
    headers: { 'X-Api-Key': process.env.SONARR_API_KEY }
  });
  return res.json();
}

async function sonarrPost(path, body) {
  const res = await fetch(`${process.env.SONARR_URL}/api/v3${path}`, {
    method: 'POST',
    headers: { 'X-Api-Key': process.env.SONARR_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
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

// ─── Progress Simulator ───────────────────────────────────────────────────────
setInterval(async () => {
  try {
    const activeResult = await pool.query(
      "SELECT COUNT(*) FROM downloads WHERE status = 'downloading'"
    );
    const activeCount = parseInt(activeResult.rows[0].count);

    if (activeCount === 0) {
      await pool.query(
        `UPDATE downloads SET status = 'downloading', speed = '12.4 MB/s', eta = 'Calculating...'
         WHERE id = (SELECT id FROM downloads WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1)`
      );
    }

    const downloading = await pool.query(
      "SELECT * FROM downloads WHERE status = 'downloading'"
    );

    for (const dl of downloading.rows) {
      const increment = Math.floor(Math.random() * 5) + 3;
      const newProgress = Math.min(dl.progress + increment, 100);
      const speed = `${(Math.random() * 15 + 5).toFixed(1)} MB/s`;
      const remaining = Math.ceil((100 - newProgress) / increment * 4);
      const eta = newProgress >= 100 ? null : remaining < 60 ? `${remaining}s` : `${Math.ceil(remaining / 60)}m`;
      const status = newProgress >= 100 ? 'completed' : 'downloading';

      await pool.query(
        `UPDATE downloads SET progress = $1, speed = $2, eta = $3, status = $4 WHERE id = $5`,
        [newProgress, status === 'completed' ? null : speed, eta, status, dl.id]
      );

      if (status === 'completed' && dl.request_id) {
        await pool.query(
          "UPDATE requests SET status = 'available', progress = 100 WHERE id = $1",
          [dl.request_id]
        );
      }
    }
  } catch (err) {
    console.error('Simulator error:', err.message);
  }
}, 4000);

const PORT = process.env.PORT || 3004;
app.listen(PORT, () => {
  console.log(`CineStack API running on port ${PORT}`);
});
