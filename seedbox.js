'use strict';

/**
 * CineStack — Seedbox SFTP Auto-Transfer
 *
 * Security guarantees:
 *  - Password AES-256-GCM encrypted at rest in DB — never stored plaintext
 *  - Credentials never appear in any log, error message, or API response
 *  - Path traversal blocked — filenames and paths validated before any FS op
 *  - Local writes restricted to the configured media root — no escape possible
 *  - Transfers are atomic — .tmp file written, size-verified, then renamed
 *  - Transfer lock prevents concurrent transfers of the same file
 *  - Connection always closed in finally — no SFTP handle leaks
 *  - All errors sanitized before surfacing to API layer
 *
 * File integrity guarantees:
 *  - .part / .!qb / .tmp files on seedbox are never transferred
 *  - Write goes to <dest>.cinestack.tmp first
 *  - Size verified against remote stat before rename
 *  - On any failure the .tmp file is deleted — no partial files left behind
 *  - existsSync check on final destination prevents re-transfer
 *  - Transfer lock (Set) prevents overlapping transfers of the same file
 */

const SftpClient = require('ssh2-sftp-client');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');
const axios      = require('axios');

// ── Encryption ────────────────────────────────────────────────────────────────
// AES-256-GCM: authenticated encryption — detects tampering.
// Key is derived from JWT_SECRET so it is unique per installation.

const ALGORITHM = 'aes-256-gcm';

function getDerivedKey() {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not set — cannot derive encryption key');
  return crypto.pbkdf2Sync(secret, 'cinestack-seedbox-v1', 100_000, 32, 'sha256');
}

function encrypt(plaintext) {
  if (!plaintext) return '';
  const key     = getDerivedKey();
  const iv      = crypto.randomBytes(12);
  const cipher  = crypto.createCipheriv(ALGORITHM, key, iv);
  const enc     = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Format: iv(hex):authTag(hex):ciphertext(hex)
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${enc.toString('hex')}`;
}

function decrypt(stored) {
  if (!stored) return '';
  try {
    const [ivHex, authTagHex, ctHex] = stored.split(':');
    if (!ivHex || !authTagHex || !ctHex) return '';
    const key     = getDerivedKey();
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    return Buffer.concat([
      decipher.update(Buffer.from(ctHex, 'hex')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return ''; // tampered or corrupted — fail closed, never throw
  }
}

// ── Path / filename validation ────────────────────────────────────────────────

const TRAVERSAL_RE = /(\.\.[/\\]|[/\\]\.\.|^\.\.$)/;

function validateRemotePath(p) {
  if (!p || typeof p !== 'string') throw new Error('Invalid remote path');
  if (TRAVERSAL_RE.test(p))        throw new Error('Remote path contains traversal sequence');
}

function validateFilename(name) {
  if (!name || typeof name !== 'string')  throw new Error('Invalid filename');
  if (path.basename(name) !== name)        throw new Error('Filename must not contain path separators');
  if (TRAVERSAL_RE.test(name))             throw new Error('Filename contains traversal sequence');
  if (/[<>:"|?*\x00-\x1f]/.test(name))    throw new Error('Filename contains illegal characters');
}

/**
 * Resolves dest path and verifies it stays inside allowedRoot.
 * Throws if any attempt is made to write outside the media root.
 */
function safeLocalPath(allowedRoot, filename) {
  validateFilename(filename);
  const root     = path.resolve(allowedRoot);
  const resolved = path.resolve(allowedRoot, filename);
  if (resolved !== root && !resolved.startsWith(root + path.sep)) {
    throw new Error('Resolved path escapes allowed root — aborting');
  }
  return resolved;
}

// ── In-memory state ───────────────────────────────────────────────────────────

const state = {
  connected: false,
  lastPoll:  null,
  lastError: null,
  transfers: {},   // filename → { progress, speed, status, startedAt }
};

const transferLock = new Set(); // filenames currently in-flight

let pollerTimer = null;
let pool        = null;

// ── Init ──────────────────────────────────────────────────────────────────────

function init(pgPool) {
  pool = pgPool;
}

// ── DB helpers ────────────────────────────────────────────────────────────────

async function dbSet(key, value) {
  await pool.query(
    `INSERT INTO settings (key, value, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
    [key, value]
  );
}

// ── Config read ───────────────────────────────────────────────────────────────

async function getSeedboxConfig() {
  const res = await pool.query(
    `SELECT key, value FROM settings WHERE key = ANY($1)`,
    [[
      'seedbox_enabled',
      'seedbox_host',
      'seedbox_port',
      'seedbox_username',
      'seedbox_password_enc',
      'seedbox_remote_path',
      'seedbox_local_path',
    ]]
  );
  const m = {};
  res.rows.forEach(r => { m[r.key] = r.value; });

  return {
    enabled:    m.seedbox_enabled === 'true',
    host:       m.seedbox_host        || '',
    port:       parseInt(m.seedbox_port || '22', 10),
    username:   m.seedbox_username    || '',
    password:   decrypt(m.seedbox_password_enc || ''),
    remotePath: m.seedbox_remote_path || '',
    localPath:  m.seedbox_local_path  || '/mnt/media',
  };
}

// ── Config write (encrypts password before storing) ───────────────────────────

async function saveSeedboxConfig({ enabled, host, port, username, password, remotePath, localPath }) {
  if (remotePath) validateRemotePath(remotePath);
  if (localPath && TRAVERSAL_RE.test(localPath)) throw new Error('Invalid local path');

  await dbSet('seedbox_enabled',     String(!!enabled));
  await dbSet('seedbox_host',        (host       || '').trim());
  await dbSet('seedbox_port',        String(parseInt(port || '22', 10)));
  await dbSet('seedbox_username',    (username   || '').trim());
  await dbSet('seedbox_remote_path', (remotePath || '').trim());
  await dbSet('seedbox_local_path',  (localPath  || '/mnt/media').trim());

  // Only overwrite the encrypted password if a real new value was supplied
  if (password && password !== '••••••••') {
    await dbSet('seedbox_password_enc', encrypt(password));
  }
}

// ── Safe config for API responses — password NEVER leaves the server ──────────

function publicConfig(cfg) {
  return {
    enabled:    cfg.enabled,
    host:       cfg.host,
    port:       cfg.port,
    username:   cfg.username,
    password:   cfg.password ? '••••••••' : '',
    remotePath: cfg.remotePath,
    localPath:  cfg.localPath,
  };
}

// ── SFTP connect ──────────────────────────────────────────────────────────────

async function connect(cfg) {
  const sftp = new SftpClient();
  await sftp.connect({
    host:         cfg.host,
    port:         cfg.port,
    username:     cfg.username,
    password:     cfg.password,
    readyTimeout: 20_000,
    agent:        null,   // no agent forwarding
  });
  return sftp;
}

// ── Incomplete file guard ─────────────────────────────────────────────────────

const INCOMPLETE_EXT = new Set(['.part', '.!qb', '.crdownload', '.tmp', '.downloading']);

function isCompleteFile(filename) {
  return !INCOMPLETE_EXT.has(path.extname(filename).toLowerCase());
}

// ── Atomic file transfer ──────────────────────────────────────────────────────

async function transferFile(sftp, cfg, file) {
  const { name: filename, size: remoteSize } = file;

  validateFilename(filename);

  const localDest = safeLocalPath(cfg.localPath, filename);
  const localTmp  = localDest + '.cinestack.tmp';

  transferLock.add(filename);

  state.transfers[filename] = {
    status:    'transferring',
    progress:  0,
    speed:     '—',
    startedAt: Date.now(),
  };

  await pool.query(
    `UPDATE downloads
     SET status = 'transferring', progress = 0, speed = NULL, eta = NULL
     WHERE status IN ('downloading','queued','pending')
       AND title ILIKE $1`,
    [`%${titleSearchTerm(filename)}%`]
  ).catch(() => {});

  console.log(`[Seedbox] Starting: ${filename} (${formatBytes(remoteSize)})`);

  let success = false;

  try {
    fs.mkdirSync(cfg.localPath, { recursive: true });

    let lastBytes = 0;
    let lastTime  = Date.now();

    await sftp.fastGet(
      path.posix.join(cfg.remotePath, filename),
      localTmp,
      {
        step: (transferred, _chunk, total) => {
          const pct  = Math.round((transferred / total) * 100);
          const now  = Date.now();
          const secs = Math.max((now - lastTime) / 1000, 0.1);
          const bps  = (transferred - lastBytes) / secs;

          state.transfers[filename].progress = pct;
          state.transfers[filename].speed    = `${formatBytes(bps)}/s`;

          lastBytes = transferred;
          lastTime  = now;

          pool.query(
            `UPDATE downloads SET progress = $1, speed = $2
             WHERE status = 'transferring' AND title ILIKE $3`,
            [pct, state.transfers[filename].speed, `%${titleSearchTerm(filename)}%`]
          ).catch(() => {});
        },
      }
    );

    // ── Integrity check ───────────────────────────────────────────────────────
    const localStat = fs.statSync(localTmp);
    if (localStat.size !== remoteSize) {
      throw new Error(`Size mismatch: expected ${remoteSize}, got ${localStat.size}`);
    }

    // Atomic rename — only after integrity check passes
    fs.renameSync(localTmp, localDest);
    success = true;

    state.transfers[filename].status   = 'complete';
    state.transfers[filename].progress = 100;

    await pool.query(
      `UPDATE downloads
       SET status = 'available', progress = 100, speed = NULL, eta = NULL
       WHERE status = 'transferring' AND title ILIKE $1`,
      [`%${titleSearchTerm(filename)}%`]
    ).catch(() => {});

    console.log(`[Seedbox] Complete: ${filename}`);
    await triggerJellyfinScan();

  } catch (err) {
    state.transfers[filename].status = 'failed';
    state.lastError = sanitizeError(err);

    // Delete the .tmp file — never leave partial data
    try {
      if (fs.existsSync(localTmp)) fs.unlinkSync(localTmp);
    } catch { /* ignore cleanup error */ }

    // Revert row so it can retry next poll
    await pool.query(
      `UPDATE downloads SET status = 'downloading', progress = 0
       WHERE status = 'transferring' AND title ILIKE $1`,
      [`%${titleSearchTerm(filename)}%`]
    ).catch(() => {});

    console.error(`[Seedbox] Transfer failed: ${sanitizeError(err)}`);

  } finally {
    transferLock.delete(filename);
    setTimeout(() => { delete state.transfers[filename]; }, 5 * 60 * 1000);
  }

  return success;
}

// ── Poll ──────────────────────────────────────────────────────────────────────

async function poll() {
  let cfg;
  try {
    cfg = await getSeedboxConfig();
  } catch (err) {
    console.error('[Seedbox] Config load failed:', sanitizeError(err));
    return;
  }

  if (!cfg.enabled || !cfg.host || !cfg.username || !cfg.password || !cfg.remotePath) {
    return;
  }

  let sftp;
  try {
    sftp = await connect(cfg);
    state.connected = true;
    state.lastPoll  = new Date().toISOString();
    state.lastError = null;

    const files = await sftp.list(cfg.remotePath);

    for (const file of files) {
      if (file.type !== '-')             continue;   // skip dirs/symlinks
      if (!isCompleteFile(file.name))    continue;   // skip incomplete

      try {
        validateFilename(file.name);
      } catch {
        console.warn('[Seedbox] Skipping file with invalid name');
        continue;
      }

      const localDest = safeLocalPath(cfg.localPath, file.name);

      if (fs.existsSync(localDest))          continue;  // already transferred
      if (transferLock.has(file.name))        continue;  // already in-flight

      // One at a time — awaited sequentially, no race conditions
      await transferFile(sftp, cfg, file);
    }

  } catch (err) {
    state.connected = false;
    state.lastError = sanitizeError(err);
    console.error('[Seedbox] Poll error:', sanitizeError(err));
  } finally {
    if (sftp) {
      try { await sftp.end(); } catch { /* ignore */ }
    }
  }
}

// ── Jellyfin scan ─────────────────────────────────────────────────────────────

async function triggerJellyfinScan() {
  try {
    const res = await pool.query(
      `SELECT key, value FROM settings WHERE key IN ('jellyfinUrl','jellyfinApiKey')`
    );
    const m = {};
    res.rows.forEach(r => { m[r.key] = r.value; });

    const url    = m.jellyfinUrl    || process.env.JELLYFIN_URL;
    const apiKey = m.jellyfinApiKey || process.env.JELLYFIN_API_KEY;

    if (!url || !apiKey) return;

    await axios.post(`${url}/Library/Refresh`, {}, {
      params:  { api_key: apiKey },
      timeout: 15_000,
    });
    console.log('[Seedbox] Jellyfin library scan triggered');
  } catch (err) {
    console.warn('[Seedbox] Jellyfin scan failed (non-fatal):', sanitizeError(err));
  }
}

// ── Test connection ───────────────────────────────────────────────────────────

async function testConnection({ host, port, username, password, remotePath }) {
  if (!host || !username || !password || !remotePath) {
    throw new Error('Missing required connection fields');
  }
  validateRemotePath(remotePath);

  const sftp = await connect({
    host, port: parseInt(port || '22', 10), username, password,
  });
  try {
    const list = await sftp.list(remotePath);
    return {
      ok:    true,
      files: list.filter(f => f.type === '-' && isCompleteFile(f.name)).length,
      path:  remotePath,
    };
  } finally {
    try { await sftp.end(); } catch { /* ignore */ }
  }
}

// ── Poller control ────────────────────────────────────────────────────────────

function startPoller(intervalSeconds = 60) {
  if (pollerTimer) return;
  console.log(`[Seedbox] Poller started (${intervalSeconds}s interval)`);
  // Stagger first poll 10s to let the server fully initialise
  setTimeout(() => {
    poll();
    pollerTimer = setInterval(poll, intervalSeconds * 1_000);
  }, 10_000);
}

function stopPoller() {
  if (pollerTimer) {
    clearInterval(pollerTimer);
    pollerTimer = null;
    console.log('[Seedbox] Poller stopped');
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function titleSearchTerm(filename) {
  return filename
    .replace(/\.[^/.]+$/, '')   // remove extension
    .replace(/[._]/g, ' ')      // dots and underscores → spaces
    .replace(/\s+/g, ' ')
    .trim()
    .substring(0, 80);          // cap to prevent pathological LIKE queries
}

function sanitizeError(err) {
  if (!err) return 'Unknown error';
  let msg = String(err.message || err);
  msg = msg.replace(/password[=:\s][^\s&,]*/gi, 'password=[redacted]');
  msg = msg.replace(/\/root\/[^\s,]*/g,          '[path redacted]');
  msg = msg.replace(/\/home\/[^\s,]*/g,          '[path redacted]');
  return msg.substring(0, 200);
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024)         return `${bytes} B`;
  if (bytes < 1024 ** 2)    return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3)    return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = {
  init,
  startPoller,
  stopPoller,
  poll,
  testConnection,
  getSeedboxConfig,
  saveSeedboxConfig,
  publicConfig,
  getState: () => ({
    connected: state.connected,
    lastPoll:  state.lastPoll,
    lastError: state.lastError,
    transfers: { ...state.transfers },
  }),
};