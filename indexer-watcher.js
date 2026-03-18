/**
 * CineStack — Indexer Watcher Service
 * Polls Prowlarr every 5 minutes, detects unhealthy indexers, and auto-retests them.
 */

require('dotenv').config();
const axios = require('axios');

const PROWLARR_URL = process.env.PROWLARR_URL || 'http://localhost:9696';
const PROWLARR_API_KEY = process.env.PROWLARR_API_KEY;
const POLL_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

if (!PROWLARR_API_KEY) {
  console.error('[indexer-watcher] PROWLARR_API_KEY not set — exiting.');
  process.exit(1);
}

const prowlarr = axios.create({
  baseURL: PROWLARR_URL,
  headers: { 'X-Api-Key': PROWLARR_API_KEY },
  timeout: 15000,
});

function log(msg) {
  console.log(`[${new Date().toISOString()}] [indexer-watcher] ${msg}`);
}

async function getHealthIssues() {
  const res = await prowlarr.get('/api/v1/health');
  return res.data; // array of health issue objects
}

async function getAllIndexers() {
  const res = await prowlarr.get('/api/v1/indexer');
  return res.data; // array of indexer objects
}

async function retestIndexer(id, name) {
  try {
    await prowlarr.post(`/api/v1/indexer/${id}/test`);
    log(`  ↺ Retested: ${name} (id: ${id})`);
  } catch (err) {
    log(`  ✗ Retest failed for ${name} (id: ${id}): ${err.message}`);
  }
}

async function runCheck() {
  log('Running indexer health check...');

  try {
    const [healthIssues, indexers] = await Promise.all([
      getHealthIssues(),
      getAllIndexers(),
    ]);

    if (healthIssues.length === 0) {
      log(`✓ All systems healthy — ${indexers.length} indexer(s) online.`);
      return;
    }

    // Log any health warnings (not just indexer-related)
    for (const issue of healthIssues) {
      log(`⚠ Health issue [${issue.type}]: ${issue.message}`);
    }

    // Find indexers that are failing (enabled but not working)
    const failingIndexers = indexers.filter(idx => {
      if (!idx.enable) return false;
      // Prowlarr marks indexers with a non-null 'lastRssSyncMessage' or missing stats
      // We retest any enabled indexer when there are health issues
      return true;
    });

    if (failingIndexers.length === 0) {
      log('No enabled indexers to retest.');
      return;
    }

    log(`Retesting ${failingIndexers.length} enabled indexer(s)...`);
    for (const idx of failingIndexers) {
      await retestIndexer(idx.id, idx.name);
      // Stagger retests slightly to avoid hammering Prowlarr
      await new Promise(r => setTimeout(r, 2000));
    }

    log('Retest cycle complete.');
  } catch (err) {
    log(`✗ Check failed: ${err.message}`);
  }
}

// Run immediately on start, then on interval
log('Indexer watcher started.');
runCheck();
setInterval(runCheck, POLL_INTERVAL_MS);
