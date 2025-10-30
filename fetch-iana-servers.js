#!/usr/bin/env node
/**
 * IANA WHOIS Server Fetcher
 *
 * Fetches WHOIS servers from the official IANA Root Zone Database and updates whois_dict.json
 *
 * Data sources:
 * - TLD List: https://data.iana.org/TLD/tlds-alpha-by-domain.txt (updated daily)
 * - WHOIS Servers: https://www.iana.org/domains/root/db/{tld}.html (per-TLD pages)
 *
 * Usage:
 *   node fetch-iana-servers.js
 *   node fetch-iana-servers.js --dry-run
 */

import fetch from 'node-fetch';
import fs from 'fs/promises';

const DRY_RUN = process.argv.includes('--dry-run');
const BATCH_SIZE = 10; // Process in batches to avoid overwhelming IANA
const DELAY_MS = 500; // Delay between batches (be nice to IANA servers)

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function formatDate() {
  return new Date().toISOString().split('T')[0];
}

async function fetchTLDList() {
  log('\n📥 Fetching TLD list from IANA...', 'cyan');
  const response = await fetch('https://data.iana.org/TLD/tlds-alpha-by-domain.txt');
  const text = await response.text();

  const tlds = text
    .split('\n')
    .filter(line => line && !line.startsWith('#'))
    .map(tld => tld.toLowerCase().trim())
    .filter(tld => tld);

  log(`✓ Found ${tlds.length} TLDs`, 'green');
  return tlds;
}

async function fetchWhoisServer(tld) {
  try {
    const url = `https://www.iana.org/domains/root/db/${tld}.html`;
    const response = await fetch(url);

    if (!response.ok) {
      return { tld, server: null, error: `HTTP ${response.status}` };
    }

    const html = await response.text();
    const whoisMatch = html.match(/<b>WHOIS Server:<\/b>\s*([^\s<]+)/i);

    if (whoisMatch) {
      return { tld, server: whoisMatch[1].trim(), error: null };
    }

    return { tld, server: null, error: 'No WHOIS server listed' };
  } catch (error) {
    return { tld, server: null, error: error.message };
  }
}

async function processBatch(tlds, startIdx, currentDict) {
  const batch = tlds.slice(startIdx, startIdx + BATCH_SIZE);
  const results = await Promise.all(
    batch.map(tld => fetchWhoisServer(tld))
  );

  for (const result of results) {
    if (result.server) {
      const existing = currentDict[result.tld];
      if (!existing) {
        process.stdout.write(colors.green + '+' + colors.reset);
      } else if (existing !== result.server) {
        process.stdout.write(colors.yellow + '~' + colors.reset);
      } else {
        process.stdout.write(colors.gray + '.' + colors.reset);
      }
    } else {
      process.stdout.write(colors.gray + '-' + colors.reset);
    }
  }

  return results;
}

async function main() {
  log('\n🔄 IANA WHOIS Server Sync', 'blue');
  log('━'.repeat(50), 'gray');

  if (DRY_RUN) {
    log('🔍 DRY RUN MODE - No changes will be made', 'yellow');
  }

  // Load current dictionary
  let currentDict = {};
  try {
    const content = await fs.readFile('whois_dict.json', 'utf8');
    currentDict = JSON.parse(content);
    log(`📖 Current dictionary: ${Object.keys(currentDict).length} TLDs`, 'gray');
  } catch (error) {
    log('⚠️  No existing dictionary found, creating new one', 'yellow');
  }

  // Fetch TLD list
  const tlds = await fetchTLDList();

  log(`\n🔍 Fetching WHOIS servers for ${tlds.length} TLDs...`, 'cyan');
  log('Legend: ' +
      colors.green + '+' + colors.reset + ' new, ' +
      colors.yellow + '~' + colors.reset + ' changed, ' +
      colors.gray + '.' + colors.reset + ' unchanged, ' +
      colors.gray + '-' + colors.reset + ' no server\n', 'gray');

  // Process in batches
  const allResults = [];
  for (let i = 0; i < tlds.length; i += BATCH_SIZE) {
    const results = await processBatch(tlds, i, currentDict);
    allResults.push(...results);

    if (i + BATCH_SIZE < tlds.length) {
      await new Promise(resolve => setTimeout(resolve, DELAY_MS));
    }
  }

  console.log('\n');

  // Build new dictionary
  const newDict = {};
  const stats = {
    total: tlds.length,
    withWhois: 0,
    withoutWhois: 0,
    new: 0,
    changed: 0,
    unchanged: 0
  };

  const changes = [];

  for (const result of allResults) {
    if (result.server) {
      newDict[result.tld] = result.server;
      stats.withWhois++;

      const existing = currentDict[result.tld];
      if (!existing) {
        stats.new++;
        changes.push({ tld: result.tld, type: 'new', server: result.server });
      } else if (existing !== result.server) {
        stats.changed++;
        changes.push({ tld: result.tld, type: 'changed', old: existing, new: result.server });
      } else {
        stats.unchanged++;
      }
    } else {
      stats.withoutWhois++;
    }
  }

  // Display summary
  log('📊 Sync Summary', 'blue');
  log('━'.repeat(50), 'gray');
  log(`Total TLDs in IANA:     ${stats.total}`, 'gray');
  log(`TLDs with WHOIS:        ${stats.withWhois}`, 'green');
  log(`TLDs without WHOIS:     ${stats.withoutWhois} (brand TLDs, reserved, etc.)`, 'gray');
  log('');
  log(`New TLDs:               ${stats.new}`, stats.new > 0 ? 'green' : 'gray');
  log(`Changed servers:        ${stats.changed}`, stats.changed > 0 ? 'yellow' : 'gray');
  log(`Unchanged:              ${stats.unchanged}`, 'gray');

  // Show changes
  if (changes.length > 0) {
    log(`\n📝 Changes (${changes.length})`, 'yellow');
    log('━'.repeat(50), 'gray');

    for (const change of changes.slice(0, 20)) {
      if (change.type === 'new') {
        log(`  .${change.tld} → ${change.server}`, 'green');
      } else {
        log(`  .${change.tld}`, 'yellow');
        log(`    ${change.old} → ${change.new}`, 'gray');
      }
    }

    if (changes.length > 20) {
      log(`  ... and ${changes.length - 20} more`, 'gray');
    }
  }

  // Save results
  if (!DRY_RUN && (stats.new > 0 || stats.changed > 0)) {
    log('\n💾 Saving changes...', 'cyan');

    // Backup current dictionary
    if (Object.keys(currentDict).length > 0) {
      const backupPath = `whois_dict.json.backup.${formatDate()}`;
      await fs.writeFile(backupPath, JSON.stringify(currentDict, null, 2));
      log(`✓ Backup created: ${backupPath}`, 'gray');
    }

    // Save new dictionary (sorted by key)
    const sortedDict = Object.keys(newDict)
      .sort()
      .reduce((acc, key) => {
        acc[key] = newDict[key];
        return acc;
      }, {});

    await fs.writeFile('whois_dict.json', JSON.stringify(sortedDict, null, 2) + '\n');
    log('✓ Updated whois_dict.json', 'green');

    // Update README with last sync date
    try {
      let readme = await fs.readFile('README.md', 'utf8');
      const lastUpdated = `Last updated: ${formatDate()}`;

      // Update or add last updated line
      if (readme.includes('Last updated:')) {
        readme = readme.replace(/Last updated: \d{4}-\d{2}-\d{2}/, lastUpdated);
      } else {
        // Add before the first heading if not found
        readme = `${lastUpdated}\n\n${readme}`;
      }

      await fs.writeFile('README.md', readme);
      log('✓ Updated README.md with last sync date', 'green');
    } catch (error) {
      log(`⚠️  Could not update README.md: ${error.message}`, 'yellow');
    }

    log('\n✅ Sync complete!', 'green');
    log(`\n📈 Stats: ${stats.withWhois} TLDs with WHOIS servers (${Math.round(stats.withWhois / stats.total * 100)}%)`, 'cyan');
  } else if (DRY_RUN) {
    log('\n🔍 Dry run complete - no changes made', 'yellow');
  } else {
    log('\n✅ Dictionary is up-to-date!', 'green');
  }
}

main().catch(error => {
  log(`\n❌ Sync failed: ${error.message}`, 'red');
  console.error(error);
  process.exit(1);
});
