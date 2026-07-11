/**
 * Live WHOIS Server Tests
 *
 * Tests the whois-parser against live WHOIS servers.
 * Run with: npm run test:live
 * Run sample only: npm run test:sample
 *
 * Note: These tests hit live servers and may be affected by:
 * - Rate limiting
 * - Server timeouts
 * - Network issues
 */

import { whoisQuery, parseWhoisData } from './whois-parser.js';
import * as fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Check for --sample flag
const sampleOnly = process.argv.includes('--sample');

// Fetch and load RDAP TLDs (to exclude from WHOIS tests)
console.log('Fetching IANA RDAP service list...');
const rdapResponse = await fetch('https://data.iana.org/rdap/dns.json');
const rdapData = await rdapResponse.json();
const rdapTlds = new Set();
rdapData.services.forEach(([tlds, urls]) => {
    tlds.forEach(tld => rdapTlds.add(tld.toLowerCase()));
});

// Load WHOIS dictionary
const whoisDict = JSON.parse(fs.readFileSync(path.join(__dirname, 'whois_dict.json'), 'utf8'));

// Top 20 ccTLDs to test (most commonly used)
const topCCTlds = [
    { tld: 'uk', domain: 'bbc.co.uk' },
    { tld: 'de', domain: 'google.de' },
    { tld: 'fr', domain: 'google.fr' },
    { tld: 'it', domain: 'google.it' },
    { tld: 'nl', domain: 'google.nl' },
    { tld: 'es', domain: 'google.es' },
    { tld: 'pl', domain: 'google.pl' },
    { tld: 'ru', domain: 'yandex.ru' },
    { tld: 'ch', domain: 'google.ch' },
    { tld: 'be', domain: 'google.be' },
    { tld: 'se', domain: 'google.se' },
    { tld: 'dk', domain: 'google.dk' },
    { tld: 'no', domain: 'google.no' },
    { tld: 'fi', domain: 'google.fi' },
    { tld: 'cz', domain: 'google.cz' },
    { tld: 'at', domain: 'google.at' },
    { tld: 'ie', domain: 'google.ie' },
    { tld: 'gg', domain: 'google.gg' },
    { tld: 'je', domain: 'google.je' },
    { tld: 'im', domain: 'google.im' },
    { tld: 'jp', domain: 'google.jp' },
    { tld: 'kr', domain: 'naver.kr' },
].filter(({ tld }) => whoisDict[tld] && !rdapTlds.has(tld));

// Limit to sample if requested
const testCases = sampleOnly ? topCCTlds.slice(0, 5) : topCCTlds;

console.log(`\nTesting ${testCases.length} ccTLDs that use WHOIS${sampleOnly ? ' (sample mode)' : ''}\n`);

const results = {
    successful: [],
    failed: [],
    parsingIssues: []
};

for (const { tld, domain } of testCases) {
    const server = whoisDict[tld];
    try {
        console.log(`Testing .${tld} (${domain}) via ${server}...`);

        // Query WHOIS server
        const rawWhois = await whoisQuery(domain, server);

        // Parse the response
        const parsed = parseWhoisData(rawWhois, domain);

        // Check for parsing issues
        const issues = [];
        if (!parsed.domainName || parsed.domainName === domain) {
            // Only flag if domain wasn't found AND we're using fallback
            if (!rawWhois.toLowerCase().includes(domain.toLowerCase())) {
                issues.push('domain name not found in response');
            }
        }
        if (!parsed.creationDate) issues.push('missing creation date');
        if (!parsed.nameservers || parsed.nameservers.length === 0) issues.push('missing nameservers');

        if (issues.length > 0) {
            results.parsingIssues.push({
                tld,
                domain,
                server,
                issues,
                data: {
                    domainName: parsed.domainName,
                    creationDate: parsed.creationDate,
                    nameservers: parsed.nameservers?.slice(0, 2)
                }
            });
            console.log(`  ⚠️  Parsing issues: ${issues.join(', ')}`);
        } else {
            results.successful.push(tld);
            console.log(`  ✅ OK (domain: ${parsed.domainName}, created: ${parsed.creationDate})`);
        }

        // Rate limiting - 1 second between queries
        await new Promise(resolve => setTimeout(resolve, 1000));

    } catch (error) {
        results.failed.push({ tld, domain, server, error: error.message });
        console.log(`  ❌ Failed: ${error.message}`);
    }
}

console.log('\n========== SUMMARY ==========');
console.log(`✅ Successful: ${results.successful.length}/${testCases.length}`);
console.log(`⚠️  Parsing Issues: ${results.parsingIssues.length}/${testCases.length}`);
console.log(`❌ Failed: ${results.failed.length}/${testCases.length}`);

if (results.parsingIssues.length > 0) {
    console.log('\n========== PARSING ISSUES ==========');
    results.parsingIssues.forEach(({ tld, domain, server, issues, data }) => {
        console.log(`\n.${tld} (${domain}) via ${server}:`);
        console.log(`  Issues: ${issues.join(', ')}`);
        console.log(`  Domain: ${data.domainName || 'null'}`);
        console.log(`  Creation Date: ${data.creationDate || 'null'}`);
        console.log(`  Nameservers: ${JSON.stringify(data.nameservers || [])}`);
    });
}

if (results.failed.length > 0) {
    console.log('\n========== FAILED ==========');
    results.failed.forEach(({ tld, domain, server, error }) => {
        console.log(`\n.${tld} (${domain}) via ${server}: ${error}`);
    });
}

// Save results to file
const outputPath = '/tmp/whois-live-test-results.json';
fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
console.log(`\n✅ Full results saved to ${outputPath}`);
