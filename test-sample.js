import { fetchDomainInfo } from './utils/domainLookupUtils.js';
import * as fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Fetch and load RDAP TLDs
console.log('Fetching IANA RDAP service list...');
const rdapResponse = await fetch('https://data.iana.org/rdap/dns.json');
const rdapData = await rdapResponse.json();
const rdapTlds = new Set();
rdapData.services.forEach(([tlds, urls]) => {
    tlds.forEach(tld => rdapTlds.add(tld.toLowerCase()));
});
const rdapSet = rdapTlds;

// Load WHOIS dictionary
const whoisDict = JSON.parse(fs.readFileSync(path.join(__dirname, 'utils/whois_dict.json'), 'utf8'));

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
].filter(({ tld }) => whoisDict[tld] && !rdapSet.has(tld));

console.log(`Testing ${topCCTlds.length} popular ccTLDs that use WHOIS\n`);

const results = {
    successful: [],
    failed: [],
    parsingIssues: []
};

for (const { tld, domain } of topCCTlds) {
    try {
        console.log(`Testing .${tld} (${domain})...`);
        const result = await fetchDomainInfo(domain);

        // Check for parsing issues
        const domainValue = result.standardizedData.find(d => d.key === 'Domain')?.value;
        const registrarValue = result.standardizedData.find(d => d.key === 'Registrar')?.value;
        const creationDate = result.standardizedData.find(d => d.key === 'Creation Date')?.value;
        const nameservers = result.standardizedData.find(d => d.key === 'Nameservers')?.value;

        const issues = [];
        if (!domainValue || domainValue === 'Not available') issues.push('missing domain name');
        if (!creationDate || creationDate === 'Not available') issues.push('missing creation date');
        if (!nameservers || nameservers.length === 0) issues.push('missing nameservers');

        if (issues.length > 0) {
            results.parsingIssues.push({
                tld,
                domain,
                issues,
                data: { domainValue, registrarValue, creationDate, nameservers: nameservers?.slice(0, 2) }
            });
            console.log(`  ⚠️  Parsing issues: ${issues.join(', ')}`);
        } else {
            results.successful.push(tld);
            console.log(`  ✅ OK (domain: ${domainValue}, created: ${creationDate})`);
        }

        // Rate limiting - 1 second between queries
        await new Promise(resolve => setTimeout(resolve, 1000));

    } catch (error) {
        results.failed.push({ tld, domain, error: error.message });
        console.log(`  ❌ Failed: ${error.message}`);
    }
}

console.log('\n========== SUMMARY ==========');
console.log(`✅ Successful: ${results.successful.length}/${topCCTlds.length}`);
console.log(`⚠️  Parsing Issues: ${results.parsingIssues.length}/${topCCTlds.length}`);
console.log(`❌ Failed: ${results.failed.length}/${topCCTlds.length}`);

if (results.parsingIssues.length > 0) {
    console.log('\n========== PARSING ISSUES ==========');
    results.parsingIssues.forEach(({ tld, domain, issues, data }) => {
        console.log(`\n.${tld} (${domain}):`);
        console.log(`  Issues: ${issues.join(', ')}`);
        console.log(`  Domain: ${data.domainValue || 'null'}`);
        console.log(`  Creation Date: ${data.creationDate || 'null'}`);
        console.log(`  Nameservers: ${JSON.stringify(data.nameservers || [])}`);
    });
}

if (results.failed.length > 0) {
    console.log('\n========== FAILED ==========');
    results.failed.forEach(({ tld, domain, error }) => {
        console.log(`\n.${tld} (${domain}): ${error}`);
    });
}

// Save results to file
fs.writeFileSync('/tmp/whois-sample-test-results.json', JSON.stringify(results, null, 2));
console.log('\n✅ Full results saved to /tmp/whois-sample-test-results.json');
