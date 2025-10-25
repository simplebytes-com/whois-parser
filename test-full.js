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

// Find ccTLDs (2-letter codes) that use WHOIS only
const ccTlds = Object.keys(whoisDict).filter(tld => {
    return tld.length === 2 && !rdapSet.has(tld);
}).sort();

console.log(`Found ${ccTlds.length} ccTLDs using WHOIS (no RDAP support)`);
console.log(`This will take approximately ${Math.ceil(ccTlds.length / 60)} minutes (1 sec delay per query)\n`);

// Common domains to test for each TLD
const getTestDomain = (tld) => {
    const commonTests = {
        'uk': 'google.co.uk',
        'au': 'google.com.au',
        'nz': 'google.co.nz',
        'za': 'google.co.za',
        'jp': 'google.co.jp',
        'cn': 'baidu.cn',
        'in': 'google.co.in',
        'br': 'google.com.br',
        'mx': 'google.com.mx',
        'kr': 'naver.kr',
        'de': 'google.de',
        'fr': 'google.fr',
        'it': 'google.it',
        'es': 'google.es',
        'nl': 'google.nl',
        'be': 'google.be',
        'ch': 'google.ch',
        'at': 'google.at',
        'se': 'google.se',
        'no': 'google.no',
        'dk': 'google.dk',
        'fi': 'google.fi',
        'pl': 'google.pl',
        'cz': 'google.cz',
        'ru': 'yandex.ru',
        'tr': 'google.com.tr',
        'il': 'google.co.il',
        'sg': 'google.com.sg',
        'hk': 'google.com.hk',
        'tw': 'google.com.tw',
        'th': 'google.co.th',
        'my': 'google.com.my',
        'id': 'google.co.id',
        'ph': 'google.com.ph',
        'vn': 'google.com.vn',
        'ar': 'google.com.ar',
        'cl': 'google.cl',
        'co': 'google.co',
        'pe': 'google.com.pe',
        've': 'google.co.ve',
        'gg': 'google.gg',
        'je': 'google.je',
        'im': 'google.im',
        'ac': 'nic.ac',
        'sh': 'nic.sh',
        'io': 'google.io',
        'ai': 'google.ai',
        'cc': 'google.cc',
        'tv': 'google.tv',
        'me': 'google.me',
        'ca': 'google.ca',
        'us': 'google.us',
        'ws': 'google.ws',
        'to': 'google.to',
        'nu': 'google.nu',
    };

    return commonTests[tld] || `test.${tld}`;
};

// Test each ccTLD
const results = {
    successful: [],
    failed: [],
    parsingIssues: []
};

for (let i = 0; i < ccTlds.length; i++) {
    const tld = ccTlds[i];
    const testDomain = getTestDomain(tld);
    const progress = `[${i + 1}/${ccTlds.length}]`;

    try {
        console.log(`${progress} Testing .${tld} (${testDomain})...`);
        const result = await fetchDomainInfo(testDomain);

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
                domain: testDomain,
                issues,
                data: { domainValue, registrarValue, creationDate, nameservers: nameservers?.slice(0, 2) }
            });
            console.log(`  ⚠️  Parsing issues: ${issues.join(', ')}`);
        } else {
            results.successful.push(tld);
            console.log(`  ✅ OK`);
        }

        // Rate limiting
        await new Promise(resolve => setTimeout(resolve, 1000));

    } catch (error) {
        results.failed.push({ tld, domain: testDomain, error: error.message });
        console.log(`  ❌ Failed: ${error.message}`);
    }
}

console.log('\n========== SUMMARY ==========');
console.log(`✅ Successful: ${results.successful.length}`);
console.log(`⚠️  Parsing Issues: ${results.parsingIssues.length}`);
console.log(`❌ Failed: ${results.failed.length}`);

if (results.parsingIssues.length > 0) {
    console.log('\n========== PARSING ISSUES ==========');
    results.parsingIssues.forEach(({ tld, domain, issues, data }) => {
        console.log(`\n.${tld} (${domain}):`);
        console.log(`  Issues: ${issues.join(', ')}`);
        console.log(`  Domain: ${data.domainValue || 'null'}`);
        console.log(`  Creation Date: ${data.creationDate || 'null'}`);
        console.log(`  Nameservers: ${JSON.stringify(data.nameservers)}`);
    });
}

// Save results to file
fs.writeFileSync('/tmp/whois-test-results.json', JSON.stringify(results, null, 2));
console.log('\n✅ Full results saved to /tmp/whois-test-results.json');
