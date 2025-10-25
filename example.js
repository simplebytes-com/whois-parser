/**
 * Example usage of the WHOIS Parser
 */

import { parseWhoisData, whoisQuery } from './whois-parser.js';
import fs from 'fs';

// Load WHOIS server dictionary
const whoisDict = JSON.parse(fs.readFileSync('./whois_dict.json', 'utf8'));

async function lookupDomain(domain) {
    try {
        // Extract TLD from domain
        const tld = domain.split('.').pop();

        // Get WHOIS server for this TLD
        const server = whoisDict[tld];
        if (!server) {
            throw new Error(`No WHOIS server found for .${tld}`);
        }

        console.log(`\nQuerying ${domain} via ${server}...`);

        // Query WHOIS server
        const whoisText = await whoisQuery(domain, server);

        // Parse the response
        const parsed = parseWhoisData(whoisText, domain);

        // Display results
        console.log('\n========== WHOIS DATA ==========');
        console.log(`Domain:          ${parsed.domainName || 'N/A'}`);
        console.log(`Registrar:       ${parsed.registrar || 'N/A'}`);
        console.log(`Created:         ${parsed.creationDate || 'N/A'}`);
        console.log(`Expires:         ${parsed.expirationDate || 'N/A'}`);
        console.log(`Registrant:      ${parsed.registrant || 'N/A'}`);
        console.log(`DNSSEC:          ${parsed.dnssec || 'N/A'}`);
        console.log(`Last Modified:   ${parsed.lastModified || 'N/A'}`);

        if (parsed.nameservers && parsed.nameservers.length > 0) {
            console.log(`Nameservers:     ${parsed.nameservers.join(', ')}`);
        }

        if (parsed.status && parsed.status.length > 0) {
            console.log(`Status:          ${parsed.status.join(', ')}`);
        }

        return parsed;

    } catch (error) {
        console.error(`\n❌ Error: ${error.message}`);
        throw error;
    }
}

// Example usage
const domains = [
    'google.jp',    // Japan - square bracket format
    'naver.kr',     // South Korea - Korean/English format
    'google.gg',    // Guernsey - natural language dates
    'google.de',    // Germany - Nserver format
];

console.log('='.repeat(50));
console.log('WHOIS Parser - Example Queries');
console.log('='.repeat(50));

// Query each domain sequentially
for (const domain of domains) {
    await lookupDomain(domain);
    // Add delay between queries to be respectful to WHOIS servers
    await new Promise(resolve => setTimeout(resolve, 1000));
}

console.log('\n' + '='.repeat(50));
console.log('All queries completed!');
console.log('='.repeat(50));
