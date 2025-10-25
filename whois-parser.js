/**
 * WHOIS Parser for ccTLDs
 *
 * A comprehensive WHOIS parser supporting 169 country-code TLDs with various formats.
 * Built for DomainDetails.com
 *
 * @author Simple Bytes LLC
 * @license MIT
 */

import net from 'net';

/**
 * Query a WHOIS server for domain information
 * @param {string} domain - Domain name to query
 * @param {string} server - WHOIS server address
 * @param {number} timeout - Timeout in milliseconds (default: 30000)
 * @returns {Promise<string>} WHOIS response text
 */
export function whoisQuery(domain, server, timeout = 30000) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(43, server);
        let data = '';

        socket.on('connect', () => {
            console.log(`Connected to WHOIS server ${server} for domain ${domain}`);
            socket.write(`${domain}\r\n`);
        });

        socket.on('data', (chunk) => {
            data += chunk.toString();
        });

        socket.on('end', () => {
            if (!data || data.trim().length === 0) {
                reject(new Error(`WHOIS server ${server} returned no data`));
            } else {
                resolve(data);
            }
        });

        socket.on('error', (err) => {
            console.error(`WHOIS server error for ${server}:`, err.message);
            reject(new Error(`WHOIS server ${server} error: ${err.message}`));
        });

        socket.setTimeout(timeout, () => {
            socket.destroy();
            reject(new Error(`WHOIS server ${server} timed out after ${timeout / 1000} seconds`));
        });
    });
}

/**
 * Parse WHOIS data from raw text response
 * @param {string} whoisText - Raw WHOIS response text
 * @param {string} domainName - Domain name as fallback (optional)
 * @returns {Object} Parsed WHOIS data
 */
export function parseWhoisData(whoisText, domainName = null) {
    // Normalize dates from natural language to ISO format
    const normalizeDateString = (dateStr) => {
        if (!dateStr) return null;

        // Handle .gg/.je style: "30th April 2003"
        const ggMatch = dateStr.match(/(\d+)(?:st|nd|rd|th)\s+(\w+)\s+(\d{4})/i);
        if (ggMatch) {
            const [, day, month, year] = ggMatch;
            const monthMap = {
                'january': '01', 'february': '02', 'march': '03', 'april': '04',
                'may': '05', 'june': '06', 'july': '07', 'august': '08',
                'september': '09', 'october': '10', 'november': '11', 'december': '12'
            };
            const monthNum = monthMap[month.toLowerCase()];
            if (monthNum) {
                return `${year}-${monthNum}-${day.padStart(2, '0')}T00:00:00Z`;
            }
        }

        // Handle recurring dates: "30th April each year"
        const recurringMatch = dateStr.match(/(\d+)(?:st|nd|rd|th)\s+(\w+)\s+each year/i);
        if (recurringMatch) {
            const [, day, month] = recurringMatch;
            const monthMap = {
                'january': '01', 'february': '02', 'march': '03', 'april': '04',
                'may': '05', 'june': '06', 'july': '07', 'august': '08',
                'september': '09', 'october': '10', 'november': '11', 'december': '12'
            };
            const monthNum = monthMap[month.toLowerCase()];
            if (monthNum) {
                // Use next year for recurring dates
                const nextYear = new Date().getFullYear() + 1;
                return `${nextYear}-${monthNum}-${day.padStart(2, '0')}T00:00:00Z`;
            }
        }

        // Handle .jp format: "2005/05/30" → "2005-05-30T00:00:00Z"
        const jpMatch = dateStr.match(/^(\d{4})\/(\d{2})\/(\d{2})$/);
        if (jpMatch) {
            const [, year, month, day] = jpMatch;
            return `${year}-${month}-${day}T00:00:00Z`;
        }

        // Handle .kr format: "2007. 03. 02." → "2007-03-02T00:00:00Z"
        const krMatch = dateStr.match(/^(\d{4})\.\s*(\d{2})\.\s*(\d{2})\.?$/);
        if (krMatch) {
            const [, year, month, day] = krMatch;
            return `${year}-${month}-${day}T00:00:00Z`;
        }

        // Already in a standard format, return as-is
        return dateStr;
    };

    const parseField = (field, alternativeFields = []) => {
        const fields = [field, ...alternativeFields];
        for (const f of fields) {
            // Handle formats like "domain...............: test.ax" or "Domain: test.com"
            const colonMatch = whoisText.match(new RegExp(`${f}[\\.\\s]*:\\s*(.+)`, 'i'));
            if (colonMatch) return colonMatch[1].trim();

            // Handle .jp square bracket format: "[Domain Name]                   GOOGLE.JP"
            const bracketMatch = whoisText.match(new RegExp(`\\[${f}\\]\\s+(.+)`, 'i'));
            if (bracketMatch) return bracketMatch[1].trim();
        }
        return null;
    };

    const parseMultipleFields = (field) => {
        const matches = whoisText.match(new RegExp(`${field}:\\s*(.+)`, 'ig'));
        return matches ? matches.map(match => match.split(':')[1].trim()) : [];
    };

    // Enhanced nameserver parsing for various ccTLD formats
    const parseNameservers = () => {
        // Try multi-line formats first (.gg, .je, .it style)
        const multilinePatterns = [
            /Name servers:\s*([\s\S]*?)(?=\n\n|WHOIS lookup)/i,  // .gg, .je
            /Nameservers\s*\n([\s\S]*?)(?=\n\n|\n[A-Z])/i,       // .it
        ];

        for (const pattern of multilinePatterns) {
            const match = whoisText.match(pattern);
            if (match) {
                const servers = match[1]
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('WHOIS'))
                    .map(line => line.split(/\s+/)[0]); // Take first word (handles .ru format with IPs)
                if (servers.length > 0) return servers;
            }
        }

        // Try single-line colon-separated formats
        const colonPatterns = [
            'nserver',      // .de, .ru (lowercase)
            'Nserver',      // .de (capitalized)
            'Name Server',  // standard
            'nameservers',  // standard lowercase
            'nameserver',   // standard singular
            'Host Name',    // .kr format
        ];

        for (const field of colonPatterns) {
            const matches = whoisText.match(new RegExp(`${field}\\s*:\\s*(.+)`, 'ig'));
            if (matches && matches.length > 0) {
                return matches.map(match => {
                    const value = match.split(':')[1].trim();
                    // Handle .ru format: "ns1.yandex.ru. 213.180.193.1"
                    return value.split(/\s+/)[0].replace(/\.$/, ''); // Remove trailing dot
                });
            }
        }

        // Try .jp square bracket format: "[Name Server]                   ns1.google.com"
        const jpMatches = whoisText.match(/\[Name Server\]\s+(.+)/gi);
        if (jpMatches && jpMatches.length > 0) {
            return jpMatches.map(match => {
                const value = match.replace(/\[Name Server\]/i, '').trim();
                return value.split(/\s+/)[0];
            });
        }

        return null;
    };

    const parseStatus = () => {
        // Try multi-line status format (.gg, .je)
        const statusSection = whoisText.match(/Domain Status:\s*([\s\S]*?)(?=\n\n|Registrant:)/i);
        if (statusSection) {
            const statuses = statusSection[1]
                .split('\n')
                .map(line => line.trim())
                .filter(line => line);
            if (statuses.length > 0) return statuses;
        }

        // Try single-line formats
        const singleLineMatch = parseMultipleFields('Domain Status') ||
                               parseMultipleFields('Status') ||
                               parseMultipleFields('state');
        if (singleLineMatch && singleLineMatch.length > 0) return singleLineMatch;

        return null;
    };

    const parseCreationDate = () => {
        // Try various creation date formats
        const patterns = [
            /Registered on (\d+(?:st|nd|rd|th) \w+ \d{4})/i,      // .gg, .je
            /created:\s*(.+)/i,                                    // .ru, .de
            /Created:\s*(.+)/i,                                    // .it
            /Creation Date:\s*(.+)/i,                              // standard
            /Created On:\s*(.+)/i,                                 // alternative
            /Registered Date\s*:\s*(.+)/i,                         // .kr
            /\[登録年月日\]\s+(.+)/,                               // .jp (Registration Date in Japanese)
        ];

        for (const pattern of patterns) {
            const match = whoisText.match(pattern);
            if (match) {
                const rawDate = match[1].trim();
                return normalizeDateString(rawDate);
            }
        }

        return null;
    };

    const parseExpiryDate = () => {
        // Try various expiry date formats
        const patterns = [
            /Registry fee due on (\d+(?:st|nd|rd|th) \w+ each year)/i,  // .gg, .je
            /paid-till:\s*(.+)/i,                                        // .ru
            /Expire Date:\s*(.+)/i,                                      // .it
            /Registry Expiry Date:\s*(.+)/i,                             // standard
            /Expiration Date\s*:\s*(.+)/i,                               // .kr, alternative
            /renewal date:\s*(.+)/i,                                     // alternative
            /Expires On:\s*(.+)/i,                                       // alternative
            /\[有効期限\]\s+(.+)/,                                       // .jp (Expiry Date in Japanese)
        ];

        for (const pattern of patterns) {
            const match = whoisText.match(pattern);
            if (match) {
                const rawDate = match[1].trim();
                return normalizeDateString(rawDate);
            }
        }

        return null;
    };

    // Try enhanced parsing for various ccTLD formats
    const parsedDomain = parseField('Domain', ['Domain Name', 'domain name', 'domain']);

    return {
        domainName: parsedDomain || domainName, // Use fallback if parsing failed
        registrar: parseField('Registrar', ['REGISTRAR', 'registrar']),
        creationDate: parseCreationDate(),
        expirationDate: parseExpiryDate(),
        nameservers: parseNameservers(),
        registrant: parseField('Registrant', ['registrant name', 'org', 'Organization']),
        status: parseStatus(),
        dnssec: parseField('DNSSEC', ['Signed', 'dnssec']),
        lastModified: parseField('Last Modified', ['last modified', 'Last Update', 'Changed', 'changed']),
    };
}
