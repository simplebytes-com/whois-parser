/**
 * WHOIS Parser for ccTLDs
 *
 * A comprehensive WHOIS parser supporting 169 country-code TLDs with various formats.
 * Built for DomainDetails.com
 *
 * @author Simple Bytes LLC
 * @license MIT
 * @version 1.1.0
 */

import net from 'net';

// ============================================================================
// Custom Error Classes
// ============================================================================

/**
 * Base error class for WHOIS errors
 */
export class WhoisError extends Error {
    constructor(message, code, server = null) {
        super(message);
        this.name = 'WhoisError';
        this.code = code;
        this.server = server;
    }
}

/**
 * Error thrown when connection to WHOIS server fails
 */
export class ConnectionError extends WhoisError {
    constructor(message, server) {
        super(message, 'CONNECTION_ERROR', server);
        this.name = 'ConnectionError';
    }
}

/**
 * Error thrown when WHOIS server times out
 */
export class TimeoutError extends WhoisError {
    constructor(message, server, timeoutMs) {
        super(message, 'TIMEOUT', server);
        this.name = 'TimeoutError';
        this.timeoutMs = timeoutMs;
    }
}

/**
 * Error thrown when WHOIS server returns no data
 */
export class NoDataError extends WhoisError {
    constructor(message, server) {
        super(message, 'NO_DATA', server);
        this.name = 'NoDataError';
    }
}

/**
 * Error thrown for invalid input parameters
 */
export class ValidationError extends WhoisError {
    constructor(message, field) {
        super(message, 'VALIDATION_ERROR');
        this.name = 'ValidationError';
        this.field = field;
    }
}

// ============================================================================
// Input Validation
// ============================================================================

/**
 * Validate domain name format
 * @param {string} domain - Domain name to validate
 * @returns {boolean} True if valid
 */
export function isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    // Basic domain validation - allows IDN and ccTLD formats
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainRegex.test(domain) && domain.length <= 253;
}

/**
 * Validate WHOIS server address
 * @param {string} server - Server address to validate
 * @returns {boolean} True if valid
 */
export function isValidServer(server) {
    if (!server || typeof server !== 'string') return false;
    // Allow hostnames and IP addresses
    return server.length > 0 && server.length <= 253;
}

// ============================================================================
// WHOIS Query
// ============================================================================

/**
 * Query a WHOIS server for domain information
 * @param {string} domain - Domain name to query
 * @param {string} server - WHOIS server address
 * @param {Object} options - Query options
 * @param {number} options.timeout - Timeout in milliseconds (default: 30000)
 * @returns {Promise<string>} WHOIS response text
 * @throws {ValidationError} If domain or server is invalid
 * @throws {ConnectionError} If connection fails
 * @throws {TimeoutError} If server times out
 * @throws {NoDataError} If server returns no data
 */
export function whoisQuery(domain, server, options = {}) {
    const timeout = typeof options === 'number' ? options : (options.timeout || 30000);

    // Input validation
    if (!domain || typeof domain !== 'string') {
        return Promise.reject(new ValidationError('Domain name is required', 'domain'));
    }
    if (!server || typeof server !== 'string') {
        return Promise.reject(new ValidationError('WHOIS server address is required', 'server'));
    }

    return new Promise((resolve, reject) => {
        const socket = net.createConnection(43, server);
        let data = '';

        socket.on('connect', () => {
            socket.write(`${domain}\r\n`);
        });

        socket.on('data', (chunk) => {
            data += chunk.toString();
        });

        socket.on('end', () => {
            if (!data || data.trim().length === 0) {
                reject(new NoDataError(`WHOIS server ${server} returned no data`, server));
            } else {
                resolve(data);
            }
        });

        socket.on('error', (err) => {
            if (err.code === 'ECONNREFUSED') {
                reject(new ConnectionError(`Connection refused by WHOIS server ${server}`, server));
            } else if (err.code === 'ENOTFOUND') {
                reject(new ConnectionError(`WHOIS server ${server} not found`, server));
            } else {
                reject(new ConnectionError(`WHOIS server ${server} error: ${err.message}`, server));
            }
        });

        socket.setTimeout(timeout, () => {
            socket.destroy();
            reject(new TimeoutError(`WHOIS server ${server} timed out after ${timeout / 1000} seconds`, server, timeout));
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
        // Use slice(1).join(':') to preserve colons in the value (e.g., URLs like https://...)
        return matches ? matches.map(match => match.split(':').slice(1).join(':').trim()) : [];
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
        // Try single-line format first (most common)
        const singleLineMatch = parseMultipleFields('Domain Status') ||
                               parseMultipleFields('Status') ||
                               parseMultipleFields('state');

        if (singleLineMatch && singleLineMatch.length > 0) {
            // Return immediately if we found valid single-line status codes
            return singleLineMatch;
        }

        // Try multi-line status format (.gg, .je) only if single-line didn't work
        const statusSection = whoisText.match(/Domain Status:\s*([\s\S]*?)(?=\n\n|Registrant:)/i);
        if (statusSection) {
            const statuses = statusSection[1]
                .split('\n')
                .map(line => line.trim())
                .filter(line => line);
            if (statuses.length > 0) return statuses;
        }

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
        // Check for recurring annual fee pattern first (.gg, .je domains)
        // For these domains, expiration is handled by renewalInfo instead
        const recurringPattern = /Registry fee due on (\d+(?:st|nd|rd|th) \w+ each year)/i;
        const recurringMatch = whoisText.match(recurringPattern);
        if (recurringMatch) {
            // For domains with annual recurring fees (like .gg, .je), don't set expiration date
            // This is handled separately in parseRenewalInfo()
            return null;
        }

        // Try various expiry date formats
        const patterns = [
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

    const parseRenewalInfo = () => {
        // Check for recurring annual fee pattern (.gg, .je domains)
        const recurringPattern = /Registry fee due on (\d+(?:st|nd|rd|th) \w+ each year)/i;
        const recurringMatch = whoisText.match(recurringPattern);
        if (recurringMatch) {
            const rawDate = recurringMatch[1].trim();
            // Extract day and month for annual renewal
            const dateMatch = rawDate.match(/(\d+)(?:st|nd|rd|th)\s+(\w+)/i);
            if (dateMatch) {
                const [, day, month] = dateMatch;
                return {
                    type: 'annual_renewal',
                    renewalDay: parseInt(day),
                    renewalMonth: month,
                    description: 'Registered until cancelled with annual fee'
                };
            }
        }

        // Check for "Registered until cancelled" status
        if (/Registered until cancelled/i.test(whoisText)) {
            return {
                type: 'until_cancelled',
                description: 'Registered until cancelled'
            };
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
        renewalInfo: parseRenewalInfo(), // For annual renewal domains (.gg, .je)
        nameservers: parseNameservers(),
        registrant: parseField('Registrant', ['registrant name', 'org', 'Organization']),
        status: parseStatus(),
        dnssec: parseField('DNSSEC', ['Signed', 'dnssec']),
        lastModified: parseField('Updated Date', ['Last Modified', 'last modified', 'Last Update', 'Changed', 'changed']),
    };
}
