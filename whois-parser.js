/**
 * WHOIS Parser for ccTLDs
 *
 * A comprehensive WHOIS parser supporting 169 country-code TLDs with various formats.
 * Built for DomainDetails.com
 *
 * Parsing is line-oriented: every response line is decomposed into normalized
 * key/value entries (including sectioned formats like .uk/.gg/.it and the
 * .jp bracket format), then fields are resolved through the alias lists in
 * field-mappings.js. This avoids the substring false-positives of free-text
 * regex matching.
 *
 * @author Simple Bytes LLC
 * @license MIT
 * @version 1.2.0
 */

import net from 'net';
import { domainToASCII } from 'url';
import {
    DOMAIN_NAME_FIELDS,
    REGISTRAR_FIELDS,
    REGISTRAR_URL_FIELDS,
    REGISTRAR_IANA_ID_FIELDS,
    REGISTRAR_WHOIS_SERVER_FIELDS,
    ABUSE_EMAIL_FIELDS,
    REGISTRANT_FIELDS,
    REGISTRANT_COUNTRY_FIELDS,
    CREATION_DATE_FIELDS,
    EXPIRATION_DATE_FIELDS,
    UPDATED_DATE_FIELDS,
    NAMESERVER_FIELDS,
    STATUS_FIELDS,
    DNSSEC_FIELDS,
} from './field-mappings.js';

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

/**
 * Error thrown when the WHOIS server refuses the query due to rate limiting
 */
export class RateLimitError extends WhoisError {
    constructor(message, server) {
        super(message, 'RATE_LIMITED', server);
        this.name = 'RateLimitError';
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
    // Basic domain validation - allows IDN (punycode) and ccTLD formats
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
// Availability & Rate-Limit Detection
// ============================================================================

// Registry-specific "domain does not exist" responses. Anchored to line
// starts wherever possible so remark text inside a registered-domain record
// cannot trigger a false "available".
const AVAILABILITY_PATTERNS = [
    /^\s*No match for/im,                             // Verisign, .uk, .gg
    /^\s*NOT FOUND\b/im,                              // Identity Digital registries
    /^\s*%?\s*Domain not found/im,                    // .fi, .ee
    /^\s*No Data Found/im,
    /^\s*No entries found/im,                         // .ru, .dk
    /The queried object does not exist/i,             // various EPP registries
    /^\s*Object does not exist/im,
    /^\s*No match!!/im,                               // .jp
    /^\s*Status:\s*(free|AVAILABLE)\s*$/im,           // .de, .be, .eu, .it
    /^\s*[a-z0-9.\-]+\.[a-z]{2,} is free\b/im,        // .nl
    /is available for (registration|purchase)/i,
    /^\s*This domain name has not been registered/im, // .uk (Nominet)
    /Above domain name is not registered/i,           // .kr (KRNIC)
    /No information available about domain name/i,    // .pl (NASK)
    /"[^"\n]+" not found/i,                           // .se, .nu
    /^\s*No records matching/im,                      // .ax
    /Not Registered - /i,                             // .ie
    /^\s*%ERROR:101:/im,                              // .cz
    /no matching record/i,                            // .tw
    /^\s*%?\s*nothing found/im,                       // .at
];

// Responses that mean "you were throttled", not "the domain is free" and not
// "the domain has no data". Parsing these as domain records produces the
// empty/garbage results this module previously suffered from.
const RATE_LIMIT_PATTERNS = [
    /quota exceeded/i,
    /rate limit/i,
    /too many requests/i,
    /exceeded the maximum/i,
    /maximum number of (queries|requests)/i,
    /number of allowed queries exceeded/i,            // .it
    /excessive querying/i,                            // .ch
    /WHOIS LIMIT EXCEEDED/i,
    /requests of this client are not permitted/i,     // .ch
    /access will only be enabled for\s+IP addresses\s+authori[sz]ed/i, // .es
    /query rate exceeded/i,
    /connection limit exceeded/i,
    /IP (address )?(has been |is )?(temporarily )?(blocked|banned)/i,
    /server (is )?too busy/i,
];

/**
 * Check whether a raw WHOIS response says the query was rate limited.
 * @param {string} whoisText - Raw WHOIS response text
 * @returns {boolean} True if the response is a rate-limit/abuse rejection
 */
export function isRateLimited(whoisText) {
    if (!whoisText || typeof whoisText !== 'string') return false;
    return RATE_LIMIT_PATTERNS.some((p) => p.test(whoisText));
}

/**
 * Check whether a raw WHOIS response says the domain is not registered.
 * @param {string} whoisText - Raw WHOIS response text
 * @returns {boolean} True if the domain appears available for registration
 */
export function isDomainAvailable(whoisText) {
    if (!whoisText || typeof whoisText !== 'string') return false;
    if (isRateLimited(whoisText)) return false;
    return AVAILABILITY_PATTERNS.some((p) => p.test(whoisText));
}

// ============================================================================
// Date Normalization
// ============================================================================

const MONTHS = {
    jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06',
    jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12',
};

const monthNumber = (name) => MONTHS[name.slice(0, 3).toLowerCase()] || null;
const pad2 = (n) => String(n).padStart(2, '0');

// Timezone abbreviations seen in WHOIS output mapped to ISO offsets.
const TZ_ABBREVIATIONS = {
    JST: '+09:00',
    KST: '+09:00',
    UTC: 'Z',
    GMT: 'Z',
    CET: '+01:00',
    CEST: '+02:00',
    MSK: '+03:00',
};

const normalizeTimePart = (time) => {
    if (!time) return '00:00:00';
    return time.length === 5 ? `${time}:00` : time;
};

const normalizeOffset = (tz) => {
    if (!tz) return 'Z'; // no timezone given: assume UTC (pragmatic, keeps dates machine-parseable)
    if (tz === 'Z' || tz === 'z') return 'Z';
    const abbrev = TZ_ABBREVIATIONS[tz.toUpperCase()];
    if (abbrev) return abbrev;
    // +02 / +0200 / +02:00
    const m = tz.match(/^([+-])(\d{2}):?(\d{2})?$/);
    if (m) return `${m[1]}${m[2]}:${m[3] || '00'}`;
    return 'Z';
};

/**
 * Normalize a WHOIS date string to ISO 8601 where the format is recognized.
 * Unrecognized formats (e.g. .uk "before Aug-1996") are returned unchanged.
 *
 * @param {string} dateStr - Raw date string from a WHOIS response
 * @returns {string|null} ISO 8601 date string, the original string, or null
 */
export function normalizeDateString(dateStr) {
    if (!dateStr) return null;
    let str = dateStr.trim();

    // Strip trailing timezone abbreviation in parens: "2025/06/01 01:05:04 (JST)"
    let tzHint = null;
    const parenTz = str.match(/^(.*?)\s*\(([A-Z]{2,5})\)\s*$/);
    if (parenTz && TZ_ABBREVIATIONS[parenTz[2]]) {
        str = parenTz[1].trim();
        tzHint = parenTz[2];
    }

    // ISO date, optionally with time and timezone:
    // "2024-11-06", "2024-11-06T00:49:34Z", "1999-12-10 00:00:00", "2002-12-04 00:00:00+02"
    const isoMatch = str.match(
        /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?)(?:\.\d+)?\s*(Z|[+-]\d{2}(?::?\d{2})?)?)?$/
    );
    if (isoMatch) {
        const [, year, month, day, time, tz] = isoMatch;
        if (!time && !tz && !tzHint) return str; // plain "2024-11-06" or full ISO: preserve as-is
        return `${year}-${month}-${day}T${normalizeTimePart(time)}${normalizeOffset(tz || tzHint)}`;
    }

    // .jp style: "2005/05/30" with optional time
    const slashMatch = str.match(/^(\d{4})\/(\d{1,2})\/(\d{1,2})(?:\s+(\d{2}:\d{2}(?::\d{2})?))?$/);
    if (slashMatch) {
        const [, year, month, day, time] = slashMatch;
        return `${year}-${pad2(month)}-${pad2(day)}T${normalizeTimePart(time)}${normalizeOffset(tzHint)}`;
    }

    // .kr / .pl style: "2007. 03. 02." or "2002.09.19 13:00:00"
    const dotYmdMatch = str.match(/^(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})\.?(?:\s+(\d{2}:\d{2}(?::\d{2})?))?$/);
    if (dotYmdMatch) {
        const [, year, month, day, time] = dotYmdMatch;
        return `${year}-${pad2(month)}-${pad2(day)}T${normalizeTimePart(time)}${normalizeOffset(tzHint)}`;
    }

    // .fi style: "1.9.2006" / "5.9.2003 12:01:02" (day first)
    const dotDmyMatch = str.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})(?:\s+(\d{2}:\d{2}(?::\d{2})?))?$/);
    if (dotDmyMatch) {
        const [, day, month, year, time] = dotDmyMatch;
        return `${year}-${pad2(month)}-${pad2(day)}T${normalizeTimePart(time)}${normalizeOffset(tzHint)}`;
    }

    // .at style: "20240304 13:11:29"
    const compactMatch = str.match(/^(\d{4})(\d{2})(\d{2})(?:\s+(\d{2}:\d{2}(?::\d{2})?))?$/);
    if (compactMatch) {
        const [, year, month, day, time] = compactMatch;
        return `${year}-${month}-${day}T${normalizeTimePart(time)}${normalizeOffset(tzHint)}`;
    }

    // .uk / .ie style: "01-Dec-2023" or "1-Dec-2023"
    const dmyMatch = str.match(/^(\d{1,2})[- ]([A-Za-z]{3,9})[- ](\d{4})$/);
    if (dmyMatch) {
        const [, day, monthName, year] = dmyMatch;
        const month = monthNumber(monthName);
        if (month) return `${year}-${month}-${pad2(day)}T00:00:00Z`;
    }

    // .gg/.je style: "30th April 2003"
    const ordinalMatch = str.match(/(\d+)(?:st|nd|rd|th)\s+(\w+)\s+(\d{4})/i);
    if (ordinalMatch) {
        const [, day, monthName, year] = ordinalMatch;
        const month = monthNumber(monthName);
        if (month) return `${year}-${month}-${pad2(day)}T00:00:00Z`;
    }

    // Recurring dates: "30th April each year"
    const recurringMatch = str.match(/(\d+)(?:st|nd|rd|th)\s+(\w+)\s+each year/i);
    if (recurringMatch) {
        const [, day, monthName] = recurringMatch;
        const month = monthNumber(monthName);
        if (month) {
            const nextYear = new Date().getFullYear() + 1;
            return `${nextYear}-${month}-${pad2(day)}T00:00:00Z`;
        }
    }

    // Unrecognized format (e.g. .uk "before Aug-1996"): return unchanged
    return str;
}

// ============================================================================
// WHOIS Query
// ============================================================================

// Servers that need a non-default query string to return complete data.
const SERVER_QUERY_FORMATS = {
    'whois.denic.de': (domain) => `-T dn,ace ${domain}`,   // full record incl. nameservers
    'whois.jprs.jp': (domain) => `${domain}/e`,            // English output
    'whois.verisign-grs.com': (domain) => `domain ${domain}`, // exclude NS/registrar matches
};

const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;

/**
 * Query a WHOIS server for domain information
 * @param {string} domain - Domain name to query (IDN accepted; converted to punycode)
 * @param {string} server - WHOIS server address
 * @param {Object|number} options - Query options (or timeout in ms for backwards compatibility)
 * @param {number} options.timeout - Inactivity timeout in milliseconds (default: 30000)
 * @param {number} options.maxResponseBytes - Response size cap (default: 1 MiB)
 * @param {string} options.query - Override the query string sent to the server
 * @returns {Promise<string>} WHOIS response text
 * @throws {ValidationError} If domain or server is invalid
 * @throws {ConnectionError} If connection fails
 * @throws {TimeoutError} If server times out
 * @throws {NoDataError} If server returns no data
 */
export function whoisQuery(domain, server, options = {}) {
    const opts = typeof options === 'number' ? { timeout: options } : options;
    const timeout = opts.timeout || DEFAULT_TIMEOUT_MS;
    const maxResponseBytes = opts.maxResponseBytes || DEFAULT_MAX_RESPONSE_BYTES;

    if (!domain || typeof domain !== 'string') {
        return Promise.reject(new ValidationError('Domain name is required', 'domain'));
    }
    if (!server || typeof server !== 'string') {
        return Promise.reject(new ValidationError('WHOIS server address is required', 'server'));
    }

    let queryDomain = domain.trim().replace(/\.$/, '');
    // Convert internationalized domain names to punycode for the wire
    if (/[^\x00-\x7F]/.test(queryDomain)) {
        const ascii = domainToASCII(queryDomain);
        if (!ascii) {
            return Promise.reject(new ValidationError(`Invalid internationalized domain name: ${domain}`, 'domain'));
        }
        queryDomain = ascii;
    }
    if (!isValidDomain(queryDomain)) {
        return Promise.reject(new ValidationError(`Invalid domain name: ${domain}`, 'domain'));
    }
    if (!isValidServer(server)) {
        return Promise.reject(new ValidationError(`Invalid WHOIS server address: ${server}`, 'server'));
    }

    const format = SERVER_QUERY_FORMATS[server.toLowerCase()];
    const queryString = opts.query || (format ? format(queryDomain) : queryDomain);

    return new Promise((resolve, reject) => {
        const socket = net.createConnection(43, server);
        let data = '';
        let settled = false;

        const settle = (fn, value) => {
            if (settled) return;
            settled = true;
            fn(value);
        };

        socket.on('connect', () => {
            socket.write(`${queryString}\r\n`);
        });

        socket.on('data', (chunk) => {
            data += chunk.toString();
            if (data.length >= maxResponseBytes) {
                // Defensive cap: return what we have rather than buffering forever
                settle(resolve, data);
                socket.destroy();
            }
        });

        socket.on('end', () => {
            if (!data || data.trim().length === 0) {
                settle(reject, new NoDataError(`WHOIS server ${server} returned no data`, server));
            } else {
                settle(resolve, data);
            }
        });

        // Some registries close the connection abruptly (RST) after sending
        // the full response; treat received data as a successful reply.
        socket.on('close', () => {
            if (data && data.trim().length > 0) {
                settle(resolve, data);
            } else {
                settle(reject, new ConnectionError(`Connection to WHOIS server ${server} closed without data`, server));
            }
        });

        socket.on('error', (err) => {
            if (data && data.trim().length > 0 && err.code === 'ECONNRESET') {
                settle(resolve, data);
                return;
            }
            if (err.code === 'ECONNREFUSED') {
                settle(reject, new ConnectionError(`Connection refused by WHOIS server ${server}`, server));
            } else if (err.code === 'ENOTFOUND') {
                settle(reject, new ConnectionError(`WHOIS server ${server} not found`, server));
            } else {
                settle(reject, new ConnectionError(`WHOIS server ${server} error: ${err.message}`, server));
            }
        });

        socket.setTimeout(timeout, () => {
            settle(reject, new TimeoutError(`WHOIS server ${server} timed out after ${timeout / 1000} seconds`, server, timeout));
            socket.destroy();
        });
    });
}

// ============================================================================
// Line-Oriented Response Parsing
// ============================================================================

/**
 * Normalize a raw key for lookup: strip brackets/dot-leaders, collapse
 * whitespace, lowercase. "Domain Name" / "[Domain Name]" / "domain....." all
 * become "domain name" / "domain".
 */
const normalizeKey = (raw) =>
    raw
        .replace(/^\[|\]$/g, '')
        .replace(/[.\s]+$/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .toLowerCase();

const KV_LINE = /^([ \t]*)([^:\n]{1,64}?)[ \t.]*:[ \t]*(.*)$/;
const BRACKET_LINE = /^[ \t]*\[([^\[\]]+)\][ \t]*(.*?)[ \t]*$/;
const COMMENT_LINE = /^[ \t]*(%|#|>>>|\*\*\*)/;

/**
 * Decompose a WHOIS response into a key -> values multimap.
 *
 * Handles:
 * - "Key: value" (optionally indented, dot-leader "key....: value")
 * - "[Key]  value" (.jp bracket format)
 * - "Key:" followed by indented value lines (.uk/.gg/.nl sections)
 * - Bare section headers with indented children (.it "Registrant" /
 *   "Nameservers", .kr name-server blocks). Child key/value pairs are
 *   recorded under both the plain key and "<section> <key>".
 */
function extractEntries(whoisText) {
    const entries = new Map();

    const record = (key, value) => {
        if (!key) return;
        if (!entries.has(key)) entries.set(key, []);
        entries.get(key).push(value);
    };

    const lines = whoisText.split(/\r?\n/);
    let section = null; // { key, indent, sawKvChild }

    for (const line of lines) {
        if (!line.trim()) {
            section = null;
            continue;
        }
        if (COMMENT_LINE.test(line)) continue;

        const bracketMatch = line.match(BRACKET_LINE);
        if (bracketMatch) {
            section = null;
            record(normalizeKey(bracketMatch[1]), bracketMatch[2].trim());
            continue;
        }

        const indent = line.match(/^[ \t]*/)[0].length;
        let kvMatch = line.match(KV_LINE);
        // A colon belonging to a URL ("... (http://x)") is not a key separator
        if (kvMatch && kvMatch[3].startsWith('//')) kvMatch = null;

        if (kvMatch) {
            const key = normalizeKey(kvMatch[2]);
            const value = kvMatch[3].trim();

            if (!value) {
                // "Key:" with no value opens a section; following lines are
                // its values or its prefixed sub-fields (.uk "Domain name:",
                // .gg "Registrant:", .ee "Registrant:" at equal indent)
                section = { key, indent, sawKvChild: false };
                continue;
            }

            if (section && indent >= section.indent) {
                record(`${section.key} ${key}`, value);
                section.sawKvChild = true;
            } else if (section) {
                section = null; // dedent closes the section
            }
            record(key, value);
            continue;
        }

        // Bare line (no colon). A deeper-indented bare line is a section
        // value (.gg/.uk nameserver lists) unless the section already has
        // key/value children — then it is a wrapped continuation of the
        // previous value (.it multi-line addresses) and is skipped.
        if (section && indent > section.indent) {
            if (!section.sawKvChild) record(section.key, line.trim());
        } else {
            // Bare header candidate (.it "Nameservers", .kr "Primary Name Server")
            section = { key: normalizeKey(line), indent, sawKvChild: false };
        }
    }

    return entries;
}

const REDACTED_VALUE = /redacted|privacy|data protected|not disclosed|withheld|gdpr masked|^gdpr$|not shown|statutory masking/i;

// ============================================================================
// Public Parse API
// ============================================================================

/**
 * Parse WHOIS data from raw text response
 * @param {string} whoisText - Raw WHOIS response text
 * @param {string} domainName - Domain name as fallback (optional)
 * @returns {Object} Parsed WHOIS data
 */
export function parseWhoisData(whoisText, domainName = null) {
    if (!whoisText || typeof whoisText !== 'string') whoisText = '';

    const entries = extractEntries(whoisText);
    const lookup = (alias) => entries.get(normalizeKey(alias)) || [];

    /** First non-empty value across aliases, in alias-priority order */
    const getFirst = (aliases) => {
        for (const alias of aliases) {
            for (const value of lookup(alias)) {
                if (value) return value;
            }
        }
        return null;
    };

    /** All non-empty values across aliases, deduplicated, order preserved */
    const getAll = (aliases) => {
        const seen = new Set();
        const values = [];
        for (const alias of aliases) {
            for (const value of lookup(alias)) {
                if (value && !seen.has(value)) {
                    seen.add(value);
                    values.push(value);
                }
            }
        }
        return values;
    };

    // ---- Registrant (with privacy-redaction fallback to organization) ----
    const parseRegistrant = () => {
        const candidates = getAll(REGISTRANT_FIELDS);
        if (candidates.length === 0) return null;
        const disclosed = candidates.find((v) => !REDACTED_VALUE.test(v));
        return disclosed || candidates[0];
    };

    // ---- Nameservers ----
    const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
    const HOSTNAME = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$/;

    const parseNameservers = () => {
        const raw = getAll(NAMESERVER_FIELDS);
        const seen = new Set();
        const servers = [];
        for (const value of raw) {
            // ".ru format: ns1.yandex.ru. 213.180.193.1" -> take the hostname token
            const host = value.split(/\s+/)[0].replace(/\.$/, '').toLowerCase();
            if (!host || IPV4.test(host) || host.includes(':') || !HOSTNAME.test(host)) continue;
            if (seen.has(host)) continue;
            seen.add(host);
            servers.push(host);
        }
        return servers.length > 0 ? servers : null;
    };

    // ---- Status ----
    const parseStatus = () => {
        const statuses = getAll(STATUS_FIELDS)
            // .kr publishes "정보공개여부: Y" (publish yes/no) under a status-like key
            .filter((s) => s !== 'Y' && s !== 'N');
        return statuses.length > 0 ? statuses : null;
    };

    // ---- Dates ----
    const parseCreationDate = () => {
        const value = getFirst(CREATION_DATE_FIELDS);
        if (value) return normalizeDateString(value);

        // Freeform fallbacks that carry the date inside prose (.gg/.je)
        const proseMatch = whoisText.match(/Registered on (\d+(?:st|nd|rd|th) \w+ \d{4})/i);
        if (proseMatch) return normalizeDateString(proseMatch[1].trim());
        return null;
    };

    const recurringFeeMatch = whoisText.match(/Registry fee due on (\d+(?:st|nd|rd|th) \w+ each year)/i);

    const parseExpiryDate = () => {
        // .gg/.je domains renew annually until cancelled; expiration is
        // expressed via renewalInfo instead of a fixed date
        if (recurringFeeMatch) return null;

        const value = getFirst(EXPIRATION_DATE_FIELDS);
        return value ? normalizeDateString(value) : null;
    };

    const parseRenewalInfo = () => {
        if (recurringFeeMatch) {
            const dateMatch = recurringFeeMatch[1].match(/(\d+)(?:st|nd|rd|th)\s+(\w+)/i);
            if (dateMatch) {
                const [, day, month] = dateMatch;
                return {
                    type: 'annual_renewal',
                    renewalDay: parseInt(day, 10),
                    renewalMonth: month,
                    description: 'Registered until cancelled with annual fee',
                };
            }
        }

        if (/Registered until cancelled/i.test(whoisText)) {
            return {
                type: 'until_cancelled',
                description: 'Registered until cancelled',
            };
        }

        return null;
    };

    const parseLastModified = () => {
        const value = getFirst(UPDATED_DATE_FIELDS);
        return value ? normalizeDateString(value) : null;
    };

    // ---- Registrar ----
    const parseRegistrar = () => {
        const value = getFirst(REGISTRAR_FIELDS);
        if (!value) return null;
        // .uk appends the registrar tag: "British Broadcasting Corporation [Tag = BBC]"
        return value.replace(/\s*\[Tag\s*=\s*[^\]]*\]\s*$/i, '').trim() || null;
    };

    const parsedDomain = getFirst(DOMAIN_NAME_FIELDS);
    const creationDate = parseCreationDate();
    const nameservers = parseNameservers();

    const available = isDomainAvailable(whoisText) && !creationDate && !nameservers;
    const rateLimited = isRateLimited(whoisText);

    return {
        domainName: parsedDomain || domainName, // Use fallback if parsing failed
        registrar: parseRegistrar(),
        registrarUrl: getFirst(REGISTRAR_URL_FIELDS),
        registrarIanaId: getFirst(REGISTRAR_IANA_ID_FIELDS),
        registrarWhoisServer: getFirst(REGISTRAR_WHOIS_SERVER_FIELDS),
        abuseContactEmail: getFirst(ABUSE_EMAIL_FIELDS),
        creationDate,
        expirationDate: parseExpiryDate(),
        renewalInfo: parseRenewalInfo(), // For annual renewal domains (.gg, .je)
        nameservers,
        registrant: parseRegistrant(),
        registrantCountry: getFirst(REGISTRANT_COUNTRY_FIELDS),
        status: parseStatus(),
        dnssec: getFirst(DNSSEC_FIELDS),
        lastModified: parseLastModified(),
        isAvailable: available,
        isRateLimited: rateLimited,
    };
}
