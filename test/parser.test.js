import { describe, it, expect, beforeAll } from 'vitest';
import { parseWhoisData } from '../whois-parser.js';
import * as fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load fixtures
const loadFixture = (name) => {
    return fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
};

describe('parseWhoisData', () => {
    describe('Japanese format (.jp)', () => {
        let result;

        beforeAll(() => {
            const whoisText = loadFixture('jp-format.txt');
            result = parseWhoisData(whoisText, 'google.jp');
        });

        it('should parse domain name with square bracket format', () => {
            expect(result.domainName).toBe('GOOGLE.JP');
        });

        it('should parse registrant', () => {
            expect(result.registrant).toBe('Google LLC');
        });

        it('should parse nameservers', () => {
            expect(result.nameservers).toContain('ns1.google.com');
            expect(result.nameservers).toContain('ns2.google.com');
            expect(result.nameservers.length).toBe(4);
        });

        it('should parse creation date from Japanese field', () => {
            expect(result.creationDate).toBe('2005-05-30T00:00:00Z');
        });

        it('should parse expiration date from Japanese field', () => {
            expect(result.expirationDate).toBe('2026-05-31T00:00:00Z');
        });

        it('should parse status from Japanese field [状態]', () => {
            expect(result.status).toContain('Active');
        });
    });

    describe('Korean format (.kr)', () => {
        let result;

        beforeAll(() => {
            const whoisText = loadFixture('kr-format.txt');
            result = parseWhoisData(whoisText, 'naver.kr');
        });

        it('should parse domain name', () => {
            expect(result.domainName).toBe('naver.kr');
        });

        it('should parse creation date with Korean date format', () => {
            expect(result.creationDate).toBe('2007-03-02T00:00:00Z');
        });

        it('should parse expiration date with Korean date format', () => {
            expect(result.expirationDate).toBe('2028-03-02T00:00:00Z');
        });

        it('should parse nameservers from Host Name field', () => {
            expect(result.nameservers).toContain('ns1.naver.com');
            expect(result.nameservers).toContain('ns2.naver.com');
        });

        // Parser returns first match - Korean version comes before English
        it('should parse DNSSEC status (returns Korean text)', () => {
            expect(result.dnssec).toBe('미서명');
        });
    });

    describe('Guernsey format (.gg/.je) with natural language dates', () => {
        let result;

        beforeAll(() => {
            const whoisText = loadFixture('gg-format.txt');
            result = parseWhoisData(whoisText, 'google.gg');
        });

        it('should parse domain name', () => {
            expect(result.domainName).toBe('google.gg');
        });

        it('should parse registrant', () => {
            expect(result.registrant).toBe('Google LLC');
        });

        it('should parse registrar', () => {
            expect(result.registrar).toContain('MarkMonitor');
        });

        it('should parse creation date from natural language format', () => {
            expect(result.creationDate).toBe('2003-04-30T00:00:00Z');
        });

        it('should NOT set expiration date for recurring annual fee domains', () => {
            // .gg/.je domains have annual fees, not fixed expiration
            expect(result.expirationDate).toBeNull();
        });

        it('should parse renewalInfo for annual renewal domains', () => {
            expect(result.renewalInfo).not.toBeNull();
            expect(result.renewalInfo.type).toBe('annual_renewal');
            expect(result.renewalInfo.renewalDay).toBe(30);
            expect(result.renewalInfo.renewalMonth).toBe('April');
        });

        it('should parse nameservers from multi-line format', () => {
            expect(result.nameservers).toContain('ns1.google.com');
            expect(result.nameservers).toContain('ns2.google.com');
            expect(result.nameservers.length).toBe(4);
        });

        it('should parse domain status', () => {
            expect(result.status).toContain('Registered until cancelled');
        });
    });

    describe('Russian format (.ru)', () => {
        let result;

        beforeAll(() => {
            const whoisText = loadFixture('ru-format.txt');
            result = parseWhoisData(whoisText, 'yandex.ru');
        });

        it('should parse domain name', () => {
            expect(result.domainName).toBe('YANDEX.RU');
        });

        it('should parse registrar', () => {
            expect(result.registrar).toBe('RU-CENTER-RU');
        });

        it('should parse creation date', () => {
            expect(result.creationDate).toBe('1997-09-23T09:45:07Z');
        });

        it('should parse expiration date from paid-till field', () => {
            expect(result.expirationDate).toBe('2025-09-30T21:00:00Z');
        });

        it('should parse nameservers with trailing dots and IPs removed', () => {
            expect(result.nameservers).toContain('ns1.yandex.ru');
            expect(result.nameservers).toContain('ns2.yandex.ru');
            // Should NOT include IP addresses
            expect(result.nameservers.join(' ')).not.toContain('213.180.193.1');
        });

        it('should parse status from state field', () => {
            expect(result.status).toContain('REGISTERED, DELEGATED, VERIFIED');
        });

        it('should parse organization as registrant', () => {
            expect(result.registrant).toBe('YANDEX, LLC');
        });
    });

    describe('Standard format (.io and similar)', () => {
        let result;

        beforeAll(() => {
            const whoisText = loadFixture('io-format.txt');
            result = parseWhoisData(whoisText, 'meeting.io');
        });

        it('should parse domain name', () => {
            expect(result.domainName).toBe('MEETING.IO');
        });

        it('should parse registrar', () => {
            expect(result.registrar).toBe('Uniregistrar Corp');
        });

        it('should parse creation date', () => {
            expect(result.creationDate).toBe('2018-02-20T20:04:42Z');
        });

        it('should parse expiration date', () => {
            expect(result.expirationDate).toBe('2026-02-20T20:04:42Z');
        });

        it('should parse last modified date', () => {
            expect(result.lastModified).toBe('2024-11-06T00:49:34Z');
        });

        it('should parse nameservers', () => {
            expect(result.nameservers).toContain('ns-1012.awsdns-62.net');
            expect(result.nameservers).toContain('ns-57.awsdns-07.com');
            expect(result.nameservers.length).toBe(4);
        });

        it('should parse multiple domain statuses with URLs preserved', () => {
            expect(result.status.length).toBe(3);
            expect(result.status[0]).toContain('clientDeleteProhibited');
            expect(result.status[0]).toContain('https://');
        });

        it('should parse DNSSEC status', () => {
            expect(result.dnssec).toBe('unsigned');
        });

        // When Registrant Name is redacted, fall back to the first
        // non-redacted registrant field (here: Registrant Organization)
        it('should fall back to Organization when Registrant Name is REDACTED', () => {
            expect(result.registrant).toBe('Meeting.io, Inc.');
        });

        it('should parse registrar URL, IANA ID, WHOIS server and abuse email', () => {
            expect(result.registrarUrl).toBe('http://www.uniregistry.com');
            expect(result.registrarIanaId).toBe('1659');
            expect(result.registrarWhoisServer).toBe('whois.uniregistrar.net');
            expect(result.abuseContactEmail).toBe('abuse@uniregistry.com');
        });

        it('should parse registrant country', () => {
            expect(result.registrantCountry).toBe('US');
        });

        it('should not report a registered domain as available', () => {
            expect(result.isAvailable).toBe(false);
            expect(result.isRateLimited).toBe(false);
        });
    });

    describe('Edge cases', () => {
        it('should use fallback domain name when not found in WHOIS', () => {
            const result = parseWhoisData('Some random text without domain', 'example.com');
            expect(result.domainName).toBe('example.com');
        });

        it('should return null for missing fields', () => {
            const result = parseWhoisData('Domain Name: test.com', 'test.com');
            expect(result.registrar).toBeNull();
            expect(result.creationDate).toBeNull();
            expect(result.expirationDate).toBeNull();
        });

        it('should handle empty input gracefully', () => {
            const result = parseWhoisData('', 'fallback.com');
            expect(result.domainName).toBe('fallback.com');
        });

        it('should handle dotted format (domain...: value)', () => {
            const whoisText = 'domain...............: test.ax\nregistrar...........: Example Registrar';
            const result = parseWhoisData(whoisText);
            expect(result.domainName).toBe('test.ax');
            expect(result.registrar).toBe('Example Registrar');
        });
    });

    describe('Date normalization', () => {
        it('should normalize JP date format YYYY/MM/DD', () => {
            const whoisText = 'Creation Date: 2005/05/30';
            const result = parseWhoisData(whoisText);
            expect(result.creationDate).toBe('2005-05-30T00:00:00Z');
        });

        it('should normalize KR date format YYYY. MM. DD.', () => {
            const whoisText = 'Registered Date: 2007. 03. 02.';
            const result = parseWhoisData(whoisText);
            expect(result.creationDate).toBe('2007-03-02T00:00:00Z');
        });

        it('should normalize natural language dates', () => {
            const whoisText = 'Registered on 30th April 2003';
            const result = parseWhoisData(whoisText);
            expect(result.creationDate).toBe('2003-04-30T00:00:00Z');
        });

        it('should handle ordinal suffixes (1st, 2nd, 3rd, 11th, etc)', () => {
            const testCases = [
                { input: 'Registered on 1st January 2020', expected: '2020-01-01T00:00:00Z' },
                { input: 'Registered on 2nd February 2020', expected: '2020-02-02T00:00:00Z' },
                { input: 'Registered on 3rd March 2020', expected: '2020-03-03T00:00:00Z' },
                { input: 'Registered on 11th November 2020', expected: '2020-11-11T00:00:00Z' },
                { input: 'Registered on 21st December 2020', expected: '2020-12-21T00:00:00Z' },
            ];

            for (const { input, expected } of testCases) {
                const result = parseWhoisData(input);
                expect(result.creationDate).toBe(expected);
            }
        });

        it('should preserve ISO 8601 dates as-is', () => {
            const whoisText = 'Creation Date: 2024-11-06T00:49:34Z';
            const result = parseWhoisData(whoisText);
            expect(result.creationDate).toBe('2024-11-06T00:49:34Z');
        });
    });
});
