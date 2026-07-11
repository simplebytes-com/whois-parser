import { describe, it, expect, beforeAll } from 'vitest';
import { parseWhoisData } from '../whois-parser.js';
import * as fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const loadFixture = (name) =>
    fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

describe('parseWhoisData - additional registries', () => {
    describe('UK format (.uk Nominet)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('uk-format.txt'), 'bbc.co.uk');
        });

        it('should parse domain name from indented section', () => {
            expect(result.domainName).toBe('bbc.co.uk');
        });

        it('should parse registrar with [Tag = ...] suffix stripped', () => {
            expect(result.registrar).toBe('British Broadcasting Corporation');
        });

        it('should parse registrar URL from registrar section', () => {
            expect(result.registrarUrl).toBe('http://www.bbc.co.uk');
        });

        it('should keep unparseable creation date as-is', () => {
            expect(result.creationDate).toBe('before Aug-1996');
        });

        it('should parse expiry date in dd-Mon-yyyy format', () => {
            expect(result.expirationDate).toBe('2025-12-13T00:00:00Z');
        });

        it('should parse last updated date', () => {
            expect(result.lastModified).toBe('2024-12-10T00:00:00Z');
        });

        it('should parse registration status', () => {
            expect(result.status).toContain('Registered until expiry date.');
        });

        it('should parse nameservers and drop glue IPs', () => {
            expect(result.nameservers).toEqual(['ddns0.bbc.co.uk', 'ddns1.bbc.com']);
        });

        it('should not be reported available', () => {
            expect(result.isAvailable).toBe(false);
        });
    });

    describe('German format (.de DENIC)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('de-format.txt'), 'google.de');
        });

        it('should parse domain, status and nameservers', () => {
            expect(result.domainName).toBe('google.de');
            expect(result.status).toEqual(['connect']);
            expect(result.nameservers.length).toBe(4);
            expect(result.nameservers).toContain('ns1.google.com');
        });

        it('should parse Changed date with timezone offset', () => {
            expect(result.lastModified).toBe('2018-03-12T21:44:25+01:00');
        });
    });

    describe('Italian format (.it)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('it-format.txt'), 'google.it');
        });

        it('should parse domain and status', () => {
            expect(result.domainName).toBe('google.it');
            expect(result.status).toEqual(['ok']);
        });

        it('should parse registrant organization from section', () => {
            expect(result.registrant).toBe('Google LLC');
        });

        it('should not leak address continuation lines into fields', () => {
            expect(result.registrant).not.toBe('94043');
            expect(result.registrant).not.toBe('Mountain View');
        });

        it('should parse registrar organization from section', () => {
            expect(result.registrar).toBe('MarkMonitor International Limited');
        });

        it('should parse dates with space-separated time', () => {
            expect(result.creationDate).toBe('1999-12-10T00:00:00Z');
            expect(result.lastModified).toBe('2024-12-27T00:47:56Z');
            expect(result.expirationDate).toBe('2025-12-11');
        });

        it('should parse nameservers from bare section', () => {
            expect(result.nameservers.length).toBe(4);
            expect(result.nameservers).toContain('ns1.google.com');
        });

        it('should parse DNSSEC from Signed field', () => {
            expect(result.dnssec).toBe('no');
        });
    });

    describe('Dutch format (.nl SIDN)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('nl-format.txt'), 'google.nl');
        });

        it('should parse domain, status and dates', () => {
            expect(result.domainName).toBe('google.nl');
            expect(result.status).toEqual(['active']);
            expect(result.creationDate).toBe('1999-05-27');
            expect(result.lastModified).toBe('2015-12-01');
        });

        it('should parse registrar from indented section', () => {
            expect(result.registrar).toBe('MarkMonitor Inc.');
        });

        it('should parse nameservers from "Domain nameservers" section', () => {
            expect(result.nameservers.length).toBe(4);
            expect(result.nameservers).toContain('ns1.google.com');
        });

        it('should parse DNSSEC', () => {
            expect(result.dnssec).toBe('no');
        });
    });

    describe('Finnish format (.fi dot-leader keys)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('fi-format.txt'), 'google.fi');
        });

        it('should parse domain and status', () => {
            expect(result.domainName).toBe('google.fi');
            expect(result.status).toEqual(['Registered']);
        });

        it('should parse d.m.yyyy dates', () => {
            expect(result.creationDate).toBe('2006-06-12T00:00:00Z');
            expect(result.expirationDate).toBe('2026-07-04T00:00:00Z');
            expect(result.lastModified).toBe('2025-06-05T00:00:00Z');
        });

        it('should parse nameservers and drop [Ok] suffix', () => {
            expect(result.nameservers).toEqual([
                'ns1.google.com',
                'ns2.google.com',
                'ns3.google.com',
            ]);
        });

        it('should parse holder name as registrant', () => {
            expect(result.registrant).toBe('Google LLC');
        });

        it('should parse registrant country', () => {
            expect(result.registrantCountry).toBe('United States of America');
        });
    });

    describe('Estonian format (.ee equal-indent sections)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('ee-format.txt'), 'google.ee');
        });

        it('should parse domain name from Domain section', () => {
            expect(result.domainName).toBe('google.ee');
        });

        it('should parse status', () => {
            expect(result.status).toContain('ok (paid and in zone)');
        });

        it('should parse dates with timezone offsets', () => {
            expect(result.creationDate).toBe('2010-07-04T06:26:24+03:00');
            expect(result.expirationDate).toBe('2025-07-04');
            expect(result.lastModified).toBe('2024-06-25T09:15:20+03:00');
        });

        it('should parse registrant from Registrant section', () => {
            expect(result.registrant).toBe('Google LLC');
        });

        it('should parse registrant country', () => {
            expect(result.registrantCountry).toBe('US');
        });

        it('should parse registrar name and URL from Registrar section', () => {
            expect(result.registrar).toBe('Zone Media OÜ');
            expect(result.registrarUrl).toBe('http://www.zone.ee');
        });

        it('should parse nameservers', () => {
            expect(result.nameservers).toEqual(['ns1.google.com', 'ns2.google.com']);
        });
    });

    describe('Danish format (.dk)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('dk-format.txt'), 'google.dk');
        });

        it('should parse domain name', () => {
            expect(result.domainName).toBe('google.dk');
        });

        it('should not treat the DNS field (zone name) as a nameserver', () => {
            expect(result.nameservers).not.toContain('google.dk');
        });

        it('should parse nameservers from Hostname fields', () => {
            expect(result.nameservers.length).toBe(4);
            expect(result.nameservers).toContain('ns1.google.com');
        });

        it('should parse dates', () => {
            expect(result.creationDate).toBe('1999-01-10');
            expect(result.expirationDate).toBe('2026-03-31');
        });

        it('should parse registrant from Registrant section', () => {
            expect(result.registrant).toBe('Google LLC');
            expect(result.registrantCountry).toBe('US');
        });

        it('should parse status and DNSSEC', () => {
            expect(result.status).toEqual(['Active']);
            expect(result.dnssec).toBe('Unsigned delegation');
        });
    });

    describe('Austrian format (.at)', () => {
        let result;

        beforeAll(() => {
            result = parseWhoisData(loadFixture('at-format.txt'), 'google.at');
        });

        it('should parse domain and registrar', () => {
            expect(result.domainName).toBe('google.at');
            expect(result.registrar).toContain('MarkMonitor');
        });

        it('should parse compact yyyymmdd changed date', () => {
            expect(result.lastModified).toBe('2024-03-04T13:11:29Z');
        });

        it('should parse nameservers', () => {
            expect(result.nameservers).toEqual(['ns1.google.com', 'ns2.google.com']);
        });
    });
});
