import { describe, it, expect } from 'vitest';
import { parseWhoisData, isDomainAvailable, isRateLimited } from '../whois-parser.js';
import * as fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const loadFixture = (name) =>
    fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

describe('isDomainAvailable', () => {
    const availableFixtures = [
        ['available-com.txt', 'Verisign "No match for"'],
        ['available-de.txt', 'DENIC "Status: free"'],
        ['available-nl.txt', 'SIDN "is free"'],
        ['available-uk.txt', 'Nominet "No match for"'],
        ['available-jp.txt', 'JPRS "No match!!"'],
    ];

    it.each(availableFixtures)('should detect %s as available', (fixture) => {
        expect(isDomainAvailable(loadFixture(fixture))).toBe(true);
    });

    const registeredFixtures = [
        'io-format.txt',
        'uk-format.txt',
        'de-format.txt',
        'it-format.txt',
        'nl-format.txt',
        'fi-format.txt',
        'ee-format.txt',
        'dk-format.txt',
        'at-format.txt',
        'jp-format.txt',
        'kr-format.txt',
        'ru-format.txt',
        'gg-format.txt',
    ];

    it.each(registeredFixtures)('should NOT flag registered domain fixture %s', (fixture) => {
        expect(isDomainAvailable(loadFixture(fixture))).toBe(false);
    });

    it('should not treat rate-limit responses as available', () => {
        expect(isDomainAvailable(loadFixture('ratelimit-generic.txt'))).toBe(false);
        expect(isDomainAvailable(loadFixture('ratelimit-it.txt'))).toBe(false);
    });

    it('should not trip on remark text mentioning "not found" mid-line', () => {
        const text = 'Domain Name: EXAMPLE.COM\nRemark: previous record was not found in archive\nCreation Date: 2001-01-01';
        expect(isDomainAvailable(text)).toBe(false);
    });

    it('should handle empty/invalid input', () => {
        expect(isDomainAvailable('')).toBe(false);
        expect(isDomainAvailable(null)).toBe(false);
        expect(isDomainAvailable(undefined)).toBe(false);
    });
});

describe('isRateLimited', () => {
    it('should detect quota/rate-limit responses', () => {
        expect(isRateLimited(loadFixture('ratelimit-generic.txt'))).toBe(true);
        expect(isRateLimited(loadFixture('ratelimit-it.txt'))).toBe(true);
        expect(isRateLimited('WHOIS LIMIT EXCEEDED - SEE WWW.PIR.ORG/WHOIS FOR DETAILS')).toBe(true);
        expect(isRateLimited('% Excessive querying, grace period of 24h')).toBe(true);
        expect(isRateLimited('Your IP has been blocked due to excessive use')).toBe(true);
    });

    it('should detect access-policy denials (.ch, .es)', () => {
        expect(isRateLimited('Requests of this client are not permitted. Please use https://www.nic.ch/whois/ for queries.')).toBe(true);
        expect(isRateLimited('Access will only be enabled for  IP addresses  authorised  by Red.es.')).toBe(true);
    });

    it('should not flag normal responses', () => {
        expect(isRateLimited(loadFixture('io-format.txt'))).toBe(false);
        expect(isRateLimited(loadFixture('uk-format.txt'))).toBe(false);
        expect(isRateLimited('')).toBe(false);
        expect(isRateLimited(null)).toBe(false);
    });
});

describe('parseWhoisData availability flags', () => {
    it('should set isAvailable on available-domain responses', () => {
        const result = parseWhoisData(loadFixture('available-com.txt'), 'thisdomaindoesnotexist-xyz.com');
        expect(result.isAvailable).toBe(true);
        expect(result.isRateLimited).toBe(false);
        expect(result.creationDate).toBeNull();
        expect(result.nameservers).toBeNull();
    });

    it('should set isRateLimited on throttled responses', () => {
        const result = parseWhoisData(loadFixture('ratelimit-generic.txt'), 'example.it');
        expect(result.isRateLimited).toBe(true);
        expect(result.isAvailable).toBe(false);
    });

    it('should not set isAvailable when domain data is present', () => {
        // Even if a pattern matched remark text, real record data wins
        const text = loadFixture('de-format.txt') + '\nRemark: nothing found in legacy database\n';
        const result = parseWhoisData(text, 'google.de');
        expect(result.isAvailable).toBe(false);
    });
});
