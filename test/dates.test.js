import { describe, it, expect } from 'vitest';
import { normalizeDateString } from '../whois-parser.js';

describe('normalizeDateString', () => {
    it('should return null for empty input', () => {
        expect(normalizeDateString(null)).toBeNull();
        expect(normalizeDateString('')).toBeNull();
    });

    it('should preserve full ISO 8601 timestamps', () => {
        expect(normalizeDateString('2024-11-06T00:49:34Z')).toBe('2024-11-06T00:49:34Z');
        expect(normalizeDateString('1997-09-23T09:45:07Z')).toBe('1997-09-23T09:45:07Z');
    });

    it('should preserve plain ISO dates without inventing a time', () => {
        expect(normalizeDateString('2025-12-11')).toBe('2025-12-11');
    });

    it('should normalize ISO datetimes with a space separator (.it, .cn)', () => {
        expect(normalizeDateString('1999-12-10 00:00:00')).toBe('1999-12-10T00:00:00Z');
        expect(normalizeDateString('2003-03-17 12:20:05')).toBe('2003-03-17T12:20:05Z');
    });

    it('should normalize short timezone offsets (.ua style)', () => {
        expect(normalizeDateString('2002-12-04 00:00:00+02')).toBe('2002-12-04T00:00:00+02:00');
        expect(normalizeDateString('2010-07-04 06:26:24 +03:00')).toBe('2010-07-04T06:26:24+03:00');
    });

    it('should normalize yyyy/mm/dd (.jp)', () => {
        expect(normalizeDateString('2005/05/30')).toBe('2005-05-30T00:00:00Z');
        expect(normalizeDateString('2005/5/3')).toBe('2005-05-03T00:00:00Z');
    });

    it('should normalize .jp datetimes with (JST) timezone hint', () => {
        expect(normalizeDateString('2025/06/01 01:05:04 (JST)')).toBe('2025-06-01T01:05:04+09:00');
    });

    it('should normalize yyyy. mm. dd. (.kr)', () => {
        expect(normalizeDateString('2007. 03. 02.')).toBe('2007-03-02T00:00:00Z');
        expect(normalizeDateString('2007. 3. 2.')).toBe('2007-03-02T00:00:00Z');
    });

    it('should normalize yyyy.mm.dd with time (.pl)', () => {
        expect(normalizeDateString('2002.09.19 13:00:00')).toBe('2002-09-19T13:00:00Z');
    });

    it('should normalize d.m.yyyy (.fi)', () => {
        expect(normalizeDateString('12.6.2006')).toBe('2006-06-12T00:00:00Z');
        expect(normalizeDateString('4.7.2026')).toBe('2026-07-04T00:00:00Z');
    });

    it('should normalize dd-Mon-yyyy (.uk, .ie)', () => {
        expect(normalizeDateString('01-Dec-2023')).toBe('2023-12-01T00:00:00Z');
        expect(normalizeDateString('1-Jan-2020')).toBe('2020-01-01T00:00:00Z');
        expect(normalizeDateString('13-Dec-2025')).toBe('2025-12-13T00:00:00Z');
    });

    it('should normalize compact yyyymmdd with time (.at)', () => {
        expect(normalizeDateString('20240304 13:11:29')).toBe('2024-03-04T13:11:29Z');
    });

    it('should normalize ordinal natural-language dates (.gg, .je)', () => {
        expect(normalizeDateString('30th April 2003')).toBe('2003-04-30T00:00:00Z');
        expect(normalizeDateString('1st January 2020')).toBe('2020-01-01T00:00:00Z');
    });

    it('should return unrecognized formats unchanged', () => {
        expect(normalizeDateString('before Aug-1996')).toBe('before Aug-1996');
        expect(normalizeDateString('not a date')).toBe('not a date');
    });
});
