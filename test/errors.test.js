import { describe, it, expect } from 'vitest';
import {
    WhoisError,
    ConnectionError,
    TimeoutError,
    NoDataError,
    ValidationError,
    isValidDomain,
    isValidServer,
    whoisQuery,
} from '../whois-parser.js';

describe('Custom Error Classes', () => {
    describe('WhoisError', () => {
        it('should create error with code and server', () => {
            const error = new WhoisError('Test error', 'TEST_CODE', 'whois.test.com');
            expect(error.name).toBe('WhoisError');
            expect(error.message).toBe('Test error');
            expect(error.code).toBe('TEST_CODE');
            expect(error.server).toBe('whois.test.com');
        });

        it('should be instanceof Error', () => {
            const error = new WhoisError('Test', 'TEST');
            expect(error instanceof Error).toBe(true);
        });
    });

    describe('ConnectionError', () => {
        it('should have CONNECTION_ERROR code', () => {
            const error = new ConnectionError('Connection failed', 'whois.test.com');
            expect(error.name).toBe('ConnectionError');
            expect(error.code).toBe('CONNECTION_ERROR');
            expect(error.server).toBe('whois.test.com');
        });
    });

    describe('TimeoutError', () => {
        it('should have TIMEOUT code and timeoutMs', () => {
            const error = new TimeoutError('Timed out', 'whois.test.com', 30000);
            expect(error.name).toBe('TimeoutError');
            expect(error.code).toBe('TIMEOUT');
            expect(error.timeoutMs).toBe(30000);
        });
    });

    describe('NoDataError', () => {
        it('should have NO_DATA code', () => {
            const error = new NoDataError('No data', 'whois.test.com');
            expect(error.name).toBe('NoDataError');
            expect(error.code).toBe('NO_DATA');
        });
    });

    describe('ValidationError', () => {
        it('should have VALIDATION_ERROR code and field', () => {
            const error = new ValidationError('Invalid domain', 'domain');
            expect(error.name).toBe('ValidationError');
            expect(error.code).toBe('VALIDATION_ERROR');
            expect(error.field).toBe('domain');
        });
    });
});

describe('Input Validation', () => {
    describe('isValidDomain', () => {
        it('should accept valid domains', () => {
            expect(isValidDomain('example.com')).toBe(true);
            expect(isValidDomain('sub.example.com')).toBe(true);
            expect(isValidDomain('google.co.uk')).toBe(true);
            expect(isValidDomain('test-domain.org')).toBe(true);
        });

        it('should reject invalid domains', () => {
            expect(isValidDomain('')).toBe(false);
            expect(isValidDomain(null)).toBe(false);
            expect(isValidDomain(undefined)).toBe(false);
            expect(isValidDomain(123)).toBe(false);
            expect(isValidDomain('-invalid.com')).toBe(false);
            expect(isValidDomain('invalid-.com')).toBe(false);
        });
    });

    describe('isValidServer', () => {
        it('should accept valid servers', () => {
            expect(isValidServer('whois.nic.uk')).toBe(true);
            expect(isValidServer('whois.jprs.jp')).toBe(true);
            expect(isValidServer('192.168.1.1')).toBe(true);
        });

        it('should reject invalid servers', () => {
            expect(isValidServer('')).toBe(false);
            expect(isValidServer(null)).toBe(false);
            expect(isValidServer(undefined)).toBe(false);
        });
    });
});

describe('whoisQuery validation', () => {
    it('should reject null domain', async () => {
        await expect(whoisQuery(null, 'whois.test.com')).rejects.toThrow(ValidationError);
    });

    it('should reject empty domain', async () => {
        await expect(whoisQuery('', 'whois.test.com')).rejects.toThrow(ValidationError);
    });

    it('should reject null server', async () => {
        await expect(whoisQuery('example.com', null)).rejects.toThrow(ValidationError);
    });

    it('should reject empty server', async () => {
        await expect(whoisQuery('example.com', '')).rejects.toThrow(ValidationError);
    });

    it('should include field name in ValidationError', async () => {
        try {
            await whoisQuery(null, 'whois.test.com');
        } catch (error) {
            expect(error.field).toBe('domain');
        }
    });
});
