import { describe, it, expect } from 'vitest';
import {
    normalizeStatus,
    normalizeStatuses,
    isActive,
    hasTransferLock,
    getStatusDescription,
} from '../status-codes.js';

describe('normalizeStatus', () => {
    it('should normalize common "ok" variations', () => {
        expect(normalizeStatus('ok')).toBe('ok');
        expect(normalizeStatus('active')).toBe('ok');
        expect(normalizeStatus('Active')).toBe('ok');
        expect(normalizeStatus('ACTIVE')).toBe('ok');
        expect(normalizeStatus('registered')).toBe('ok');
        expect(normalizeStatus('Registered')).toBe('ok');
    });

    it('should normalize Russian status formats', () => {
        expect(normalizeStatus('REGISTERED, DELEGATED')).toBe('ok');
        expect(normalizeStatus('REGISTERED, DELEGATED, VERIFIED')).toBe('ok');
        expect(normalizeStatus('REGISTERED, NOT DELEGATED')).toBe('inactive');
    });

    it('should normalize Guernsey/Jersey status', () => {
        expect(normalizeStatus('Registered until cancelled')).toBe('ok');
    });

    it('should normalize lock status codes', () => {
        expect(normalizeStatus('locked')).toBe('clientTransferProhibited');
        expect(normalizeStatus('DomainTransferLocked')).toBe('clientTransferProhibited');
        expect(normalizeStatus('AgentChangeLocked')).toBe('clientUpdateProhibited');
    });

    it('should handle EPP status with URLs', () => {
        expect(normalizeStatus('clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited')).toBe('clientDeleteProhibited');
        expect(normalizeStatus('clientTransferProhibited https://icann.org/epp#clientTransferProhibited')).toBe('clientTransferProhibited');
    });

    it('should preserve unknown status codes', () => {
        expect(normalizeStatus('customStatus')).toBe('customStatus');
        expect(normalizeStatus('unknownCode')).toBe('unknownCode');
    });

    it('should handle null/empty input', () => {
        expect(normalizeStatus(null)).toBeNull();
        expect(normalizeStatus('')).toBeNull(); // Empty string is falsy
    });
});

describe('normalizeStatuses', () => {
    it('should normalize an array of statuses', () => {
        const result = normalizeStatuses(['active', 'locked', 'ok']);
        expect(result).toContain('ok');
        expect(result).toContain('clientTransferProhibited');
    });

    it('should handle empty array', () => {
        expect(normalizeStatuses([])).toEqual([]);
    });

    it('should handle non-array input', () => {
        expect(normalizeStatuses(null)).toEqual([]);
        expect(normalizeStatuses(undefined)).toEqual([]);
    });
});

describe('isActive', () => {
    it('should return true for active statuses', () => {
        expect(isActive('ok')).toBe(true);
        expect(isActive('active')).toBe(true);
        expect(isActive(['ok', 'clientTransferProhibited'])).toBe(true);
    });

    it('should return false for inactive statuses', () => {
        expect(isActive('inactive')).toBe(false);
        expect(isActive('pendingDelete')).toBe(false);
        expect(isActive(['serverHold'])).toBe(false);
    });

    it('should return true for domains with only restrictions', () => {
        // Domain with restrictions but no hold/delete is still active
        expect(isActive(['clientTransferProhibited', 'clientDeleteProhibited'])).toBe(true);
    });
});

describe('hasTransferLock', () => {
    it('should return true for transfer-locked domains', () => {
        expect(hasTransferLock('clientTransferProhibited')).toBe(true);
        expect(hasTransferLock(['ok', 'clientTransferProhibited'])).toBe(true);
        expect(hasTransferLock('locked')).toBe(true);
    });

    it('should return false for unlocked domains', () => {
        expect(hasTransferLock('ok')).toBe(false);
        expect(hasTransferLock(['ok', 'clientDeleteProhibited'])).toBe(false);
    });
});

describe('getStatusDescription', () => {
    it('should return descriptions for known codes', () => {
        expect(getStatusDescription('ok')).toBe('Domain is registered and active');
        expect(getStatusDescription('clientTransferProhibited')).toContain('transfer protection');
    });

    it('should return the code itself for unknown codes', () => {
        expect(getStatusDescription('unknownCode')).toBe('unknownCode');
    });
});
