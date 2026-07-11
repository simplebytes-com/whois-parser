/**
 * EPP Status Code Normalization
 *
 * Different registries use different status code formats and names.
 * This module normalizes them to standard EPP status codes.
 *
 * @see https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en
 */

/**
 * Standard EPP status codes
 */
export const EPP_STATUS_CODES = {
    // OK statuses
    ok: 'ok',
    active: 'ok',
    ACTIVE: 'ok',
    Active: 'ok',
    registered: 'ok',
    REGISTERED: 'ok',
    Registered: 'ok',

    // Client-side restrictions
    clientDeleteProhibited: 'clientDeleteProhibited',
    clientHold: 'clientHold',
    clientRenewProhibited: 'clientRenewProhibited',
    clientTransferProhibited: 'clientTransferProhibited',
    clientUpdateProhibited: 'clientUpdateProhibited',

    // Server-side restrictions
    serverDeleteProhibited: 'serverDeleteProhibited',
    serverHold: 'serverHold',
    serverRenewProhibited: 'serverRenewProhibited',
    serverTransferProhibited: 'serverTransferProhibited',
    serverUpdateProhibited: 'serverUpdateProhibited',

    // Transfer states
    pendingCreate: 'pendingCreate',
    pendingDelete: 'pendingDelete',
    pendingRenew: 'pendingRenew',
    pendingRestore: 'pendingRestore',
    pendingTransfer: 'pendingTransfer',
    pendingUpdate: 'pendingUpdate',

    // Redemption
    redemptionPeriod: 'redemptionPeriod',
    pendingRestore: 'pendingRestore',

    // Other
    inactive: 'inactive',
    addPeriod: 'addPeriod',
    autoRenewPeriod: 'autoRenewPeriod',
    renewPeriod: 'renewPeriod',
    transferPeriod: 'transferPeriod',
};

/**
 * Registry-specific status mappings
 */
const STATUS_MAPPINGS = {
    // Common variations
    'ok': 'ok',
    'active': 'ok',
    'Active': 'ok',
    'ACTIVE': 'ok',
    'registered': 'ok',
    'Registered': 'ok',
    'REGISTERED': 'ok',

    // Russian format
    'REGISTERED, DELEGATED': 'ok',
    'REGISTERED, DELEGATED, VERIFIED': 'ok',
    'REGISTERED, DELEGATED, UNVERIFIED': 'ok',
    'REGISTERED, NOT DELEGATED': 'inactive',

    // UK format
    'Registered until expiry date.': 'ok',
    'Registration request being processed.': 'pendingCreate',

    // Guernsey/Jersey format
    'Registered until cancelled': 'ok',

    // German format
    'connect': 'ok',
    'free': 'inactive',

    // Delete/inactive variations
    'inactive': 'inactive',
    'Inactive': 'inactive',
    'INACTIVE': 'inactive',
    'pendingDelete': 'pendingDelete',
    'PendingDelete': 'pendingDelete',
    'PENDING DELETE': 'pendingDelete',

    // Transfer variations
    'pendingTransfer': 'pendingTransfer',
    'PendingTransfer': 'pendingTransfer',
    'PENDING TRANSFER': 'pendingTransfer',

    // Lock variations (map to clientTransferProhibited)
    'locked': 'clientTransferProhibited',
    'Locked': 'clientTransferProhibited',
    'LOCKED': 'clientTransferProhibited',
    'DomainTransferLocked': 'clientTransferProhibited',
    'AgentChangeLocked': 'clientUpdateProhibited',
};

/**
 * Normalize a single status code
 * @param {string} status - The raw status code
 * @returns {string} Normalized EPP status code
 */
export function normalizeStatus(status) {
    if (!status) return null;

    // Trim whitespace
    const trimmed = status.trim();

    // Check direct mapping first
    if (STATUS_MAPPINGS[trimmed]) {
        return STATUS_MAPPINGS[trimmed];
    }

    // Check if it's an EPP status code with URL (e.g., "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited")
    const eppMatch = trimmed.match(/^(\w+)\s+https?:\/\//i);
    if (eppMatch) {
        const code = eppMatch[1];
        // Check if it's a known EPP code
        if (EPP_STATUS_CODES[code]) {
            return EPP_STATUS_CODES[code];
        }
        // Return as-is if it looks like a valid EPP code
        if (/^(client|server)[A-Z]/.test(code)) {
            return code;
        }
    }

    // Check for case-insensitive match in EPP codes
    const lowerStatus = trimmed.toLowerCase();
    for (const [key, value] of Object.entries(EPP_STATUS_CODES)) {
        if (key.toLowerCase() === lowerStatus) {
            return value;
        }
    }

    // Return original if no mapping found
    return trimmed;
}

/**
 * Normalize an array of status codes
 * @param {string[]} statuses - Array of raw status codes
 * @returns {string[]} Array of normalized EPP status codes
 */
export function normalizeStatuses(statuses) {
    if (!Array.isArray(statuses)) return [];
    return statuses.map(normalizeStatus).filter(Boolean);
}

/**
 * Check if a status indicates the domain is active/registered
 * @param {string|string[]} status - Status code(s) to check
 * @returns {boolean} True if domain is active
 */
export function isActive(status) {
    const statuses = Array.isArray(status) ? status : [status];
    const normalized = normalizeStatuses(statuses);

    // Domain is active if it has 'ok' status or no hold/delete statuses
    if (normalized.includes('ok')) return true;

    const inactiveStatuses = ['inactive', 'pendingDelete', 'serverHold', 'clientHold'];
    return !normalized.some(s => inactiveStatuses.includes(s));
}

/**
 * Check if a domain has transfer restrictions
 * @param {string|string[]} status - Status code(s) to check
 * @returns {boolean} True if domain has transfer restrictions
 */
export function hasTransferLock(status) {
    const statuses = Array.isArray(status) ? status : [status];
    const normalized = normalizeStatuses(statuses);

    const transferLocks = [
        'clientTransferProhibited',
        'serverTransferProhibited',
        'pendingTransfer',
    ];
    return normalized.some(s => transferLocks.includes(s));
}

/**
 * Get a human-readable description for a status code
 * @param {string} status - EPP status code
 * @returns {string} Human-readable description
 */
export function getStatusDescription(status) {
    const descriptions = {
        ok: 'Domain is registered and active',
        inactive: 'Domain is not active',
        clientDeleteProhibited: 'Client has requested delete protection',
        clientHold: 'Domain is on hold by client request',
        clientRenewProhibited: 'Client has requested renewal protection',
        clientTransferProhibited: 'Client has requested transfer protection',
        clientUpdateProhibited: 'Client has requested update protection',
        serverDeleteProhibited: 'Server has set delete protection',
        serverHold: 'Domain is on hold by server',
        serverRenewProhibited: 'Server has set renewal protection',
        serverTransferProhibited: 'Server has set transfer protection',
        serverUpdateProhibited: 'Server has set update protection',
        pendingCreate: 'Domain registration is pending',
        pendingDelete: 'Domain deletion is pending',
        pendingRenew: 'Domain renewal is pending',
        pendingRestore: 'Domain restore is pending',
        pendingTransfer: 'Domain transfer is pending',
        pendingUpdate: 'Domain update is pending',
        redemptionPeriod: 'Domain is in redemption period',
        addPeriod: 'Domain is in add grace period',
        autoRenewPeriod: 'Domain is in auto-renew period',
        renewPeriod: 'Domain is in renewal period',
        transferPeriod: 'Domain is in transfer period',
    };

    return descriptions[status] || status;
}
