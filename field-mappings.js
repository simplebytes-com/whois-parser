/**
 * Field Name Mappings for WHOIS Parsing
 *
 * RFC 7485 documented extreme variation in field names across registries.
 * For example, "Name Server" has 63 different labels across registries.
 *
 * This module centralizes all field name aliases to make parsing more robust
 * and easier to extend.
 */

/**
 * Domain name field aliases
 */
export const DOMAIN_NAME_FIELDS = [
    'Domain Name',
    'Domain',
    'domain name',
    'domain',
    'DOMAIN NAME',
    'DOMAIN',
];

/**
 * Registrar field aliases
 */
export const REGISTRAR_FIELDS = [
    'Registrar',
    'REGISTRAR',
    'registrar',
    'Sponsoring Registrar',
    'Authorized Agency',
    '등록대행자', // Korean
];

/**
 * Registrant field aliases
 */
export const REGISTRANT_FIELDS = [
    'Registrant',
    'Registrant Name',
    'Registrant Organization',
    'registrant',
    'REGISTRANT',
    'org',
    'Organization',
    '등록인', // Korean
];

/**
 * Admin contact field aliases
 */
export const ADMIN_CONTACT_FIELDS = [
    'Admin Name',
    'Admin Organization',
    'Administrative Contact',
    'Admin Contact',
    'admin',
    'ADMIN',
    'AC',
    '책임자', // Korean
];

/**
 * Tech contact field aliases
 */
export const TECH_CONTACT_FIELDS = [
    'Tech Name',
    'Tech Organization',
    'Technical Contact',
    'Tech Contact',
    'tech',
    'TECH',
    'TC',
];

/**
 * Billing contact field aliases
 */
export const BILLING_CONTACT_FIELDS = [
    'Billing Name',
    'Billing Organization',
    'Billing Contact',
    'billing',
    'BILLING',
    'BC',
];

/**
 * Creation date field aliases
 */
export const CREATION_DATE_FIELDS = [
    'Creation Date',
    'Created Date',
    'Created',
    'created',
    'Created On',
    'Registration Date',
    'Registered Date',
    'Registered',
    'Registered on',
    '登録年月日', // Japanese
    '등록일', // Korean
];

/**
 * Expiration date field aliases
 */
export const EXPIRATION_DATE_FIELDS = [
    'Registry Expiry Date',
    'Expiration Date',
    'Expiry Date',
    'Expire Date',
    'Expires',
    'Expires On',
    'paid-till',
    'renewal date',
    '有効期限', // Japanese
    '사용 종료일', // Korean
];

/**
 * Last updated date field aliases
 */
export const UPDATED_DATE_FIELDS = [
    'Updated Date',
    'Last Updated Date',
    'Last Modified',
    'last modified',
    'Last Update',
    'Changed',
    'changed',
    'Modified',
    '최근 정보 변경일', // Korean
    '最終更新', // Japanese
];

/**
 * Name server field aliases
 */
export const NAMESERVER_FIELDS = [
    'Name Server',
    'Nameserver',
    'nameserver',
    'nameservers',
    'Name Servers',
    'nserver',
    'Nserver',
    'Host Name',
    'DNS',
    '호스트이름', // Korean
];

/**
 * Status field aliases
 */
export const STATUS_FIELDS = [
    'Domain Status',
    'Status',
    'status',
    'state',
    'State',
    'Registration status',
    '状態', // Japanese
    '정보공개여부', // Korean
];

/**
 * DNSSEC field aliases
 */
export const DNSSEC_FIELDS = [
    'DNSSEC',
    'dnssec',
    'Signed',
    'DS Rdata',
    'Signing Key',
];

/**
 * Get all field aliases for a category
 * @param {string} category - The field category
 * @returns {string[]} Array of field aliases
 */
export function getFieldAliases(category) {
    const mappings = {
        domain: DOMAIN_NAME_FIELDS,
        registrar: REGISTRAR_FIELDS,
        registrant: REGISTRANT_FIELDS,
        admin: ADMIN_CONTACT_FIELDS,
        tech: TECH_CONTACT_FIELDS,
        billing: BILLING_CONTACT_FIELDS,
        created: CREATION_DATE_FIELDS,
        expires: EXPIRATION_DATE_FIELDS,
        updated: UPDATED_DATE_FIELDS,
        nameserver: NAMESERVER_FIELDS,
        status: STATUS_FIELDS,
        dnssec: DNSSEC_FIELDS,
    };
    return mappings[category] || [];
}

/**
 * All field categories
 */
export const FIELD_CATEGORIES = [
    'domain',
    'registrar',
    'registrant',
    'admin',
    'tech',
    'billing',
    'created',
    'expires',
    'updated',
    'nameserver',
    'status',
    'dnssec',
];
