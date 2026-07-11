/**
 * Field Name Mappings for WHOIS Parsing
 *
 * RFC 7485 documented extreme variation in field names across registries.
 * For example, "Name Server" has 63 different labels across registries.
 *
 * This module centralizes all field name aliases and is consumed directly by
 * whois-parser.js. Keys are matched case-insensitively against normalized
 * response keys (brackets and dot-leaders stripped, whitespace collapsed),
 * so aliases only need to appear once regardless of casing.
 *
 * IMPORTANT: Order matters — earlier aliases win when a response contains
 * several matching fields.
 */

/**
 * Domain name field aliases
 */
export const DOMAIN_NAME_FIELDS = [
    'Domain Name',
    'Domain',
    '도메인이름', // Korean
];

/**
 * Registrar field aliases
 */
export const REGISTRAR_FIELDS = [
    'Registrar',
    'Sponsoring Registrar',
    'Registrar Organization', // .it "Registrar" section > "Organization:"
    'Registrar Name',
    'Authorized Agency',
    '등록대행자', // Korean
];

/**
 * Registrar URL field aliases
 */
export const REGISTRAR_URL_FIELDS = [
    'Registrar URL', // includes .uk "Registrar:" section > "URL:" via section prefixing
];

/**
 * Registrar IANA ID field aliases
 */
export const REGISTRAR_IANA_ID_FIELDS = [
    'Registrar IANA ID',
];

/**
 * Registrar WHOIS server field aliases (referral target for thin registries)
 */
export const REGISTRAR_WHOIS_SERVER_FIELDS = [
    'Registrar WHOIS Server',
    'Whois Server',
];

/**
 * Abuse contact email field aliases
 */
export const ABUSE_EMAIL_FIELDS = [
    'Registrar Abuse Contact Email',
    'Abuse Contact Email',
    'abuse-mailbox',
];

/**
 * Registrant field aliases
 */
export const REGISTRANT_FIELDS = [
    'Registrant Name',
    'Registrant',
    'Registrant Organization',
    'Registrant Contact Name',
    'org',
    'Organization',
    'owner',
    'holder',
    'holder name',
    '등록인', // Korean
    'name', // .fi holder block — keep last: only used when nothing better matched
];

/**
 * Registrant country field aliases
 */
export const REGISTRANT_COUNTRY_FIELDS = [
    'Registrant Country',
    'country',
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
    'BC',
];

/**
 * Creation date field aliases
 */
export const CREATION_DATE_FIELDS = [
    'Creation Date',
    'Created Date',
    'Registered Date',
    'Registration Date',
    'Registration Time', // .cn
    'Created On',
    'Registered on', // .uk
    'created',
    'Registered',
    'Domain Record Created',
    '登録年月日', // Japanese
    '등록일', // Korean
];

/**
 * Expiration date field aliases
 */
export const EXPIRATION_DATE_FIELDS = [
    'Registry Expiry Date',
    'Expiration Date',
    'Expiry Date', // .uk "Expiry date"
    'Expire Date', // .it
    'Expires On',
    'Expires',
    'Expiry',
    'Expiration Time', // .cn
    'paid-till', // .ru
    'renewal date',
    'Valid Until',
    'expire',
    'expire-date',
    '有効期限', // Japanese
    '사용 종료일', // Korean
];

/**
 * Last updated date field aliases
 */
export const UPDATED_DATE_FIELDS = [
    'Updated Date',
    'Last Updated Date',
    'Last updated', // .uk
    'Last Modified',
    'Last Update', // .it
    'Changed', // .de, .at, .ee
    'Modified',
    'last-update',
    '최근 정보 변경일', // Korean
    '最終更新', // Japanese
];

/**
 * Name server field aliases
 */
export const NAMESERVER_FIELDS = [
    'Name Server',
    'Nameserver',
    'Nameservers', // .it bare section header
    'Name Servers', // .uk/.gg "Name servers:" section
    'nserver', // .de, .ru, .ee
    'Host Name', // .kr
    'Hostname', // .dk
    'Domain nameservers', // .nl
    '호스트이름', // Korean
];

/**
 * Status field aliases
 */
export const STATUS_FIELDS = [
    'Domain Status',
    'Status',
    'state', // .ru
    'Registration status', // .uk
    '状態', // Japanese
];

/**
 * DNSSEC field aliases
 */
export const DNSSEC_FIELDS = [
    'DNSSEC',
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
        registrarUrl: REGISTRAR_URL_FIELDS,
        registrarIanaId: REGISTRAR_IANA_ID_FIELDS,
        registrarWhoisServer: REGISTRAR_WHOIS_SERVER_FIELDS,
        abuseEmail: ABUSE_EMAIL_FIELDS,
        registrant: REGISTRANT_FIELDS,
        registrantCountry: REGISTRANT_COUNTRY_FIELDS,
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
    'registrarUrl',
    'registrarIanaId',
    'registrarWhoisServer',
    'abuseEmail',
    'registrant',
    'registrantCountry',
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
