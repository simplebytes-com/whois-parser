Last updated: 2025-10-30

# WHOIS Parser for ccTLDs

A comprehensive, battle-tested WHOIS parser with support for 169 country-code TLDs (ccTLDs) and 1,260+ TLDs total. Built for [DomainDetails.com](https://domaindetails.com) by Simple Bytes LLC.

## WHOIS Server Dictionary

This repository includes `whois_dict.json` with WHOIS servers for **1,260+ TLDs** (updated from IANA Root Zone Database).

## Overview

This parser handles the messy reality of WHOIS data across different country registries. Unlike simple regex-based parsers, it handles:

- **Multiple date formats** - from `2005/05/30` (Japan) to `2007. 03. 02.` (South Korea) to natural language dates
- **International field names** - including Japanese (登録年月日), Korean, and other non-English formats
- **Various nameserver formats** - square brackets, multi-line sections, colon-separated with IPs
- **Slow WHOIS servers** - with configurable 30-second timeouts
- **Fallback parsing** - when domain names aren't explicitly listed in responses

## 📊 Complete Breakdown of All 169 ccTLDs

### ✅ FULLY WORKING (52 - 31%)

All fields parsed: domain, dates, nameservers, registrar, status
→ **Ready for production use**

`.ac` `.af` `.ag` `.bh` `.bi` `.bj` `.ci` `.cl` `.co` `.dm` `.do` `.ge` `.gg` `.gi` `.gl` `.hr` `.hu` `.ie` `.io` `.it` `.je` `.jp` `.kr` `.kz` `.la` `.ma` `.me` `.mk` `.mn` `.mx` `.my` `.nu` `.nz` `.pk` `.pt` `.ru` `.sc` `.se` `.sg` `.sh` `.sk` `.so` `.st` `.su` `.sx` `.sy` `.tc` `.td` `.tl` `.us` `.ve` `.ws` `.信息`

### ⚠️ PARTIAL DATA (99 - 59%)

Missing some fields (usually creation date due to registry policy)
→ **Still useful but incomplete**

**Major TLDs with partial data:**
- 🇩🇪 `.de` (Germany) - No creation date (registry policy)
- 🇫🇷 `.fr` (France) - No creation date
- 🇬🇧 `.uk` (United Kingdom) - No creation date
- 🇨🇳 `.cn` (China) - No creation date
- 🇦🇺 `.au` (Australia) - No creation date
- 🇦🇹 `.at` (Austria) - No creation date
- 🇧🇪 `.be` (Belgium) - No creation date
- 🇩🇰 `.dk` (Denmark) - No creation date
- 🇳🇱 `.nl` (Netherlands) - Partial data
- 🇵🇱 `.pl` (Poland) - Partial data
- 🇪🇸 `.es` (Spain) - Authorization required
- 🇨🇭 `.ch` (Switzerland) - Blocks automated queries
- 🇮🇳 `.in` (India) - Partial data
- 🇧🇷 `.br` (Brazil) - Partial data
- 🇨🇦 `.ca` (Canada) - Partial data
- 🇪🇺 `.eu` (European Union) - No creation date

### ❌ CANNOT QUERY (18 - 11%)

Server infrastructure issues, cannot be fixed by parser

**Breakdown by error type:**
- ⏱️ **8 Timeouts** (>30s): `.dz` `.gp` `.mw` `.ng` `.pt` `.sb` `.tk` `.uy`
- 🚫 **4 Refused**: `.bo` `.cf` `.hm` `.pf`
- 🌐 **2 DNS Error**: `.iq` `.mz`
- 📭 **1 No Data**: `.bn`
- 🔌 **3 Connection Reset**: `.tr` and others

### 💡 Key Insights

1. **Parser Success**: 151/169 (89%) return SOME data
2. **Full Success**: 52/169 (31%) return ALL data
3. **Infrastructure Issues**: 18/169 (11%) cannot be queried at all

The 99 "partial data" ccTLDs are often **policy limitations, not bugs**:
- European registries hiding creation dates for GDPR compliance
- Some registries require authorization for automated queries
- Privacy-focused registries redacting sensitive information

### 🌟 Highlighted Format Support

- 🇯🇵 **Japan (.jp)** - Square bracket format with Japanese fields
- 🇰🇷 **South Korea (.kr)** - Korean/English dual format with wide spacing
- 🇬🇬 **Guernsey (.gg)**, 🇯🇪 **Jersey (.je)** - Natural language dates
- 🇷🇺 **Russia (.ru)** - Cyrillic field names with IP-annotated nameservers
- 🇮🇹 **Italy (.it)** - Multi-line nameserver sections
- 🇩🇪 **Germany (.de)** - Nserver format

## Features

- **Date Normalization**: Converts all date formats to ISO 8601 (`YYYY-MM-DDTHH:MM:SSZ`)
- **Multi-Format Parsing**: Handles colon-separated, square bracket, and multi-line formats
- **Domain Fallback**: Uses input domain when WHOIS doesn't return it explicitly
- **Robust Error Handling**: Graceful fallbacks for missing fields
- **Comprehensive Testing**: 169 ccTLD test suite included

## WHOIS Server Dictionary Maintenance

The `whois_dict.json` file is automatically synced with the [IANA Root Zone Database](https://www.iana.org/domains/root/db).

### Sync from IANA

```bash
# Install dependencies first
npm install

# Sync WHOIS servers from IANA (updates whois_dict.json)
npm run sync-iana

# Preview changes without saving
npm run sync-iana:dry-run
```

The sync script:
- Fetches complete TLD list from `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` (1,439 TLDs)
- Gets WHOIS server for each TLD from individual IANA pages
- Updates `whois_dict.json` with sorted results
- Creates dated backups before making changes
- Updates README with last sync date

### Automated Updates

A GitHub Action automatically syncs the dictionary:
- **On every push** to main/master branch
- **Weekly on Sunday at 2 AM UTC** to catch IANA updates
- **Manual trigger** via GitHub Actions UI

When changes are detected, the action:
- Updates `whois_dict.json` with new/changed TLD servers
- Updates README with current date
- Creates dated backups
- Commits and pushes changes automatically

See `.github/workflows/sync-iana.yml` for details.

## Installation

```bash
npm install
```

## Usage

```javascript
import { parseWhoisData, whoisQuery } from './whois-parser.js';

// Query a WHOIS server
const whoisText = await whoisQuery('google.jp', 'whois.jprs.jp');

// Parse the response
const parsed = parseWhoisData(whoisText, 'google.jp');

console.log(parsed);
// {
//   domainName: 'GOOGLE.JP',
//   registrar: 'Google LLC',
//   creationDate: '2005-05-30T00:00:00Z',
//   expirationDate: '2026-05-31T00:00:00Z',
//   nameservers: ['ns1.google.com', 'ns2.google.com', ...],
//   registrant: 'Google LLC',
//   status: ['Active', 'DomainTransferLocked', 'AgentChangeLocked'],
//   dnssec: null,
//   lastModified: '2025-06-01T01:05:04.000Z'
// }
```

## Testing

Run the comprehensive test suite:

```bash
# Quick test (19 popular ccTLDs, ~30 seconds)
npm run test:sample

# Full test (all 169 ccTLDs, ~5 minutes)
npm test
```

### Test Output

```
[1/169] Testing .jp (google.jp)...
  ✅ OK (domain: GOOGLE.JP, created: 2005-05-30T00:00:00Z)

[2/169] Testing .kr (naver.kr)...
  ✅ OK (domain: naver.kr, created: 2007-03-02T00:00:00Z)

========== SUMMARY ==========
✅ Successful: 52/169
⚠️  Parsing Issues: 99/169
❌ Failed: 18/169
```

## Supported Formats

### Date Formats

```
2005/05/30              → 2005-05-30T00:00:00Z  (.jp)
2007. 03. 02.           → 2007-03-02T00:00:00Z  (.kr)
30th April 2003         → 2003-04-30T00:00:00Z  (.gg, .je)
30th April each year    → 2026-04-30T00:00:00Z  (recurring)
2005-02-14T20:35:14.765Z → 2005-02-14T20:35:14.765Z (standard)
```

### Field Formats

**Square Brackets** (.jp):
```
[Domain Name]                   GOOGLE.JP
[Name Server]                   ns1.google.com
[登録年月日]                    2005/05/30
```

**Colon-Separated** (most ccTLDs):
```
Domain Name: google.kr
Registered Date: 2007. 03. 02.
Host Name: ns1.google.com
```

**Dotted Format** (.ax, .kz):
```
domain...............: test.ax
```

**Multi-Line** (.gg, .je, .it):
```
Name servers:
    ns1.google.com
    ns2.google.com
```

## Known Limitations

### Missing Creation Dates

Some registries (.de, .be, .dk, .at, .im) don't publicly expose creation dates via WHOIS. This is a registry policy, not a parser limitation.

### Server Timeouts

6 ccTLDs still timeout even at 30 seconds: .dz, .gp, .mw, .ng, .sb, .tk

### Offline Servers

Some WHOIS servers are permanently offline or block automated queries: .bo, .cf, .ch, .es, .hm, .iq, .mz, .pf, .tr

## Contributing

Found a ccTLD that doesn't parse correctly? We'd love a PR!

1. Run the test suite to identify the failing TLD
2. Query the WHOIS server manually: `whois -h <server> <domain>`
3. Identify the unique format patterns
4. Update `parseWhoisData()` with new patterns
5. Re-run tests to verify

## Credits

- **Built by**: [DomainDetails.com](https://domaindetails.com) team
- **Special thanks**: [@synozeer](https://x.com/synozeer) for spotting .gg and other ccTLD issues
- **Powered by**: Claude Code for the comprehensive parser refactor

## License

MIT License - feel free to use in your projects!

## Related Projects

- [whois](https://www.npmjs.com/package/whois) - Node.js WHOIS client
- [whoiser](https://www.npmjs.com/package/whoiser) - Alternative WHOIS parser
- [DomainDetails.com](https://domaindetails.com) - Free domain lookup tool using this parser

---

**Found this useful?** Give us a star ⭐ at [github.com/simplebytes-com/whois-parser](https://github.com/simplebytes-com/whois-parser) and check out [DomainDetails.com](https://domaindetails.com)!
