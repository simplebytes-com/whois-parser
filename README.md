# WHOIS Parser for ccTLDs

A comprehensive, battle-tested WHOIS parser with support for 169 country-code TLDs (ccTLDs). Built for [DomainDetails.com](https://domaindetails.com) by Simple Bytes LLC.

## Overview

This parser handles the messy reality of WHOIS data across different country registries. Unlike simple regex-based parsers, it handles:

- **Multiple date formats** - from `2005/05/30` (Japan) to `2007. 03. 02.` (South Korea) to natural language dates
- **International field names** - including Japanese (登録年月日), Korean, and other non-English formats
- **Various nameserver formats** - square brackets, multi-line sections, colon-separated with IPs
- **Slow WHOIS servers** - with configurable 30-second timeouts
- **Fallback parsing** - when domain names aren't explicitly listed in responses

## Success Rate

**52/169 ccTLDs fully supported** (31% perfect parsing)

- ✅ **Full parsing**: 52 ccTLDs with domain, dates, nameservers, registrar
- ⚠️ **Partial parsing**: 99 ccTLDs with some fields (often missing creation dates - registry limitation)
- ❌ **Failed**: 18 ccTLDs (server offline, timeout >30s, or connection refused)

### ✅ Fully Supported (52 ccTLDs)

`.ac` `.af` `.ag` `.bh` `.bi` `.bj` `.ci` `.cl` `.co` `.dm` `.do` `.ge` `.gg` `.gi` `.gl` `.hr` `.hu` `.ie` `.io` `.it` `.je` `.jp` `.kr` `.kz` `.la` `.ma` `.me` `.mk` `.mn` `.mx` `.my` `.nu` `.nz` `.pk` `.pt` `.ru` `.sc` `.se` `.sg` `.sh` `.sk` `.so` `.st` `.su` `.sx` `.sy` `.tc` `.td` `.tl` `.us` `.ve` `.ws` `.信息`

### ⏱️ Timeout Issues (8 ccTLDs)

These servers take longer than 30 seconds to respond:

`.dz` `.gp` `.mw` `.ng` `.pt` `.sb` `.tk` `.uy`

### 🚫 Connection Refused (4 ccTLDs)

These servers are offline or block automated queries:

`.bo` `.cf` `.hm` `.pf`

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
