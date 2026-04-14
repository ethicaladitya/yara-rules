# WordPress & PHP Malware YARA Rules

> A curated collection of YARA rules for detecting malware, backdoors, webshells, and malicious PHP code in WordPress installations and PHP applications.

[![License: Mixed Open Source](https://img.shields.io/badge/License-Open%20Source-blue.svg)](#license)
[![Rules](https://img.shields.io/badge/Rules-38%2C000%2B-red.svg)](#rule-sets)
[![WordPress](https://img.shields.io/badge/Platform-WordPress-21759B.svg)](#)

---

## Why This Repository

WordPress powers over 43% of the web, making it the most targeted CMS for malware injection.  
Attackers routinely compromise sites through vulnerable plugins, themes, and file upload endpoints — dropping **PHP backdoors, webshells, SEO spam injectors, and credential stealers** that are difficult to detect with standard antivirus tools.

This repository aggregates the most comprehensive open-source YARA rule sets specifically tuned for **PHP and WordPress malware detection**, making them easy to use in any scanning pipeline.

---

## What These Rules Detect

| Category | Examples |
|---|---|
| **PHP Backdoors** | eval/base64 chains, gzinflate payloads, ROT13 obfuscation, hex-encoded execution |
| **Webshells** | c99, r57, WSO, FilesMan, b374k, and 3,000+ custom variants |
| **Remote Code Execution** | `system()`, `exec()`, `passthru()`, `shell_exec()` with user input |
| **WordPress-Specific Malware** | Rogue admin injection, `wp_options` backdoors, cron injection, plugin hiding |
| **File Droppers** | `file_put_contents` to `.php` files, `move_uploaded_file` webshell uploads |
| **Credential Theft** | `wp-config.php` readers, `curl` exfiltration, `getenv()` of WP secrets |
| **Hidden Iframes & JS Injection** | `document.write(unescape())`, inline `eval()` script tags |
| **SEO Spam Injectors** | Hidden link injection, redirect manipulation via `wp_redirect` |
| **Obfuscated Code** | Multi-layer encoding chains, homoglyph variable names, string rebuilders |
| **C2 Beacons** | Cookie-keyed alive checks, hardcoded C2 domains, base64 data exfiltration |

---

## Rule Sets

| Directory | File | Source | License | Coverage |
|---|---|---|---|---|
| `php/` | `rfxn.yara` | [RFxN](https://www.rfxn.com/) | Personal/non-commercial free | ~38,000 PHP malware signatures |
| `php/` | `php-malware-finder.yar` | [jvoisin/php-malware-finder](https://github.com/jvoisin/php-malware-finder) | MIT | 15 semantic PHP heuristic rules |
| `php/` | `whitelist.yar` | [jvoisin/php-malware-finder](https://github.com/jvoisin/php-malware-finder) | MIT | Required whitelist for php-malware-finder |
| `webshells/` | `thor-webshells.yar` | [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | Apache 2.0 | 3,286+ webshell patterns |
| `ai_generated/` | `*.yar` | This repo | MIT | Auto-generated from confirmed malware detections |

**Total coverage: 40,000+ malware signatures and heuristics.**

---

## Quick Start

### Prerequisites

```bash
# Ubuntu / Debian
apt install yara

# macOS
brew install yara

# Python binding (for scripted scanning)
pip install yara-python
```

### Scan a WordPress Installation

```bash
# Clone this repository
git clone https://github.com/ethicaladitya/yara-rules.git
cd yara-rules

# Scan all PHP files in a WordPress directory
yara php/rfxn.yara /var/www/html/wordpress/ -r --tag php

# Check for known webshells
yara webshells/thor-webshells.yar /var/www/html/wordpress/ -r

# Run the php-malware-finder semantic rules
yara php/php-malware-finder.yar /var/www/html/wordpress/ -r
```

### Scan with Python

```python
import yara
from pathlib import Path

rules_dir = Path("yara-rules")

# Load all rule sets
rule_sets = [
    yara.compile(str(rules_dir / "php" / "rfxn.yara")),
    yara.compile(str(rules_dir / "php" / "php-malware-finder.yar")),
    yara.compile(str(rules_dir / "webshells" / "thor-webshells.yar")),
]

# Scan a file
target = "/var/www/html/wp-content/uploads/suspicious.php"
for rules in rule_sets:
    matches = rules.match(target)
    for match in matches:
        print(f"[{match.rule}] Matched: {target}")
```

### Scan an Entire WordPress Site (Bash)

```bash
#!/usr/bin/env bash
# scan-wordpress.sh — scan all PHP/JS files and report hits

RULES_DIR="./yara-rules"
SITE_DIR="${1:-/var/www/html}"
REPORT="scan-report-$(date +%Y%m%d-%H%M%S).txt"

echo "Scanning: $SITE_DIR"
echo "Report:   $REPORT"

find "$SITE_DIR" -type f \( -name "*.php" -o -name "*.js" -o -name "*.phtml" \) | while read -r file; do
  for rulefile in "$RULES_DIR"/php/*.yar "$RULES_DIR"/php/*.yara \
                  "$RULES_DIR"/webshells/*.yar \
                  "$RULES_DIR"/ai_generated/*.yar; do
    [[ -f "$rulefile" ]] || continue
    result=$(yara "$rulefile" "$file" 2>/dev/null)
    [[ -n "$result" ]] && echo "$result" >> "$REPORT"
  done
done

echo ""
echo "Scan complete. Hits: $(wc -l < "$REPORT" 2>/dev/null || echo 0)"
```

---

## Repository Structure

```
yara-rules/
├── README.md
├── LICENSE
├── php/
│   ├── rfxn.yara                 # ~38,000 PHP malware signatures (RFxN)
│   ├── php-malware-finder.yar    # Semantic PHP heuristics (jvoisin, MIT)
│   └── whitelist.yar             # Required whitelist for php-malware-finder
├── webshells/
│   └── thor-webshells.yar        # 3,286+ webshell patterns (Neo23x0, Apache 2.0)
└── ai_generated/
    ├── README.md                 # Describes auto-generated rules
    └── *.yar                     # Rules generated from confirmed detections
```

---

## Keeping Rules Up to Date

Community rule sets should be refreshed regularly as new malware variants emerge.

```bash
# Refresh all community rules
curl -fsSL https://www.rfxn.com/downloads/rfxn.yara -o php/rfxn.yara
curl -fsSL https://raw.githubusercontent.com/jvoisin/php-malware-finder/master/data/php.yar -o php/php-malware-finder.yar
curl -fsSL https://raw.githubusercontent.com/jvoisin/php-malware-finder/master/data/whitelist.yar -o php/whitelist.yar
curl -fsSL https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/thor-webshells.yar -o webshells/thor-webshells.yar
```

Or use the included update script (if applicable to your toolchain).

---

## AI-Generated Rules (`ai_generated/`)

The `ai_generated/` directory contains YARA rules derived from confirmed malware samples.  
Each rule is named with a hash of the originating file to prevent collisions and includes metadata:

```yara
rule AI_shell_php_a1b2c3d4 : ai_generated critical
{
    meta:
        description  = "PHP Obfuscated Backdoor — eval/base64 + system() chain"
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote Code Execution Shell"
        severity     = "Critical"
        generated_at = "2026-04-14T10:00:00+00:00"
        ai_generated = true

    strings:
        $s0 = "eval(base64_decode" nocase ascii wide
        $s1 = "system($_POST" nocase ascii wide

    condition:
        any of them
}
```

Rules in this directory are retracted (removed) when the triggering file is later assessed as a false positive.

---

## Integration Examples

### WP-CLI Plugin

```bash
# Scan WordPress uploads directory (common malware drop location)
yara php/rfxn.yara wp-content/uploads/ -r 2>/dev/null | grep -v "^$"
```

### cPanel / WHM Hook

Add to your virus scanner pipeline or integrate with Imunify360 / ConfigServer Exploit Scanner as a supplementary rule source.

### CI/CD Pipeline (GitHub Actions)

```yaml
- name: YARA Malware Scan
  run: |
    sudo apt-get install -y yara
    git clone https://github.com/ethicaladitya/yara-rules.git /tmp/yara-rules
    find ./wp-content -name "*.php" -exec yara /tmp/yara-rules/php/rfxn.yara {} \; | tee scan-results.txt
    [ ! -s scan-results.txt ] || (echo "Malware detected!" && exit 1)
```

---

## Contributing

Contributions are welcome — especially new rules for:

- Emerging WordPress malware families
- Plugin-specific backdoor patterns
- Theme injection techniques
- New obfuscation methods

**To contribute:**
1. Fork this repository
2. Add your `.yar` rule file to the appropriate directory
3. Include a `meta:` block with `description`, `severity`, and `reference`
4. Test that it compiles: `yara --compile-rules your-rule.yar /dev/null`
5. Open a pull request

---

## Common WordPress Malware Locations

When scanning WordPress sites, prioritise these directories:

```
wp-content/uploads/          # No PHP should ever exist here
wp-content/plugins/          # Vulnerable or injected plugins
wp-content/themes/           # Theme file injection
wp-content/mu-plugins/       # Must-use plugins (often used for persistence)
wp-config.php                # Credential theft target
.htaccess                    # Redirect injection
wp-includes/                 # Core file replacement
```

---

## Related Resources

- [YARA Documentation](https://yara.readthedocs.io/)
- [WordPress Security Codex](https://developer.wordpress.org/apis/security/)
- [Sucuri SiteCheck](https://sitecheck.sucuri.net/) — free remote scanner
- [WPScan Vulnerability Database](https://wpscan.com/wordpress-security-scanner)
- [VirusTotal YARA Hunting](https://www.virustotal.com/)

---

## License

| Component | License |
|---|---|
| `php/rfxn.yara` | Personal/non-commercial use — see [rfxn.com](https://www.rfxn.com/) |
| `php/php-malware-finder.yar`, `php/whitelist.yar` | [MIT](https://github.com/jvoisin/php-malware-finder/blob/master/LICENSE) |
| `webshells/thor-webshells.yar` | [Apache 2.0](https://github.com/Neo23x0/signature-base/blob/master/LICENSE) |
| `ai_generated/*.yar` | [MIT](LICENSE) |
| Scripts and documentation | [MIT](LICENSE) |

---

## Disclaimer

These rules are provided for **defensive security purposes only** — malware detection, incident response, and security research.  
Always obtain proper authorisation before scanning systems you do not own.
