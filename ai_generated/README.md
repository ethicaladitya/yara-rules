# AI-Generated YARA Rules

This directory contains YARA rules automatically derived from confirmed malware detections.

## How Rules Are Added

When a file is confirmed malicious through deep analysis, a YARA rule is generated from its
Indicators of Compromise (IOCs) — domains, URLs, cookie keys, backdoor parameters, and
code-level string patterns extracted from the verdict breakdown.

Each rule:
- Targets **specific strings** found in the malicious file (domains, payload snippets, parameter names)
- Uses `nocase ascii wide` matching to catch encoding variations
- Includes full metadata: verdict, category, severity, source file reference, generation timestamp
- Is compile-validated before being written to disk

## How Rules Are Retracted

When a file is later assessed as a **false positive** (LIKELY CLEAN verdict), its corresponding
rule is automatically deleted from this directory and marked as retracted in `manifest.json`.
This prevents legitimate code from being permanently flagged.

## manifest.json

The `manifest.json` file in this directory is the authoritative catalogue of all generated rules,
including retracted ones. It tracks:

```json
{
  "rules": {
    "AI_shell_php_a1b2c3d4": {
      "rule_name": "AI_shell_php_a1b2c3d4",
      "file_path": "AI_shell_php_a1b2c3d4.yar",
      "source_file": "wp-content/uploads/shell.php",
      "job_id": "job_abc123",
      "verdict": "CONFIRMED MALICIOUS",
      "severity": "Critical",
      "category": "Remote Code Execution Shell",
      "generated_at": "2026-04-14T10:00:00+00:00",
      "retracted": false
    }
  }
}
```

## Rule Naming

Rules are named `AI_<filename>_<8-char-hash>.yar` where the hash is derived from
`job_id:file_path`. This guarantees uniqueness even when the same filename appears across
different scans.

## License

Rules in this directory are released under the MIT License.
