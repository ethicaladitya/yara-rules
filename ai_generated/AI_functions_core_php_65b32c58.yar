rule AI_functions_core_php_65b32c58 : ai_generated critical
{
    meta:
        description  = "This file contains a heavily obfuscated PHP backdoor that executes hidden code via multiple layers of encoded payloads."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "PHP Obfuscated Backdoor"
        severity     = "Critical"
        source_file  = "wp-content/themes/Impreza/functions-core.php"
        job_id       = "a5393911-09e9-4699-8864-7ccccb35cc8d"
        generated_at = "2026-04-20T17:41:58.112184+00:00"
        ai_generated = true

    strings:
        $s0 = "eval(base64_decode(gzinflate(...)))" nocase ascii wide

    condition:
        any of them
}
