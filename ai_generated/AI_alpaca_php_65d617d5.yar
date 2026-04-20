rule AI_alpaca_php_65d617d5 : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a hidden PHP payload from an obfuscated base64-like string using a custom XOR cipher."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/alpaca.php"
        job_id       = "17fa7444-de9b-4e02-8d08-360d4aced33e"
        generated_at = "2026-04-20T17:41:58.237216+00:00"
        ai_generated = true

    strings:
        $s0 = "orangutan" nocase ascii wide

    condition:
        any of them
}
