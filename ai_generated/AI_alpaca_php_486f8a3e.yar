rule AI_alpaca_php_486f8a3e : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a hidden PHP payload from an encrypted string, acting as a stealth backdoor loader."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/alpaca.php"
        job_id       = "983e0681-4c62-48f4-8a46-e63ee78b32a1"
        generated_at = "2026-04-20T17:41:58.162626+00:00"
        ai_generated = true

    strings:
        $s0 = "orangutan" nocase ascii wide

    condition:
        any of them
}
