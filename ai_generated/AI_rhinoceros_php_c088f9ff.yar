rule AI_rhinoceros_php_c088f9ff : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a hidden PHP payload, acting as a stealth backdoor loader."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/rhinoceros.php"
        job_id       = "1829df11-97e0-4748-a872-3b3049d8bf5a"
        generated_at = "2026-04-20T17:41:57.892079+00:00"
        ai_generated = true

    strings:
        $s0 = "armadillo" nocase ascii wide

    condition:
        any of them
}
