rule AI_rhinoceros_php_aa6fc3b2 : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a large encrypted PHP payload, acting as a stealth backdoor loader."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/rhinoceros.php"
        job_id       = "ce729ee3-0f73-4eda-aa80-4756f2494406"
        generated_at = "2026-04-20T17:41:58.277179+00:00"
        ai_generated = true

    strings:
        $s0 = "armadillo" nocase ascii wide

    condition:
        any of them
}
