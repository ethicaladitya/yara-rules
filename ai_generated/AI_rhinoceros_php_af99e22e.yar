rule AI_rhinoceros_php_af99e22e : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a large encrypted PHP payload, acting as a stealth backdoor loader."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/rhinoceros.php"
        job_id       = "13439f2d-1cfe-4e9f-9777-b5886a2ca44c"
        generated_at = "2026-04-20T17:41:57.967101+00:00"
        ai_generated = true

    strings:
        $s0 = "armadillo" nocase ascii wide

    condition:
        any of them
}
