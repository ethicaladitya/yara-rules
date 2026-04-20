rule AI_rhinoceros_php_d7a13b11 : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a hidden PHP payload from an obfuscated base64-like string using a custom XOR cipher, enabling stealthy backdoor functionality."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/rhinoceros.php"
        job_id       = "6315a2a4-ab56-48d4-ac5e-aaccabc0f973"
        generated_at = "2026-04-20T17:41:58.000797+00:00"
        ai_generated = true

    strings:
        $s0 = "armadillo" nocase ascii wide

    condition:
        any of them
}
