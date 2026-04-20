rule AI_rhinoceros_php_845e3d30 : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a hidden PHP payload using a custom base64 variant and XOR key, enabling stealthy backdoor functionality."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/rhinoceros.php"
        job_id       = "983e0681-4c62-48f4-8a46-e63ee78b32a1"
        generated_at = "2026-04-20T17:41:58.154802+00:00"
        ai_generated = true

    strings:
        $s0 = "armadillo" nocase ascii wide
        $s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" nocase ascii wide

    condition:
        any of them
}
