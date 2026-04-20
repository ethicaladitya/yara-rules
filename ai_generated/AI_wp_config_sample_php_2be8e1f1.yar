rule AI_wp_config_sample_php_2be8e1f1 : ai_generated critical
{
    meta:
        description  = "This file contains a heavily obfuscated PHP backdoor that executes arbitrary code passed via a GET parameter, enabling remote code execution."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Obfuscated Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "wp-config-sample.php"
        job_id       = "d02d2d89-cf45-4798-bcc3-ea43fb4cc18b"
        generated_at = "2026-04-20T17:41:58.311649+00:00"
        ai_generated = true

    strings:
        $s0 = "dnswklnq" nocase ascii wide

    condition:
        any of them
}
