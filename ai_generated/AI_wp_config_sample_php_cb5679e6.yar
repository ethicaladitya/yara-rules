rule AI_wp_config_sample_php_cb5679e6 : ai_generated critical
{
    meta:
        description  = "This file contains a heavily obfuscated PHP backdoor that executes arbitrary code passed via a GET parameter."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Obfuscated Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "wp-config-sample.php"
        job_id       = "2b4b9641-90dd-4e49-8f0c-c19a6aeb6b7f"
        generated_at = "2026-04-20T17:41:58.373607+00:00"
        ai_generated = true

    strings:
        $s0 = "geteqhmz" nocase ascii wide

    condition:
        any of them
}
