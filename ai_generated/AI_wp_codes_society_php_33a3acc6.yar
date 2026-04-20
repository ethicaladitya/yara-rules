rule AI_wp_codes_society_php_33a3acc6 : ai_generated critical
{
    meta:
        description  = "This file hides the plugin from the admin panel and includes a mechanism for remote code execution."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Plugin Concealment and Remote Code Execution"
        severity     = "Critical"
        source_file  = "wp-codes-society/wp-codes-society.php"
        job_id       = "8751b478-edd2-4fa0-b639-bd36d6a2cb12"
        generated_at = "2026-04-20T17:41:57.993965+00:00"
        ai_generated = true

    strings:
        $s0 = "http://wordpress.org/#" nocase ascii wide
        $s1 = "wp-codes-society/wp-codes-society.php" nocase ascii wide

    condition:
        any of them
}
