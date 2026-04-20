rule AI_wp_config_php_d53ffb68 : ai_generated critical
{
    meta:
        description  = "This wp-config.php file contains a critical backdoor allowing arbitrary PHP code execution via a custom HTTP header."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "Infected files/wp-config.php"
        job_id       = "983e0681-4c62-48f4-8a46-e63ee78b32a1"
        generated_at = "2026-04-20T17:41:58.147899+00:00"
        ai_generated = true

    strings:
        $s0 = "NXQQIfG9gIDZtkJ" nocase ascii wide
        $s1 = "dierentehuis" nocase ascii wide
        $s2 = "127.0.0.1:3306" nocase ascii wide

    condition:
        any of them
}
