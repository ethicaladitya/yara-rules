rule AI_wp_config_php_e32db9d6 : ai_generated critical
{
    meta:
        description  = "This wp-config.php file contains a critical backdoor allowing arbitrary PHP code execution via a custom HTTP header."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "Infected files/wp-config.php"
        job_id       = "17fa7444-de9b-4e02-8d08-360d4aced33e"
        generated_at = "2026-04-20T17:41:58.218938+00:00"
        ai_generated = true

    strings:
        $s0 = "dierentehuis" nocase ascii wide
        $s1 = "NXQQIfG9gIDZtkJ" nocase ascii wide
        $s2 = "127.0.0.1:3306" nocase ascii wide

    condition:
        any of them
}
