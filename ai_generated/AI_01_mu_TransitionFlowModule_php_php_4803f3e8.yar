rule AI_01_mu_TransitionFlowModule_php_php_4803f3e8 : ai_generated critical
{
    meta:
        description  = "This file implements a stealthy backdoor that hides itself from plugin listings, creates a hidden admin user, persists code copies, and exfiltrates site data to a remote server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Persistence and Remote Data Exfiltration"
        severity     = "Critical"
        source_file  = "01-mu-TransitionFlowModule.php.php"
        job_id       = "35f972a5-6cbf-46f4-bd4e-7ca278d1e6ff"
        generated_at = "2026-04-20T17:41:58.008233+00:00"
        ai_generated = true

    strings:
        $s0 = "jsonmetafield" nocase ascii wide
        $s1 = "sub_valid_adm1" nocase ascii wide
        $s2 = "php://input" nocase ascii wide
        $s3 = "sys_[a-f0-9]{8}" nocase ascii wide

    condition:
        any of them
}
