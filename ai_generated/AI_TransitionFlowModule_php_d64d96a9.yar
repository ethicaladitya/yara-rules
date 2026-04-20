rule AI_TransitionFlowModule_php_d64d96a9 : ai_generated critical
{
    meta:
        description  = "This file implements a stealthy backdoor that hides itself from plugin lists, creates a hidden admin user, stores and exfiltrates encoded data, and appends its code to other PHP files for persistence."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with persistence and remote exfiltration"
        severity     = "Critical"
        source_file  = "woocommerce-bulk-widget/TransitionFlowModule.php"
        job_id       = "5e557c14-5eee-4917-8e64-0758519ca529"
        generated_at = "2026-04-20T17:41:58.132506+00:00"
        ai_generated = true

    strings:
        $s0 = "jsonmetafield" nocase ascii wide
        $s1 = "sub_valid_adm1" nocase ascii wide
        $s2 = "sys_[8 hex chars]" nocase ascii wide
        $s3 = "https://input" nocase ascii wide
        $s4 = "mu-plugins/01-mu-[basename].php" nocase ascii wide

    condition:
        any of them
}
