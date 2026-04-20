rule AI_TransitionFlowModule_php_638b1466 : ai_generated critical
{
    meta:
        description  = "This file implements a backdoor with persistence mechanisms and obfuscation techniques."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Persistence"
        severity     = "Critical"
        source_file  = "woocommerce-bulk-widget/TransitionFlowModule.php"
        job_id       = "329f26ab-75e3-474a-b197-3bd7d90ed526"
        generated_at = "2026-04-20T17:41:57.980471+00:00"
        ai_generated = true

    strings:
        $s0 = "jsonmetafield" nocase ascii wide
        $s1 = "sub_valid_adm1" nocase ascii wide
        $s2 = "WP_Sys_Optimiser" nocase ascii wide

    condition:
        any of them
}
