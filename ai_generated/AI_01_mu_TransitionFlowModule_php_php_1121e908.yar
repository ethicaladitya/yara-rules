rule AI_01_mu_TransitionFlowModule_php_php_1121e908 : ai_generated critical
{
    meta:
        description  = "The file contains a backdoor that creates hidden admin users, modifies plugin lists, and stores malicious payloads."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Persistence"
        severity     = "Critical"
        source_file  = "01-mu-TransitionFlowModule.php.php"
        job_id       = "1c309bdb-5437-484a-8802-894d82b2ca55"
        generated_at = "2026-04-20T17:41:57.960507+00:00"
        ai_generated = true

    strings:
        $s0 = "https://github.com/coreflux/transition-flow-module" nocase ascii wide
        $s1 = "jsonmetafield" nocase ascii wide
        $s2 = "sub_valid_adm1" nocase ascii wide
        $s3 = "noreply@<site-domain>" nocase ascii wide

    condition:
        any of them
}
