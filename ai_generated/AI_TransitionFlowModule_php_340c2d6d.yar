rule AI_TransitionFlowModule_php_340c2d6d : ai_generated critical
{
    meta:
        description  = "This file creates a backdoor with hidden admin creation and persistent file integrity checks."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Persistence"
        severity     = "Critical"
        source_file  = "woocommerce-bulk-widget/TransitionFlowModule.php"
        job_id       = "e9d6808e-b1bb-4ffe-b2d0-cffef952d1da"
        generated_at = "2026-04-20T17:41:58.355941+00:00"
        ai_generated = true

    strings:
        $s0 = "https://github.com/coreflux/transition-flow-module" nocase ascii wide
        $s1 = "jsonmetafield" nocase ascii wide
        $s2 = "sub_valid_adm1" nocase ascii wide
        $s3 = "noreply@<site-domain>" nocase ascii wide

    condition:
        any of them
}
