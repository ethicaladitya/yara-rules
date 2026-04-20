rule AI_TransitionFlowModule_php_8e85e255 : ai_generated critical
{
    meta:
        description  = "This file creates a hidden admin user and stores malicious payloads in WordPress options."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor and Unauthorized Access"
        severity     = "Critical"
        source_file  = "woocommerce-bulk-widget/TransitionFlowModule.php"
        job_id       = "ca0a14b1-0b7f-44e1-a88e-bf9182999831"
        generated_at = "2026-04-20T17:41:57.908039+00:00"
        ai_generated = true

    strings:
        $s0 = "jsonmetafield" nocase ascii wide
        $s1 = "sub_valid_adm1" nocase ascii wide
        $s2 = "php://input" nocase ascii wide
        $s3 = "some_secret_key" nocase ascii wide

    condition:
        any of them
}
