rule AI_TransitionFlowModule_php_9e125889 : ai_generated critical
{
    meta:
        description  = "The file contains a backdoor that creates hidden admin users and persists itself through file and database manipulations."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor and Persistence"
        severity     = "Critical"
        source_file  = "woocommerce-bulk-widget/TransitionFlowModule.php"
        job_id       = "b1c518ab-4e9e-4439-8e47-0e2ac2dde77a"
        generated_at = "2026-04-20T17:41:58.140368+00:00"
        ai_generated = true

    strings:
        $s0 = "php://input" nocase ascii wide
        $s1 = "jsonmetafield" nocase ascii wide
        $s2 = "sub_valid_adm1" nocase ascii wide
        $s3 = "noreply@<site-domain>" nocase ascii wide

    condition:
        any of them
}
