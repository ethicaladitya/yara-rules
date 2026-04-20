rule AI_TransitionFlowModule_php_5912e7c7 : ai_generated critical
{
    meta:
        description  = "The file contains a backdoor that creates hidden admin users and persists through file and database manipulations."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Persistence"
        severity     = "Critical"
        source_file  = "woocommerce-bulk-widget/TransitionFlowModule.php"
        job_id       = "0e64af34-8681-4d9e-bd62-30df7025c9cf"
        generated_at = "2026-04-20T17:41:58.209784+00:00"
        ai_generated = true

    strings:
        $s0 = "https://github.com/coreflux/transition-flow-module" nocase ascii wide
        $s1 = "aHR0cHM6Ly9tYWxpY2lvdXMuZXhhbXBsZS5jb20=" nocase ascii wide
        $s2 = "jsonmetafield" nocase ascii wide

    condition:
        any of them
}
