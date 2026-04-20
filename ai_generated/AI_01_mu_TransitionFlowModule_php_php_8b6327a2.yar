rule AI_01_mu_TransitionFlowModule_php_php_8b6327a2 : ai_generated critical
{
    meta:
        description  = "This file creates a backdoor with hidden admin creation and persistent file integrity checks."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Persistence"
        severity     = "Critical"
        source_file  = "01-mu-TransitionFlowModule.php.php"
        job_id       = "3e9992ef-a9b3-41fa-acae-8366f073564c"
        generated_at = "2026-04-20T17:41:58.396760+00:00"
        ai_generated = true

    strings:
        $s0 = "jsonmetafield" nocase ascii wide
        $s1 = "sub_valid_adm1" nocase ascii wide
        $s2 = "aHR0cHM6Ly9tYWxpY2lvdXN1cmwuY29t" nocase ascii wide

    condition:
        any of them
}
