rule AI_01_mu_TransitionFlowModule_php_php_4f81b2ef : ai_generated critical
{
    meta:
        description  = "This file implements a stealthy backdoor that hides itself from plugin listings, creates a hidden admin user, persists by copying itself, and exfiltrates site data via AJAX requests."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with persistence and data exfiltration"
        severity     = "Critical"
        source_file  = "01-mu-TransitionFlowModule.php.php"
        job_id       = "51591602-3d0a-4eb6-b7c7-0f6bc56cfef4"
        generated_at = "2026-04-20T17:41:57.987193+00:00"
        ai_generated = true

    strings:
        $s0 = "https://github.com/coreflux/transition-flow-module" nocase ascii wide
        $s1 = "https://github.com/coreflux" nocase ascii wide
        $s2 = "php://input" nocase ascii wide
        $s3 = "KGFzaW5nYmFzZTY0IGRhdGEp (obfuscated in code, decoded to a URL or endpoint)" nocase ascii wide
        $s4 = "sys_<8 char md5>" nocase ascii wide
        $s5 = "['jsonmetafield', 'sub_valid_adm1']" nocase ascii wide

    condition:
        any of them
}
