rule AI_index_php_76edc16d : ai_generated critical
{
    meta:
        description  = "This file fetches and executes code from an external server, maintaining persistence through self-modification."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote Code Execution"
        severity     = "Critical"
        source_file  = "index.php"
        job_id       = "8b9ffaa3-233c-4cb0-bc5a-b8d75f444796"
        generated_at = "2026-04-20T17:41:58.404215+00:00"
        ai_generated = true

    strings:
        $s0 = "http://muchcost.top/library.php?T98ZB5R2Vja28udHh0ODQ.Qxnzeb" nocase ascii wide

    condition:
        any of them
}
