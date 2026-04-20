rule AI_index_php_dd1e19c5 : ai_generated critical
{
    meta:
        description  = "This file downloads and executes remote PHP code, self-modifies to maintain persistence, and manipulates file permissions."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "index.php"
        job_id       = "50752ea5-03e7-452b-a9cb-9e088b5d212d"
        generated_at = "2026-04-20T17:41:57.945950+00:00"
        ai_generated = true

    strings:
        $s0 = "http://muchcost.top/library.php?T98ZB5R2Vja28udHh0ODQ.Qxnzeb" nocase ascii wide
        $s1 = "PD9waHAgJGdaV2JIeXJqTTFOQjk9bWljcm90aW1lKHRydWUpOyA/Pg==" nocase ascii wide

    condition:
        any of them
}
