rule AI_index_php_29bfe8e1 : ai_generated critical
{
    meta:
        description  = "This file downloads and executes remote PHP code, modifies itself to maintain persistence, and uses obfuscation to evade detection."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "index.php"
        job_id       = "ec98e61f-6746-42ff-b978-2f3b168ef38a"
        generated_at = "2026-04-20T17:41:58.201845+00:00"
        ai_generated = true

    strings:
        $s0 = "http://muchcost.top/library.php?T98ZB5R2Vja28udHh0ODQ.Qxnzeb" nocase ascii wide
        $s1 = "__FILE__ (index.php)" nocase ascii wide
        $s2 = "chmod directory 0755, chmod file 0644" nocase ascii wide

    condition:
        any of them
}
