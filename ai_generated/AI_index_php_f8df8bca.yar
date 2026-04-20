rule AI_index_php_f8df8bca : ai_generated critical
{
    meta:
        description  = "This file downloads and executes remote PHP code, self-modifies to maintain persistence, and uses obfuscation to evade detection."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "index.php"
        job_id       = "c5984573-a8cd-45b9-8924-bf08ab931b74"
        generated_at = "2026-04-20T17:41:58.303631+00:00"
        ai_generated = true

    strings:
        $s0 = "http://muchcost.top/library.php?T98ZB5R2Vja28udHh0ODQ.Qxnzeb" nocase ascii wide
        $s1 = "__FILE__ (self-modifying index.php)" nocase ascii wide
        $s2 = "chmod __DIR__ 0755, chmod __FILE__ 0644" nocase ascii wide

    condition:
        any of them
}
