rule AI_filecontral_change_mi_php_4731340c : ai_generated critical
{
    meta:
        description  = "This file implements a web-based file manager backdoor allowing arbitrary file upload, rename, delete, and download operations without authentication."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "File Manager Backdoor"
        severity     = "Critical"
        source_file  = "filecontral-change-mi.php"
        job_id       = "3f590e70-2704-4a8d-84ed-f4dc4de4a820"
        generated_at = "2026-04-20T17:41:58.389130+00:00"
        ai_generated = true

    strings:
        $s0 = "renamefile" nocase ascii wide
        $s1 = "editfile" nocase ascii wide
        $s2 = "newfilename" nocase ascii wide

    condition:
        any of them
}
