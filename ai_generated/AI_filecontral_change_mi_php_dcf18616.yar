rule AI_filecontral_change_mi_php_dcf18616 : ai_generated critical
{
    meta:
        description  = "This file implements a web-based file manager backdoor allowing arbitrary file upload, rename, delete, download, and directory listing via unsanitized GET/POST parameters."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Remote File Manager Backdoor"
        severity     = "Critical"
        source_file  = "filecontral-change-mi.php"
        job_id       = "a035f18d-1e5f-4fd5-aa91-a68dbbc8c12f"
        generated_at = "2026-04-20T17:41:57.879110+00:00"
        ai_generated = true

    strings:
        $s0 = "unzipfile" nocase ascii wide
        $s1 = "renamefile" nocase ascii wide
        $s2 = "content_file" nocase ascii wide
        $s3 = "newfilename" nocase ascii wide
        $s4 = "pathchoose" nocase ascii wide

    condition:
        any of them
}
