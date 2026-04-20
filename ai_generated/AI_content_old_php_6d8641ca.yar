rule AI_content_old_php_6d8641ca : ai_generated high
{
    meta:
        description  = "This file is a full-featured PHP web shell disguised as a Tiny File Manager, allowing authenticated users to browse, upload, modify, delete, and execute files on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / File Manager Backdoor"
        severity     = "High"
        source_file  = "wp-content/themes/Impreza/content-old.php"
        job_id       = "67d4e99b-aef5-4d4e-9cb4-2367e27b8f49"
        generated_at = "2026-04-20T17:41:57.914901+00:00"
        ai_generated = true

    strings:
        $s0 = "$2y$10$zxFoBM8VI6911GKXRjqKrOf8NSWIHAnjMW8/Hd14e.mIdBjITDwGS" nocase ascii wide
        $s1 = "filemanager" nocase ascii wide
        $s2 = "https://tinyfilemanager.github.io/" nocase ascii wide

    condition:
        any of them
}
