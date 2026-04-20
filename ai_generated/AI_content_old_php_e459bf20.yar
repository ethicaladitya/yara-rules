rule AI_content_old_php_e459bf20 : ai_generated critical
{
    meta:
        description  = "This file is a full-featured PHP web shell (Tiny File Manager) allowing authenticated remote file management and arbitrary file upload on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Backdoor"
        severity     = "Critical"
        source_file  = "wp-content/themes/Impreza/content-old.php"
        job_id       = "a5393911-09e9-4699-8864-7ccccb35cc8d"
        generated_at = "2026-04-20T17:41:58.122228+00:00"
        ai_generated = true

    strings:
        $s0 = "$2y$10$zxFoBM8VI6911GKXRjqKrOf8NSWIHAnjMW8/Hd14e.mIdBjITDwGS" nocase ascii wide
        $s1 = "http://php.net/manual/en/timezones.php" nocase ascii wide
        $s2 = "filemanager" nocase ascii wide

    condition:
        any of them
}
