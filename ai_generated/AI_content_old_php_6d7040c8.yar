rule AI_content_old_php_6d7040c8 : ai_generated critical
{
    meta:
        description  = "This file is a full-featured PHP web shell (Tiny File Manager) allowing authenticated remote file management and upload on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Backdoor"
        severity     = "Critical"
        source_file  = "wp-content/themes/Impreza/content-old.php"
        job_id       = "0eab15f0-e2a5-4914-ace6-885916cb895d"
        generated_at = "2026-04-20T17:41:57.900075+00:00"
        ai_generated = true

    strings:
        $s0 = "$2y$10$zxFoBM8VI6911GKXRjqKrOf8NSWIHAnjMW8/Hd14e.mIdBjITDwGS" nocase ascii wide
        $s1 = "http://php.net/manual/en/timezones.php" nocase ascii wide
        $s2 = "filemanager" nocase ascii wide

    condition:
        any of them
}
