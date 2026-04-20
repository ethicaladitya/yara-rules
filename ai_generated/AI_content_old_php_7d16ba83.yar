rule AI_content_old_php_7d16ba83 : ai_generated high
{
    meta:
        description  = "This file is a full-featured PHP web shell disguised as 'Tiny File Manager' allowing authenticated users to browse, upload, download, edit, delete, rename, copy, and unpack files on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / File Manager Backdoor"
        severity     = "High"
        source_file  = "wp-content/themes/Impreza/content-old.php"
        job_id       = "038cce44-9db2-41df-a113-5f5aa8e0d6c5"
        generated_at = "2026-04-20T17:41:57.938002+00:00"
        ai_generated = true

    strings:
        $s0 = "$2y$10$zxFoBM8VI6911GKXRjqKrOf8NSWIHAnjMW8/Hd14e.mIdBjITDwGS" nocase ascii wide
        $s1 = "http://php.net/manual/en/timezones.php" nocase ascii wide
        $s2 = "Tiny File Manager" nocase ascii wide

    condition:
        any of them
}
