rule AI_content_old_php_73b89187 : ai_generated high
{
    meta:
        description  = "This file is a full-featured PHP web shell disguised as a 'Tiny File Manager' allowing authenticated users to browse, upload, download, edit, delete, copy, rename, pack/unpack files and folders on the"
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / File Manager Backdoor"
        severity     = "High"
        source_file  = "wp-content/themes/Impreza/content-old.php"
        job_id       = "d2e949f9-375b-4d55-9175-348a8ba410d0"
        generated_at = "2026-04-20T17:41:57.973731+00:00"
        ai_generated = true

    strings:
        $s0 = "$2y$10$zxFoBM8VI6911GKXRjqKrOf8NSWIHAnjMW8/Hd14e.mIdBjITDwGS" nocase ascii wide
        $s1 = "http://php.net/manual/en/timezones.php" nocase ascii wide
        $s2 = "filemanager" nocase ascii wide
        $s3 = "Tiny File Manager" nocase ascii wide

    condition:
        any of them
}
