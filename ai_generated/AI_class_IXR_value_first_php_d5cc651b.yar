rule AI_class_IXR_value_first_php_d5cc651b : ai_generated critical
{
    meta:
        description  = "This file implements a fully functional web shell allowing remote file management including upload, delete, rename, move, copy, and directory removal."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Remote File Manager"
        severity     = "Critical"
        source_file  = "wp-includes/IXR/class-IXR-value-first.php"
        job_id       = "d02d2d89-cf45-4798-bcc3-ea43fb4cc18b"
        generated_at = "2026-04-20T17:41:58.328307+00:00"
        ai_generated = true

    strings:
        $s0 = "upload_file" nocase ascii wide

    condition:
        any of them
}
