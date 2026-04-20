rule AI_upgrade_meta_php_e2a0713f : ai_generated critical
{
    meta:
        description  = "This file implements a fully functional web shell allowing arbitrary file upload, deletion, renaming, moving, copying, and directory removal on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Remote File Manager"
        severity     = "Critical"
        source_file  = "wp-admin/upgrade-meta.php"
        job_id       = "d02d2d89-cf45-4798-bcc3-ea43fb4cc18b"
        generated_at = "2026-04-20T17:41:58.336772+00:00"
        ai_generated = true

    strings:
        $s0 = "wp-admin/upgrade-meta.php" nocase ascii wide
        $s1 = "upload_file" nocase ascii wide

    condition:
        any of them
}
