rule AI_class_wp_filesystem_ftpext_hashing_php_03281105 : ai_generated critical
{
    meta:
        description  = "This file implements a fully functional web shell allowing arbitrary file management and upload on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Backdoor"
        severity     = "Critical"
        source_file  = "wp-admin/includes/class-wp-filesystem-ftpext-hashing.php"
        job_id       = "d02d2d89-cf45-4798-bcc3-ea43fb4cc18b"
        generated_at = "2026-04-20T17:41:58.346071+00:00"
        ai_generated = true

    strings:
        $s0 = "upload_file" nocase ascii wide

    condition:
        any of them
}
