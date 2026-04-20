rule AI_class_wp_ms_users_list_table_compiler_php_3f3c2345 : ai_generated critical
{
    meta:
        description  = "This file implements a fully functional web shell allowing arbitrary file upload, deletion, renaming, moving, copying, and directory removal on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Remote File Manager"
        severity     = "Critical"
        source_file  = "wp-admin/includes/class-wp-ms-users-list-table-compiler.php"
        job_id       = "2b4b9641-90dd-4e49-8f0c-c19a6aeb6b7f"
        generated_at = "2026-04-20T17:41:58.365147+00:00"
        ai_generated = true

    strings:
        $s0 = "wp-admin/includes/class-wp-ms-users-list-table-compiler.php" nocase ascii wide
        $s1 = "upload_file" nocase ascii wide

    condition:
        any of them
}
