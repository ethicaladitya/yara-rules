rule AI_class_wp_widget_archives_meta_php_4deb9cab : ai_generated critical
{
    meta:
        description  = "This file implements a fully functional web shell allowing remote file management including upload, delete, rename, move, copy, and directory removal."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Remote File Manager"
        severity     = "Critical"
        source_file  = "wp-includes/widgets/class-wp-widget-archives-meta.php"
        job_id       = "2b4b9641-90dd-4e49-8f0c-c19a6aeb6b7f"
        generated_at = "2026-04-20T17:41:58.381487+00:00"
        ai_generated = true

    strings:
        $s0 = "wp-includes/widgets/class-wp-widget-archives-meta.php" nocase ascii wide
        $s1 = "upload_file" nocase ascii wide

    condition:
        any of them
}
