rule AI_wp_compat_php_67fad5b9 : ai_generated critical
{
    meta:
        description  = "This file creates a hidden admin user and manipulates WordPress hooks to conceal its presence."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor and User Manipulation"
        severity     = "Critical"
        source_file  = "wp-compat/wp-compat.php"
        job_id       = "5a6a9bcf-bff0-4c09-a1ed-0d5451fa8837"
        generated_at = "2026-04-20T17:41:57.921887+00:00"
        ai_generated = true

    strings:
        $s0 = "adminbackup" nocase ascii wide
        $s1 = "4I9d3igHUt" nocase ascii wide
        $s2 = "adminbackup@wordpress.org" nocase ascii wide
        $s3 = "WORDPRESS_ADMIN_USER" nocase ascii wide

    condition:
        any of them
}
