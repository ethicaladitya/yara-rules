rule AI_wp_compat_php_bfabda90 : ai_generated critical
{
    meta:
        description  = "This file creates a hidden admin user and manipulates WordPress hooks to conceal its presence."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor and User Manipulation"
        severity     = "Critical"
        source_file  = "plugins/wp-compat/wp-compat.php"
        job_id       = "fc61d35d-2860-4415-be33-a68eb8d07f17"
        generated_at = "2026-04-20T17:41:58.267103+00:00"
        ai_generated = true

    strings:
        $s0 = "adminbackup" nocase ascii wide
        $s1 = "rwO7Tcp3eA" nocase ascii wide
        $s2 = "adminbackup@wordpress.org" nocase ascii wide
        $s3 = "WORDPRESS_ADMIN_USER" nocase ascii wide

    condition:
        any of them
}
