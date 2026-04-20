rule AI_class_wp_http_curl_exception_php_a19f6bd5 : ai_generated critical
{
    meta:
        description  = "This file is a fully featured PHP web shell allowing remote file management including upload, delete, rename, move, copy, and directory removal."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / Remote File Manager"
        severity     = "Critical"
        source_file  = "wp-includes/class-wp-http-curl-exception.php"
        job_id       = "d02d2d89-cf45-4798-bcc3-ea43fb4cc18b"
        generated_at = "2026-04-20T17:41:58.320039+00:00"
        ai_generated = true

    strings:
        $s0 = "wp-includes/class-wp-http-curl-exception.php" nocase ascii wide
        $s1 = "File manager with upload, delete, rename, move, copy, rmdir via GET/POST parameters" nocase ascii wide

    condition:
        any of them
}
