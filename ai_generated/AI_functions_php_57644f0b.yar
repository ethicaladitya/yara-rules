rule AI_functions_php_57644f0b : ai_generated high
{
    meta:
        description  = "This file implements a sophisticated cloaked backdoor that filters posts by hidden authors, injects stealthy JavaScript, manipulates sitemaps, and exfiltrates debug data to a remote server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Cloaking and Data Exfiltration"
        severity     = "High"
        source_file  = "functions.php"
        job_id       = "2d801014-6dec-40a0-a128-5f2c697678ef"
        generated_at = "2026-04-20T17:41:58.295246+00:00"
        ai_generated = true

    strings:
        $s0 = "http://wp-update-cdn.com/src/ualogsec.php" nocase ascii wide
        $s1 = "https://www.gstatic.com/ipranges/goog.txt" nocase ascii wide
        $s2 = "add_action('wp_head', 'buffer_start_custom')" nocase ascii wide
        $s3 = "add_action('wp_footer', 'buffer_end_custom')" nocase ascii wide
        $s4 = "wp_debug_data" nocase ascii wide
        $s5 = "wp_custom_range" nocase ascii wide
        $s6 = "wp_custom_filters" nocase ascii wide

    condition:
        any of them
}
