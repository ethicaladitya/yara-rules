rule AI_functions_php_80b2e147 : ai_generated critical
{
    meta:
        description  = "This theme's functions.php contains a sophisticated backdoor that injects hidden sitemap feeds and cloaked content based on visitor IP ranges and request URIs, enabling stealthy content injection and"
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Malicious Backdoor via Theme Functions"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/themes/helix/functions.php"
        job_id       = "983e0681-4c62-48f4-8a46-e63ee78b32a1"
        generated_at = "2026-04-20T17:41:58.169951+00:00"
        ai_generated = true

    strings:
        $s0 = "wp_custom_filters" nocase ascii wide
        $s1 = "md5(sha1($_SERVER['HTTP_HOST']))" nocase ascii wide
        $s2 = "https://www.gstatic.com/ipranges/goog.txt" nocase ascii wide
        $s3 = "update_plugins_" nocase ascii wide
        $s4 = "position:absolute; filter:alpha(opacity=0);opacity:0.003;z-index:-1;" nocase ascii wide

    condition:
        any of them
}
