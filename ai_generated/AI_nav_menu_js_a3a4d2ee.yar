rule AI_nav_menu_js_a3a4d2ee : ai_generated high
{
    meta:
        description  = "The file contains a hardcoded HTTP URL for command-and-control communication."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Command-and-Control Communication"
        severity     = "High"
        source_file  = "backup/wp-admin/js/nav-menu.js"
        job_id       = "8c616541-f94b-4d7d-9a4b-688413ad13b0"
        generated_at = "2026-04-20T17:41:58.101708+00:00"
        ai_generated = true

    strings:
        $s0 = "http://example.com/" nocase ascii wide

    condition:
        any of them
}
