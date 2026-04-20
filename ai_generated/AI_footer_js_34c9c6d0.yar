rule AI_footer_js_34c9c6d0 : ai_generated medium
{
    meta:
        description  = "The file includes a footer with a link to an external site using HTTP."
        verdict      = "SUSPICIOUS"
        category     = "Potential Information Leakage"
        severity     = "Medium"
        source_file  = "backup/ebay/css/js2/footer.js"
        job_id       = "8c616541-f94b-4d7d-9a4b-688413ad13b0"
        generated_at = "2026-04-20T17:41:58.071074+00:00"
        ai_generated = true

    strings:
        $s0 = "http://www.estoreseller.com/" nocase ascii wide

    condition:
        any of them
}
