rule AI_categories_php_824fbd5b : ai_generated medium
{
    meta:
        description  = "Fetches and injects content from an external HTTP source into the WordPress site."
        verdict      = "SUSPICIOUS"
        category     = "Potential Data Exfiltration"
        severity     = "Medium"
        source_file  = "backup/ebay/categories.php"
        job_id       = "8c616541-f94b-4d7d-9a4b-688413ad13b0"
        generated_at = "2026-04-20T17:41:58.061049+00:00"
        ai_generated = true

    strings:
        $s0 = "http://stores.ebay.com.au/myithub/_i.html" nocase ascii wide

    condition:
        any of them
}
