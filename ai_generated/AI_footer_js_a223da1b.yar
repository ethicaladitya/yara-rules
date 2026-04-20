rule AI_footer_js_a223da1b : ai_generated medium
{
    meta:
        description  = "The file uses cleartext HTTP for a link to eBay, which could be insecure."
        verdict      = "SUSPICIOUS"
        category     = "Insecure HTTP Usage"
        severity     = "Medium"
        source_file  = "backup/ebay/js2/footer.js"
        job_id       = "8c616541-f94b-4d7d-9a4b-688413ad13b0"
        generated_at = "2026-04-20T17:41:58.081203+00:00"
        ai_generated = true

    strings:
        $s0 = "http://my.ebay.com.au/ws/eBayISAPI.dll?AcceptSavedSeller&sellerid=myithub-au&ssPageName=STRK:MEFS:AD" nocase ascii wide
        $s1 = "http://stores.ebay.com.au/myithubaus" nocase ascii wide

    condition:
        any of them
}
