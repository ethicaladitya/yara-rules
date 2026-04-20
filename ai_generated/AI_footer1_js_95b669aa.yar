rule AI_footer1_js_95b669aa : ai_generated medium
{
    meta:
        description  = "The file uses cleartext HTTP for a link to an eBay command-and-control URL, which could expose sensitive data."
        verdict      = "SUSPICIOUS"
        category     = "Potential Information Leak"
        severity     = "Medium"
        source_file  = "backup/ebay/js2/footer1.js"
        job_id       = "8c616541-f94b-4d7d-9a4b-688413ad13b0"
        generated_at = "2026-04-20T17:41:58.091355+00:00"
        ai_generated = true

    strings:
        $s0 = "http://my.ebay.com.au/ws/eBayISAPI.dll?AcceptSavedSeller&sellerid=myithub-au&ssPageName=STRK:MEFS:AD" nocase ascii wide

    condition:
        any of them
}
