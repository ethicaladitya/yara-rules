rule AI_yak_php_25f69f63 : ai_generated critical
{
    meta:
        description  = "This file decodes and executes a heavily obfuscated PHP payload from a custom base64-like encoded string using XOR with a static key."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Obfuscated Remote Code Execution"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/.cache/modules/yak.php"
        job_id       = "17fa7444-de9b-4e02-8d08-360d4aced33e"
        generated_at = "2026-04-20T17:41:58.255837+00:00"
        ai_generated = true

    strings:
        $s0 = "X14dDRxua0kBAwAUAAACFzMCChhDXE0XCQINHQQYC0kKABgAFglNRUpaYG9IFhEBCg0HMQwRBENcTQwfEAQZTUg8JigxN0QRDBEERDxERVNDRTIiKTc6ShUNFwlKOExZQUkBAwAUAAACFzMCChhYbGdBGRMNAgQIMwAZDUxeQR4RHjwTCBUAAgIITTdETkpJTEQ9MUIx" nocase ascii wide

    condition:
        any of them
}
