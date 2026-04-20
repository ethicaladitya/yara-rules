rule AI_yak_php_d35e76c3 : ai_generated critical
{
    meta:
        description  = "This file decrypts and executes a hidden PHP payload using a custom base64 variant and XOR key, enabling stealthy backdoor functionality."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Encrypted PHP Backdoor Loader"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/uploads/2024/.cache/modules/yak.php"
        job_id       = "983e0681-4c62-48f4-8a46-e63ee78b32a1"
        generated_at = "2026-04-20T17:41:58.194262+00:00"
        ai_generated = true

    strings:
        $s0 = "X14dDRxua0kBAwAUAAACFzMCChhDXE0XCQINHQQYC0kKABgAFglNRUpaYG9IFhEBCg0HMQwRBENcTQwfEAQZTUg8JigxN0QRDBEERDxERVNDRTIiKTc6ShUNFwlKOExZQUkBAwAUAAACFzMCChhYbGdBGRMNAgQIMwAZDUxeQR4RHjwTCBUAAgIITTdETkpJTEQ9MUIx" nocase ascii wide

    condition:
        any of them
}
