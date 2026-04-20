rule AI_functions_core_php_647cf75d : ai_generated critical
{
    meta:
        description  = "This file contains a heavily obfuscated PHP backdoor that executes hidden code via multiple layers of decoding and eval."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "PHP Obfuscated Backdoor"
        severity     = "Critical"
        source_file  = "wp-content/themes/Impreza/functions-core.php"
        job_id       = "038cce44-9db2-41df-a113-5f5aa8e0d6c5"
        generated_at = "2026-04-20T17:41:57.929894+00:00"
        ai_generated = true

    strings:
        $s0 = "Dynamic function name construction and chained decoding" nocase ascii wide

    condition:
        any of them
}
