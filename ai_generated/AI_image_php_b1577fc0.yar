rule AI_image_php_b1577fc0 : ai_generated critical
{
    meta:
        description  = "This file implements a heavily obfuscated PHP backdoor that executes arbitrary code from POST data and includes remote files."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Obfuscated Remote Code Execution Backdoor"
        severity     = "Critical"
        source_file  = "fonts/genericons/image.php"
        job_id       = "2d801014-6dec-40a0-a128-5f2c697678ef"
        generated_at = "2026-04-20T17:41:58.286385+00:00"
        ai_generated = true

    strings:
        $s0 = "ks9[87518]" nocase ascii wide
        $s1 = "25d08aad-0484-4961-b069-4ecc4b7f220f" nocase ascii wide

    condition:
        any of them
}
