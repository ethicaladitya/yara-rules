rule AI_404_object_php_0a8afae9 : ai_generated critical
{
    meta:
        description  = "This file contains a heavily obfuscated PHP backdoor that decodes and executes hidden malicious code via multiple layers of string manipulation and eval."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Obfuscated PHP Backdoor"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/themes/helix/404-object.php"
        job_id       = "983e0681-4c62-48f4-8a46-e63ee78b32a1"
        generated_at = "2026-04-20T17:41:58.178371+00:00"
        ai_generated = true

    strings:
        $s0 = "base64_decode" nocase ascii wide
        $s1 = "gzinflate" nocase ascii wide
        $s2 = "str_rot13" nocase ascii wide

    condition:
        any of them
}
