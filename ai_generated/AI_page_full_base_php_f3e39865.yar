rule AI_page_full_base_php_f3e39865 : ai_generated critical
{
    meta:
        description  = "This file is a full-featured PHP web shell disguised as a 'Tiny File Manager' allowing authenticated users to browse, upload, download, edit, delete, copy, rename, archive, and unpack files on the ser"
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / File Manager Backdoor"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/themes/helix/page-full-base.php"
        job_id       = "983e0681-4c62-48f4-8a46-e63ee78b32a1"
        generated_at = "2026-04-20T17:41:58.185911+00:00"
        ai_generated = true

    strings:
        $s0 = "$2y$10$lmuIaiK1IVc3vwIoFTYRre0I0m9uwXbi9sqmGH1o7JVxT/DyEzYNa" nocase ascii wide
        $s1 = "Tiny File Manager" nocase ascii wide
        $s2 = "ccpprogrammers@gmail.com" nocase ascii wide
        $s3 = "https://tinyfilemanager.github.io" nocase ascii wide

    condition:
        any of them
}
