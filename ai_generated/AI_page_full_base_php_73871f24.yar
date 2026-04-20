rule AI_page_full_base_php_73871f24 : ai_generated critical
{
    meta:
        description  = "This file is a full-featured PHP web shell disguised as 'Tiny File Manager' allowing authenticated users to browse, upload, download, edit, delete, and execute arbitrary files on the server."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Web Shell / File Manager Backdoor"
        severity     = "Critical"
        source_file  = "Infected files/wp-content/themes/helix/page-full-base.php"
        job_id       = "17fa7444-de9b-4e02-8d08-360d4aced33e"
        generated_at = "2026-04-20T17:41:58.246522+00:00"
        ai_generated = true

    strings:
        $s0 = "$2y$10$lmuIaiK1IVc3vwIoFTYRre0I0m9uwXbi9sqmGH1o7JVxT/DyEzYNa" nocase ascii wide
        $s1 = "Tiny File Manager" nocase ascii wide
        $s2 = "filemanager" nocase ascii wide

    condition:
        any of them
}
