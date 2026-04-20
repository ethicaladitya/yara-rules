rule AI_session_manager_php_e040908f : ai_generated critical
{
    meta:
        description  = "This file implements a persistent backdoor with self-modifying capabilities, remote shell execution, credential harvesting, and stealth persistence mechanisms."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Backdoor with Self-Modifying and Remote Code Execution"
        severity     = "Critical"
        source_file  = "session-manager.php"
        job_id       = "290b0f54-3f27-4ffe-ba85-fac8a0f99e95"
        generated_at = "2026-04-20T17:41:57.953425+00:00"
        ai_generated = true

    strings:
        $s0 = "a3f8b2c1d4e5f6071829304a5b6c7d8e9f0a1b2c3d4e5f607182930a1b2c3d4e" nocase ascii wide
        $s1 = "wp-content/uploads/2024/06/Stayed_Heart_Red-600x500.png" nocase ascii wide
        $s2 = "wp-includes/fonts/font-metrics.php" nocase ascii wide
        $s3 = "wp_cache_token" nocase ascii wide
        $s4 = "wp_debug_session" nocase ascii wide

    condition:
        any of them
}
