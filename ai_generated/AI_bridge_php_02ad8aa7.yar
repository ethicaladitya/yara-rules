rule AI_bridge_php_02ad8aa7 : ai_generated critical
{
    meta:
        description  = "The file attempts to steal WordPress credentials and includes a self-healing backdoor mechanism."
        verdict      = "CONFIRMED MALICIOUS"
        category     = "Credential Theft and Self-Healing Backdoor"
        severity     = "Critical"
        source_file  = "backup/test/bridge2cart/bridge.php"
        job_id       = "8c616541-f94b-4d7d-9a4b-688413ad13b0"
        generated_at = "2026-04-20T17:41:58.025067+00:00"
        ai_generated = true

    strings:
        $s0 = "wp-config.php" nocase ascii wide

    condition:
        any of them
}
