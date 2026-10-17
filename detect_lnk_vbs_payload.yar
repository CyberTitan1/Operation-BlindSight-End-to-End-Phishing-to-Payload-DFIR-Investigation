rule APT_Phishing_LNK_WScript_Stager {
    meta:
        description = "Detects malicious LNK shortcut invoking wscript.exe with hidden script staging"
        author = "Enoch Abikenlu"
        date = "2026-10-16"
        severity = "High"

    strings:
        // Universal LNK header magic bytes
        $lnk_header = { 4c 00 00 00 }

        // Hardcoded execution binary path in wide format
        $wscript_path = "wscript.exe" wide ascii nocase

        // Script stager arguments
        $nologo_arg = "//nologo" wide ascii nocase
        $script_ext = ".vbs" wide ascii nocase

    condition:
        $lnk_header and $wscript_path and $nologo_arg and $script_ext
}
