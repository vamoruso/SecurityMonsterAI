rule FakeMalware {
    meta:
        description = "Falsa firma di malware per scopi didattici"
        author = "You"
        date = "2025-01-01"
    strings:
        $indicator = "Win32/Exploit.Agent.EZ"
    condition:
        $indicator
}