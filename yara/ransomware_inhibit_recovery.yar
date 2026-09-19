rule Ransomware_Inhibit_System_Recovery
{
    meta:
        description = "Windows executable containing multiple commands used by ransomware to delete backups and disable recovery before encryption"
        author = "Taw"
        date = "2026-09-19"
        mitre_attack = "T1490"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a"

    strings:
        $vss1    = "vssadmin delete shadows" ascii wide nocase
        $vss2    = "vssadmin.exe delete shadows" ascii wide nocase
        $wmic    = "shadowcopy delete" ascii wide nocase
        $wbadmin = "wbadmin delete catalog" ascii wide nocase
        $bcd1    = "recoveryenabled no" ascii wide nocase
        $bcd2    = "bootstatuspolicy ignoreallfailures" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of them
}
