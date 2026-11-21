/*
   Portfolio YARA rules (Xiome West, MIT). Tested against the safe sample set built by
   triage/make_samples.py and against a benign PE to check for false positives.
*/
import "pe"
import "math"

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = "high"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" ascii
    condition:
        $e at 33 or ($e and filesize < 128)
}

rule PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell downloads and executes a remote script in memory"
        severity = "high"
        attack = "T1059.001, T1105"
    strings:
        $dl1 = "Net.WebClient" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "Invoke-WebRequest" nocase
        $ex1 = /\bIEX\b/ nocase
        $ex2 = "Invoke-Expression" nocase
    condition:
        filesize < 1MB and any of ($dl*) and any of ($ex*)
}

rule PowerShell_Encoded_Hidden
{
    meta:
        description = "Hidden PowerShell window with a Base64 -EncodedCommand payload"
        severity = "medium"
        attack = "T1027, T1059.001"
    strings:
        $enc = /-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $hid = /-w(indowstyle)?\s+hidden/ nocase
    condition:
        filesize < 1MB and $enc and $hid
}

rule Registry_Run_Key_Persistence
{
    meta:
        description = "Writes a Run key for persistence"
        severity = "medium"
        attack = "T1547.001"
    strings:
        $r = /(HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?/ nocase
        $w1 = "New-ItemProperty" nocase
        $w2 = "Set-ItemProperty" nocase
        $w3 = "reg add" nocase
        $w4 = "RegSetValue" nocase
    condition:
        $r and any of ($w*)
}

rule Office_Macro_AutoExec_Downloader
{
    meta:
        description = "VBA macro that runs on open and downloads or launches a payload"
        severity = "high"
        attack = "T1204.002, T1059.005, T1105"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Document_Open" nocase
        $a3 = "Workbook_Open" nocase
        $d1 = "URLDownloadToFile" nocase
        $d2 = "MSXML2.XMLHTTP" nocase
        $x1 = "WScript.Shell" nocase
        $x2 = /\bShell\s*\(/ nocase
    condition:
        any of ($a*) and any of ($d*) and any of ($x*)
}

rule Ransom_Note_Generic
{
    meta:
        description = "Text with typical ransom note language"
        severity = "high"
        attack = "T1486"
    strings:
        $s1 = "files have been encrypted" nocase
        $s2 = "bitcoin" nocase
        $s3 = ".onion" nocase
        $s4 = "decrypt" nocase
        $s5 = "will be published" nocase
        $s6 = "your id" nocase
    condition:
        filesize < 100KB and 4 of them
}

rule PE_Packer_Section_Names
{
    meta:
        description = "PE with section names left by common packers (UPX, MPRESS, ASPack, Themida, VMProtect)"
        severity = "medium"
        attack = "T1027.002"
    condition:
        pe.is_pe and for any s in pe.sections : (
            s.name == "UPX0" or s.name == "UPX1" or s.name == "MPRESS1" or s.name == ".aspack" or s.name == ".themida" or s.name == ".vmp0")
}

rule PE_Writable_Executable_HighEntropy_Section
{
    meta:
        description = "PE section that is writable, executable and near-random: self-unpacking or encrypted code"
        severity = "high"
        attack = "T1027.002"
    condition:
        pe.is_pe and for any s in pe.sections : (
            (s.characteristics & pe.SECTION_MEM_EXECUTE) and (s.characteristics & pe.SECTION_MEM_WRITE)
            and s.raw_data_size > 4096 and math.entropy(s.raw_data_offset, s.raw_data_size) > 7.2)
}
