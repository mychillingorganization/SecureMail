/*
 * pe_packed.yar — YARA rules phát hiện PE đóng gói/obfuscated
 */

rule PE_Packer_UPX
{
    meta:
        description = "UPX packed PE executable"
        severity    = "medium"
    strings:
        $s1 = "UPX0" fullword
        $s2 = "UPX1" fullword
        $s3 = "UPX!" fullword
    condition:
        uint16(0) == 0x5A4D and (2 of them)
}

rule PE_Packer_ASPack
{
    meta:
        description = "ASPack packed PE executable"
        severity    = "medium"
    strings:
        $s1 = ".aspack" fullword
        $s2 = ".adata"  fullword
        $s3 = "ASPack"
    condition:
        uint16(0) == 0x5A4D and (1 of them)
}

rule PE_Packer_Themida
{
    meta:
        description = "Themida/WinLicense protected PE"
        severity    = "high"
    strings:
        $s1 = ".themida"   fullword
        $s2 = ".winlicen"  fullword
        $s3 = "Themida"
    condition:
        uint16(0) == 0x5A4D and (1 of them)
}

rule PE_Suspicious_Import_ProcessInjection
{
    meta:
        description = "PE importing process injection APIs"
        severity    = "high"
    strings:
        $i1 = "CreateRemoteThread"  fullword
        $i2 = "VirtualAllocEx"      fullword
        $i3 = "WriteProcessMemory"  fullword
        $i4 = "NtCreateThreadEx"    fullword
        $i5 = "RtlCreateUserThread" fullword
        $i6 = "QueueUserAPC"        fullword
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Suspicious_Import_Download
{
    meta:
        description = "PE importing file download APIs"
        severity    = "high"
    strings:
        $d1 = "URLDownloadToFileA" fullword
        $d2 = "URLDownloadToFileW" fullword
        $d3 = "InternetOpenA"      fullword
        $d4 = "InternetOpenUrlA"   fullword
        $d5 = "WinHttpOpen"        fullword
    condition:
        uint16(0) == 0x5A4D and 1 of them
}

rule PE_Suspicious_Import_Persistence
{
    meta:
        description = "PE importing registry persistence APIs"
        severity    = "medium"
    strings:
        $r1 = "RegSetValueExA"  fullword
        $r2 = "RegSetValueExW"  fullword
        $r3 = "RegCreateKeyExA" fullword
        $r4 = "RegCreateKeyExW" fullword
        $r5 = "SHSetValue"      fullword
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule PE_Anti_Analysis
{
    meta:
        description = "PE with anti-analysis techniques (anti-debug, anti-VM)"
        severity    = "medium"
    strings:
        $a1 = "IsDebuggerPresent"            fullword
        $a2 = "CheckRemoteDebuggerPresent"   fullword
        $a3 = "NtQueryInformationProcess"    fullword
        $v1 = "VMware"                       nocase
        $v2 = "VirtualBox"                   nocase
        $v3 = "VBOX"                         nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($a*) or 1 of ($v*))
}

rule PE_No_DOS_Stub
{
    meta:
        description = "PE file without standard DOS stub (possible tool/shellcode loader)"
        severity    = "low"
    condition:
        uint16(0) == 0x5A4D
        and not (uint8(0x3C) < 0x80)   // PE offset too low
        and filesize < 10MB
}

rule Shellcode_X86_GetPC
{
    meta:
        description = "x86 shellcode GetPC technique"
        severity    = "high"
    strings:
        // call/pop pattern to get EIP
        $call_pop = { E8 00 00 00 00 5? }
        // FSTENV pattern
        $fstenv = { D9 EE D9 74 24 F4 }
    condition:
        any of them
}
