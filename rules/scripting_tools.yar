rule Suspicious_Batch_PowerShell
{
    strings:
        $a = "powershell -enc" nocase
        $b = "powershell.exe -enc" nocase
        $c = "FromBase64String" nocase
    condition:
        1 of them
}

rule Suspicious_Lolbins
{
    strings:
        $a = "regsvr32" nocase
        $b = "rundll32" nocase
        $c = "mshta" nocase
        $d = "certutil" nocase
    condition:
        2 of them
}
