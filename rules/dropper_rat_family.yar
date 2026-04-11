rule Downloader_Dropper_Chain
{
    strings:
        $a = "URLDownloadToFile" nocase
        $b = "Invoke-WebRequest" nocase
        $c = "DownloadString" nocase
        $d = "powershell -enc" nocase
        $e = "certutil -urlcache" nocase
    condition:
        2 of them
}

rule RAT_Shell_Behavior
{
    strings:
        $a = "reverse shell" nocase
        $b = "cmd /c" nocase
        $c = "wscript.shell" nocase
        $d = "meterpreter" nocase
        $e = "connectback" nocase
    condition:
        2 of them
}
