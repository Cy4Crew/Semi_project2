rule Browser_Stealer_Artifacts
{
    strings:
        $a = "Login Data" nocase
        $b = "Web Data" nocase
        $c = "Local State" nocase
        $d = "Cookies" nocase
        $e = "wallet" nocase
        $f = "metamask" nocase
    condition:
        3 of them
}

rule Discord_Token_Theft
{
    strings:
        $a = "discord" nocase
        $b = "token" nocase
        $c = "local storage" nocase
    condition:
        2 of them
}
