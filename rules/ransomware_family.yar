rule Ransomware_Shadowcopy_Delete
{
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wbadmin delete catalog" nocase
        $c = "bcdedit /set {default} recoveryenabled no" nocase
        $d = "ignoreallfailures" nocase
    condition:
        2 of them
}

rule Ransom_Note_Strings
{
    strings:
        $a = "your files have been encrypted" nocase
        $b = "decrypt" nocase
        $c = "bitcoin" nocase
        $d = "recover files" nocase
    condition:
        2 of them
}
