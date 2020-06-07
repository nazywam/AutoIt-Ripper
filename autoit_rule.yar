rule autoit_v3_26
{
    meta:
        date = "2020-03-12"
        author = "nazywam"
        description = "Detects AutoIt v3.26+ files"
        reference = "https://github.com/nazywam/AutoIt-Ripper"
    strings:
        $str1 = "This is a third-party compiled AutoIt script."
        $str2 = "AU3!EA06"
        $str3 = ">>>AUTOIT NO CMDEXECUTE<<<" wide
        $str4 = "AutoIt v3" wide
    condition:
        all of them
}


rule autoit_v3_00
{
    meta:
        date = "2020-06-07"
        author = "nazywam"
        description = "Detects AutoIt v3.00 files"
        reference = "https://github.com/nazywam/AutoIt-Ripper"
    strings:
        $str1 = "AU3_GetPluginDetails"
        $str2 = "AU3!EA05"
        $str3 = "OnAutoItStart" wide
        $str4 = "AutoIt v3" wide
        $str5 = "AutoIt script files (*.au3, *.a3x)" wide
        $str6 = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 }
    condition:
        all of them
}
