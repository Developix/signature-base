rule WEBSHELL_ASPX_Sharepoint_Drop_CVE_2025_53770_Jul25 {
   meta:
      description = "Detects ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      score = 80
      hash = "27c45b8ed7b8a7e5fff473b50c24028bd028a9fe8e25e5cea2bf5e676e531014"
      hash = "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514"
      hash = "b336f936be13b3d01a8544ea3906193608022b40c28dd8f1f281e361c9b64e93"
   strings:
      $x1 = "var sy = System.Reflection.Assembly.Load(" ascii
      $x2 = "Response.Write(cg.ValidationKey+" ascii

      $s1 = "<script runat=\"server\" language=\"c#\" CODEPAGE=\"65001\">" ascii fullword
   condition:
      filesize < 4KB
      and 1 of ($x*)
      or all of them
}

rule WEBSHELL_ASPX_Compiled_Sharepoint_Drop_CVE_2025_53770_Jul25_2 {
   meta:
      description = "Detects compiled ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth, Marius Benthin"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      modified = "2025-07-25"
      score = 75
      hash = "8d3d3f3a17d233bc8562765e61f7314ca7a08130ac0fb153ffd091612920b0f2"
      hash = "d8ca5e5d6400ac34ac4cc138efa89d2ec4d5c0e968a78fa3ba5dbc04c7550649"
      hash = "7e9b77da1f51d03ee2f96bc976f6aeb781f801cf633862a4b8c356cbb555927d"
   strings:
      $x1 = /App_Web_spinstall\d{0,1}.aspx/ wide
      $x2 = /spinstall[\w]?[\._]aspx/ ascii
      $x3 = /\/_layouts\/1[0-9]\/spinstall/ wide
      $x4 = /\/_layouts\/1[0-9]\/ghostfile/ wide

      $s1 = "System.Web.Configuration.MachineKeySection" wide
      $s2 = "Page_load" ascii fullword
      $s3 = "GetApplicationConfig" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
      or 2 of ($x*)
      or 4 of them
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1_ToolPane_EditMode
{
    meta:
        description = "Detects POST access to ToolPane.aspx with DisplayMode=Edit"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 75
    strings:
        $a1 = /POST \/_layouts\/1[0-9]\/ToolPane\.aspx/ ascii wide nocase
        $a2 = "DisplayMode=Edit&a=/ToolPane.aspx" ascii wide
    condition:
        (@a2 - @a1) < 700
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1_GET_spinstall
{
    meta:
        description = "Detects GET request to /_layouts/1x/spinstall path"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 75
    strings:
        $b1 = /GET \/_layouts\/1[0-9]\/spinstall/ ascii wide
    condition:
        any of them
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1_SignOut_200
{
    meta:
        description = "Detects HTTP 200 access to /_layouts/SignOut.aspx"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 75
    strings:
        $b2 = "/_layouts/SignOut.aspx 200" ascii wide nocase
    condition:
        any of them
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1_SignOut_spinstall_combo
{
    meta:
        description = "Detects SignOut and spinstall accessed within 700 bytes"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 75
    strings:
        $b1 = /GET \/_layouts\/1[0-9]\/spinstall/ ascii wide
        $b2 = "/_layouts/SignOut.aspx 200" ascii wide nocase
    condition:
        (@b2 - @b1) < 700
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1_ToolPane_SignOut_combo
{
    meta:
        description = "Detects ToolPane and SignOut accessed close together"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 75
    strings:
        $a1 = /POST \/_layouts\/1[0-9]\/ToolPane\.aspx/ ascii wide nocase
        $b2 = "/_layouts/SignOut.aspx 200" ascii wide nocase
    condition:
        (@b2 - @a1) < 700
}


rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2_EncodedCommand
{
    meta:
        description = "Detects PowerShell EncodedCommand related to CVE-2025-53770 exploitation"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 70
    strings:
        $x1 = "-EncodedCommand JABiAGEAcwBlADYANABTAHQAcgBpAG4AZwAgAD0" ascii wide
    condition:
        any of them
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2_SuspiciousPaths
{
    meta:
        description = "Detects suspicious SharePoint LAYOUTS paths"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 70
    strings:
        $x2 = "TEMPLATE\\LAYOUTS\\spinstall" ascii wide
        $x3 = "TEMPLATE\\LAYOUTS\\ghostfile" ascii wide
        $x4 = "TEMPLATE\\LAYOUTS\\1.css" ascii wide
    condition:
        any of them
}


rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2_SignOutAccess
{
    meta:
        description = "Detects access to SignOut.aspx with suspicious Firefox user-agent"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 70
    strings:
        $x5 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:120.0)+Gecko/20100101+Firefox/120.0 /_layouts/SignOut.aspx" ascii wide
    condition:
        any of them
}


rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2_EncodedDropper16
{
    meta:
        description = "Detects UTF-16 encoded paths from dropper sample (TEMPLATE\\LAYOUTS\\16)"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 70
    strings:
        $xe1 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA2AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA"
        $xe2 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANgBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA"
        $xe3 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADYAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA"
    condition:
        any of them
}


rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2_EncodedDropper15
{
    meta:
        description = "Detects UTF-16 encoded paths from dropper sample (TEMPLATE\\LAYOUTS\\15)"
        author = "Florian Roth"
        reference = "https://research.eye.security/sharepoint-under-siege/"
        date = "2025-07-20"
        score = 70
    strings:
        $xe4 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA1AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA"
        $xe5 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANQBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA"
        $xe6 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADUAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA"
    condition:
        any of them
}


