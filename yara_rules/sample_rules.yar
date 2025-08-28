
rule SuspiciousPowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        author = "Forensic AI Analyzer"
        
    strings:
        $powershell1 = "powershell" nocase
        $encoded1 = "EncodedCommand" nocase
        $encoded2 = "-enc" nocase
        $bypass1 = "ExecutionPolicy Bypass" nocase
        $download1 = "DownloadString" nocase
        $download2 = "IEX" nocase
        
    condition:
        $powershell1 and (
            ($encoded1 or $encoded2) or
            $bypass1 or
            ($download1 and $download2)
        )
}

rule SuspiciousNetworkActivity {
    meta:
        description = "Detects suspicious network activity patterns"
        
    strings:
        $curl1 = "curl" nocase
        $wget1 = "wget" nocase
        $nc1 = "netcat" nocase
        $nc2 = "nc -" nocase
        $reverse1 = "/bin/sh" nocase
        $reverse2 = "/bin/bash" nocase
        
    condition:
        ($curl1 or $wget1) or
        ($nc1 or $nc2) and ($reverse1 or $reverse2)
}
