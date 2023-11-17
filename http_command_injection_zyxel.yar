rule HTTP_Zyxel_SelfRep_Command_Injection {
    meta:
        description = "Detects Zyxel self-replicating command injection attempts in HTTP logs"
        author = "Aaron Meese (@ajmeese7)"
        date = "2023-11-16"
        reference = "Specific pattern for Zyxel self-replication command; VirusTotal report: https://www.virustotal.com/gui/ip-address/103.110.33.164/community"


    strings:
        $cmd_inject = "/bin/zhttpd/"
        $cmd_cd = "cd${IFS}/tmp;"
        $cmd_rm = "rm${IFS}-rf${IFS}*;"
        $cmd_wget = "wget${IFS}http://"
        $cmd_chmod = "chmod${IFS}777${IFS}"
        $cmd_execute = "./mips${IFS}"
        $cmd_zyxel = "zyxel.selfrep;"

    condition:
        $cmd_inject and 2 of ($cmd_cd, $cmd_rm, $cmd_wget, $cmd_chmod, $cmd_execute, $cmd_zyxel)
}
