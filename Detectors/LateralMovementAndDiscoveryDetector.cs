using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class LateralMovementAndDiscoveryDetector(IOptions<DetectionRulesOptions> options) : SignatureRuleBase
{
    private readonly KnownThreatSignaturesOptions _options = options.Value.KnownThreatSignatures;

    public override string Name => "LateralMovementAndDiscovery";
    public override string Description => "Detects remote execution, administrative-share access, tunneling, and common host/domain discovery.";
    public override DetectionSeverity Severity => DetectionSeverity.Medium;
    public override bool IsEnabled => _options.Enabled;

    protected override IReadOnlyList<DetectionSignature> Signatures { get; } =
    [
        new("LM-001", "PsExec-style remote service", "Service name or command line resembles PsExec/PSEXESVC remote execution.", DetectionSeverity.Critical,
            [1, 4688, 4697, 7045], Any: ["psexec", "psexesvc", "paexec", "remcomsvc"]),
        new("LM-002", "WMI remote process creation", "WMIC or PowerShell initiated remote process execution.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any: ["wmic /node:", "process call create", "invoke-wmimethod", "invoke-cimmethod"], All: ["create"]),
        new("LM-003", "PowerShell remoting", "PowerShell remoting or a remote session was initiated.", DetectionSeverity.Medium,
            [1, 4688, 4103, 4104], Any:
            ["invoke-command", "enter-pssession", "new-pssession", "connect-pssession", "invoke-command -computername"]),
        new("LM-004", "WinRS remote execution", "Windows Remote Shell was used for remote command execution.", DetectionSeverity.High,
            [1, 4688], ["winrs.exe"], Any: ["-r:", "/r:", "http://", "https://"]),
        new("LM-005", "Remote service control", "Service Control targeted a remote host.", DetectionSeverity.High,
            [1, 4688], ["sc.exe"], Any: [@"\\"]),
        new("LM-006", "Remote scheduled task", "Schtasks targeted another host.", DetectionSeverity.High,
            [1, 4688], ["schtasks.exe"], Any: ["/s ", "-s "]),
        new("LM-007", "Administrative share access", "A Windows administrative share was accessed.", DetectionSeverity.Medium,
            [5140, 5145], Any: [@"\admin$", @"\c$", @"\ipc$", @"\d$"]),
        new("LM-008", "Remote share connection", "A command connected to a UNC path or administrative share.", DetectionSeverity.Medium,
            [1, 4688], Any: [@"net use \\", @"new-psdrive \\", @"copy \\", @"robocopy \\"]),
        new("LM-009", "Remote Desktop client launched", "A Remote Desktop client was launched with a target host.", DetectionSeverity.Low,
            [1, 4688], ["mstsc.exe"], Any: ["/v:", ".rdp"]),
        new("LM-010", "SSH or PuTTY remote session", "An SSH client or PuTTY tool initiated a remote session.", DetectionSeverity.Low,
            [1, 4688], ["ssh.exe", "plink.exe", "putty.exe", "pscp.exe"], Any: ["@", "-hostkey", "-pw", "-i "]),
        new("LM-011", "Network tunneling utility", "A known tunneling, relay, or proxy utility was executed.", DetectionSeverity.High,
            [1, 4688], Any:
            ["chisel.exe", "ligolo", "frpc.exe", "frps.exe", "ngrok.exe", "socat.exe", "plink -r", "plink.exe -r", "netsh interface portproxy"]),
        new("LM-012", "Remote registry access", "Remote Registry or reg.exe targeted another host.", DetectionSeverity.High,
            [1, 4688], ["reg.exe"], Any: [@"\\", "remote registry"]),
        new("DS-001", "Account discovery", "A command enumerated local/domain users, groups, or privileges.", DetectionSeverity.Low,
            [1, 4688, 4103, 4104], Any:
            ["whoami /all", "whoami /priv", "whoami /groups", "net user", "net1 user", "net group", "net localgroup", "get-localuser", "get-localgroupmember", "get-aduser", "get-adgroupmember"]),
        new("DS-002", "Domain trust discovery", "A command enumerated domain controllers, trusts, or forest relationships.", DetectionSeverity.Medium,
            [1, 4688, 4103, 4104], Any:
            ["nltest /domain_trusts", "nltest /dclist:", "dsquery server", "get-addomain", "get-adforest", "get-adtrust", "invoke-userhunter", "find-domainshare"]),
        new("DS-003", "System owner or host discovery", "A command collected host, operating-system, or logged-on-user information.", DetectionSeverity.Low,
            [1, 4688, 4103, 4104], Any:
            ["systeminfo", "hostname", "get-computerinfo", "get-ciminstance win32_operatingsystem", "quser", "qwinsta", "query user"]),
        new("DS-004", "Network configuration discovery", "A command enumerated local network configuration, routes, ARP, or connections.", DetectionSeverity.Low,
            [1, 4688, 4103, 4104], Any:
            ["ipconfig /all", "route print", "arp -a", "netstat -ano", "get-netipconfiguration", "get-nettcpconnection", "get-netroute"]),
        new("DS-005", "Process or service discovery", "A command enumerated running processes, services, or drivers.", DetectionSeverity.Low,
            [1, 4688, 4103, 4104], Any:
            ["tasklist", "get-process", "wmic process", "sc query", "net start", "get-service", "driverquery", "fltmc"]),
        new("DS-006", "Security product discovery", "A command queried security products, Defender status, or antivirus namespaces.", DetectionSeverity.Medium,
            [1, 4688, 4103, 4104], Any:
            ["securitycenter2", "get-mpcomputerstatus", "wmic /namespace:\\\\root\\securitycenter2", "sc query windefend", "senseir.exe"]),
        new("DS-007", "File and share discovery", "A command recursively enumerated files or network shares.", DetectionSeverity.Low,
            [1, 4688, 4103, 4104], Any:
            ["net share", "get-smbshare", "dir /s", "tree /f", "get-childitem -recurse", "findstr /s"]),
        new("DS-008", "Active Directory SPN discovery", "A command enumerated service principal names, often preceding Kerberoasting.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any:
            ["setspn -q", "setspn -t", "serviceprincipalname", "get-domainuser -spn", "get-aduser -filter"], All: ["spn"])
    ];
}
