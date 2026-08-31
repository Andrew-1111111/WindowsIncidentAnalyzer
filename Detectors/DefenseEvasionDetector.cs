using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class DefenseEvasionDetector(IOptions<DetectionRulesOptions> options) : SignatureRuleBase
{
    private readonly KnownThreatSignaturesOptions _options = options.Value.KnownThreatSignatures;

    public override string Name => "DefenseEvasion";
    public override string Description => "Detects log clearing, audit/Defender tampering, shadow deletion, and security-tool impairment.";
    public override DetectionSeverity Severity => DetectionSeverity.High;
    public override bool IsEnabled => _options.Enabled;

    protected override IReadOnlyList<DetectionSignature> Signatures { get; } =
    [
        new("DE-003", "Windows Event Log service stopped", "Event logging stopped unexpectedly or the system shut down.", DetectionSeverity.High, [1100], Provider: "Eventlog"),
        new("DE-004", "System time changed", "The system clock was changed; validate whether this was expected.", DetectionSeverity.Medium, [4616]),
        new("DE-005", "Audit policy changed", "Windows audit policy was modified.", DetectionSeverity.High, [4719]),
        new("DE-006", "Defender real-time protection disabled", "Microsoft Defender reported that real-time protection was disabled.", DetectionSeverity.Critical, [5001], Provider: "Windows Defender"),
        new("DE-007", "Defender configuration changed", "Microsoft Defender configuration changed; review the affected setting.", DetectionSeverity.Medium, [5007], Provider: "Windows Defender"),
        new("DE-008", "Defender tamper protection blocked change", "Defender blocked a configuration change due to tamper protection.", DetectionSeverity.High, [5013], Provider: "Windows Defender"),
        new("DE-009", "Event log clearing command", "A command attempted to clear one or more event logs.", DetectionSeverity.Critical,
            [1, 4688, 4103, 4104], Any: ["wevtutil cl ", "wevtutil clear-log", "clear-eventlog", "remove-eventlog"]),
        new("DE-010", "Audit policy disabled", "A command disables success or failure auditing.", DetectionSeverity.Critical,
            [1, 4688, 4103, 4104], Any:
            ["auditpol /clear", "/success:disable", "/failure:disable", "set-mppreference -disableioavprotection"]),
        new("DE-011", "Defender protection disabled by command", "A command or script disables Defender protection.", DetectionSeverity.Critical,
            [1, 4688, 4103, 4104], Any:
            ["disablerealtimemonitoring $true", "disablebehaviormonitoring $true", "disableioavprotection $true", "disableintrusionpreventionsystem $true", "sc stop windefend", "net stop windefend"]),
        new("DE-012", "Defender exclusion added", "A Defender path, process, extension, or IP exclusion was configured.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any:
            ["add-mppreference -exclusion", "set-mppreference -exclusion", "exclusionpath", "exclusionprocess", "exclusionextension", "exclusionipaddress"]),
        new("DE-013", "Shadow copies deleted", "Commands delete volume shadow copies or backup catalogs, commonly inhibiting recovery.", DetectionSeverity.Critical,
            [1, 4688], Any:
            ["vssadmin delete shadows", "wmic shadowcopy delete", "delete shadows /all", "wbadmin delete catalog", "remove-computerrestorepoint"]),
        new("DE-014", "Recovery options impaired", "Boot recovery or Windows recovery environment was disabled.", DetectionSeverity.High,
            [1, 4688], Any:
            ["recoveryenabled no", "bootstatuspolicy ignoreallfailures", "reagentc /disable"]),
        new("DE-015", "PowerShell logging disabled", "Registry or PowerShell commands disable script block, module, or transcription logging.", DetectionSeverity.Critical,
            [1, 13, 4688, 4103, 4104], Any:
            ["enablescriptblocklogging", "enablemodulelogging", "enabletranscripting"], All: ["0"]),
        new("DE-016", "AMSI bypass indicator", "PowerShell content contains known AMSI bypass primitives.", DetectionSeverity.Critical,
            [4103, 4104, 1, 4688], Any:
            ["amsiutils", "amsiinitfailed", "amsiscanbuffer", "amsicontext", "amsi.dll", "patchamsi", "amsi bypass"]),
        new("DE-017", "ETW bypass indicator", "Command or script contains known ETW patching or bypass primitives.", DetectionSeverity.Critical,
            [4103, 4104, 1, 4688], Any:
            ["etweventwrite", "nttraceevent", "etw bypass", "patch etw", "etwprovider"]),
        new("DE-018", "Security service disabled", "A command disables common Windows security or logging services.", DetectionSeverity.High,
            [1, 4688], Any:
            ["sc config windefend start= disabled", "sc config eventlog start= disabled", "sc config sense start= disabled", "sc config sysmon", "fltmc unload sysmon"]),
        new("DE-019", "File timestamp manipulation", "A command or tool indicates timestamp manipulation.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any: ["timestomp", "setfiletime", "touch -r ", "creationtime =", "lastwritetime ="]),
        new("DE-020", "PowerShell history deleted", "A command removes PowerShell history or PSReadLine history.", DetectionSeverity.Medium,
            [1, 4688, 4103, 4104], Any:
            ["clear-history", "consolehost_history.txt", "set-psreadlineoption -historysavestyle savenothing"]),
        new("DE-021", "Firewall disabled", "A command disables Windows Firewall profiles.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any:
            ["netsh advfirewall set allprofiles state off", "set-netfirewallprofile"], All: ["false"]),
        new("DE-022", "Sysmon configuration changed", "Sysmon was uninstalled or reconfigured.", DetectionSeverity.High,
            [1, 4688], ProcessNames: ["sysmon.exe", "sysmon64.exe"], Any: [" -u", " -c", "/u", "/c"])
    ];
}
