using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class PersistenceAndLolbinDetector(IOptions<DetectionRulesOptions> options) : SignatureRuleBase
{
    private readonly KnownThreatSignaturesOptions _options = options.Value.KnownThreatSignatures;

    public override string Name => "PersistenceAndLolbin";
    public override string Description => "Detects common persistence mechanisms and suspicious use of Windows living-off-the-land binaries.";
    public override DetectionSeverity Severity => DetectionSeverity.High;
    public override bool IsEnabled => _options.Enabled;

    protected override IReadOnlyList<DetectionSignature> Signatures { get; } =
    [
        new("PE-003", "WMI event filter created", "A permanent WMI event filter was created.", DetectionSeverity.High, [19], Provider: "Sysmon"),
        new("PE-004", "WMI event consumer created", "A permanent WMI event consumer was created.", DetectionSeverity.High, [20], Provider: "Sysmon"),
        new("PE-005", "WMI filter-to-consumer binding", "A permanent WMI event subscription binding was created.", DetectionSeverity.Critical, [21], Provider: "Sysmon"),
        new("PE-006", "Registry Run key persistence", "A registry Run/RunOnce key was changed.", DetectionSeverity.High,
            [13], Any: [@"\software\microsoft\windows\currentversion\run", @"\runonce"], Provider: "Sysmon"),
        new("PE-007", "Winlogon registry persistence", "Winlogon Shell, Userinit, or Notify configuration was changed.", DetectionSeverity.Critical,
            [13], Any: [@"\winlogon\shell", @"\winlogon\userinit", @"\winlogon\notify"], Provider: "Sysmon"),
        new("PE-008", "Image File Execution Options hijack", "IFEO Debugger or SilentProcessExit persistence was configured.", DetectionSeverity.Critical,
            [13], Any: [@"\image file execution options\", @"\silentprocessexit\"], Provider: "Sysmon"),
        new("PE-009", "AppInit DLL persistence", "AppInit_DLLs or LoadAppInit_DLLs was changed.", DetectionSeverity.High,
            [13], Any: ["appinit_dlls", "loadappinit_dlls"], Provider: "Sysmon"),
        new("PE-010", "LSA authentication package persistence", "LSA Security Packages, Authentication Packages, or Notification Packages changed.", DetectionSeverity.Critical,
            [13], Any: ["security packages", "authentication packages", "notification packages"], Provider: "Sysmon"),
        new("PE-011", "Office add-in persistence", "An Office add-in load behavior or manifest registry value changed.", DetectionSeverity.High,
            [13], Any: [@"\office\", @"\addins\", "loadbehavior", "manifest"], Provider: "Sysmon"),
        new("PE-012", "Startup folder persistence", "A file was created in a user or system Startup folder.", DetectionSeverity.High,
            [11], Any: [@"\start menu\programs\startup\", @"\главное меню\программы\автозагрузка\"], Provider: "Sysmon"),
        new("PE-013", "Scheduled task creation command", "schtasks or PowerShell created a scheduled task.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any: ["schtasks /create", "register-scheduledtask", "new-scheduledtaskaction"]),
        new("PE-014", "Service creation command", "A command created a Windows service.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any: ["sc create ", "sc.exe create ", "new-service ", "create service"]),
        new("PE-015", "MSHTA script execution", "MSHTA executed remote content or inline script.", DetectionSeverity.High,
            [1, 4688], ["mshta.exe"], Any: ["http://", "https://", "javascript:", "vbscript:", ".hta"]),
        new("PE-016", "Regsvr32 scriptlet execution", "Regsvr32 used scrobj.dll or remote scriptlet execution switches.", DetectionSeverity.Critical,
            [1, 4688], ["regsvr32.exe"], Any: ["scrobj.dll", "/i:http", "/i:https", "-i:http", "-i:https"]),
        new("PE-017", "Rundll32 script execution", "Rundll32 invoked JavaScript, protocol handlers, or suspicious exports.", DetectionSeverity.High,
            [1, 4688], ["rundll32.exe"], Any:
            ["javascript:", "url.dll,fileprotocolhandler", "advpack.dll,launchinfsection", "setupapi.dll,installhinfsection", "shell32.dll,shellexec_rundll"]),
        new("PE-018", "Certutil download or decode", "Certutil was used to download, decode, or encode data.", DetectionSeverity.High,
            [1, 4688], ["certutil.exe"], Any: ["-urlcache", "-split", "-decode", "-decodehex", "-encode"]),
        new("PE-019", "BITS transfer", "BITSAdmin or PowerShell initiated a background file transfer.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any: ["bitsadmin /transfer", "bitsadmin /create", "start-bitstransfer", "add-bitsfile"]),
        new("PE-020", "WMIC remote or XSL execution", "WMIC used remote execution or XSL script processing.", DetectionSeverity.High,
            [1, 4688], ["wmic.exe"], Any: ["/node:", "process call create", "/format:http", "/format:https", ".xsl"]),
        new("PE-021", "MSBuild suspicious execution", "MSBuild executed a non-standard project or inline task from a writable/remote location.", DetectionSeverity.High,
            [1, 4688], ["msbuild.exe"], Any: [@"\temp\", @"\appdata\", @"\downloads\", "http://", "https://", "codedom", "usingtask"]),
        new("PE-022", "InstallUtil proxy execution", "InstallUtil command-line switches indicate proxy execution or uninstall execution.", DetectionSeverity.High,
            [1, 4688], ["installutil.exe"], Any: ["/logfile=", "/logtoconsole=false", "/u ", "-u "]),
        new("PE-023", "CMSTP proxy execution", "CMSTP silently installs a connection-manager profile.", DetectionSeverity.High,
            [1, 4688], ["cmstp.exe"], Any: ["/s", "-s", ".inf"]),
        new("PE-024", "Regasm or Regsvcs proxy execution", "A .NET registration utility executes an assembly from a suspicious location.", DetectionSeverity.High,
            [1, 4688], ["regasm.exe", "regsvcs.exe"], Any: [@"\temp\", @"\appdata\", @"\downloads\", @"\\"]),
        new("PE-025", "Odbcconf DLL execution", "Odbcconf invoked REGSVR to load a DLL.", DetectionSeverity.High,
            [1, 4688], ["odbcconf.exe"], Any: ["regsvr", "configdsn"]),
        new("PE-026", "Control panel item execution", "control.exe or rundll32 launched a CPL from a suspicious location.", DetectionSeverity.High,
            [1, 4688], ["control.exe", "rundll32.exe"], Any: [".cpl", @"\temp\", @"\appdata\"]),
        new("PE-027", "Forfiles command execution", "Forfiles spawned a command interpreter, a common proxy execution pattern.", DetectionSeverity.Medium,
            [1, 4688], ["forfiles.exe"], Any: ["/c cmd", "/c powershell"]),
        new("PE-028", "LOLBAS download via desktop utility", "A signed Windows utility was used with a remote URL or download switch.", DetectionSeverity.High,
            [1, 4688], ["desktopimgdownldr.exe", "esentutl.exe", "expand.exe", "extrac32.exe", "makecab.exe"], Any: ["http://", "https://", "/transfer", "/y"]),
        new("PE-029", "Fodhelper/UAC bypass registry", "Registry activity references fodhelper or ms-settings shell-open command UAC bypass.", DetectionSeverity.Critical,
            [1, 13, 4688], Any: ["fodhelper.exe", @"ms-settings\shell\open\command", "delegateexecute"]),
        new("PE-030", "ComputerDefaults/UAC bypass", "Registry activity references ComputerDefaults and ms-settings UAC bypass.", DetectionSeverity.Critical,
            [1, 13, 4688], Any: ["computerdefaults.exe", @"ms-settings\shell\open\command", "delegateexecute"])
    ];
}
