using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class CredentialAccessDetector(IOptions<DetectionRulesOptions> options) : SignatureRuleBase
{
    private readonly KnownThreatSignaturesOptions _options = options.Value.KnownThreatSignatures;

    public override string Name => "CredentialAccess";
    public override string Description => "Detects credential dumping, LSASS access, SAM/SECURITY hive extraction, and NTDS theft.";
    public override DetectionSeverity Severity => DetectionSeverity.High;
    public override bool IsEnabled => _options.Enabled;

    protected override IReadOnlyList<DetectionSignature> Signatures { get; } =
    [
        new("CA-001", "LSASS memory access", "A process opened LSASS with access commonly used for credential dumping.", DetectionSeverity.High,
            [10], Any: [@"\lsass.exe"], Provider: "Sysmon"),
        new("CA-002", "ProcDump targeting LSASS", "ProcDump command line targets LSASS.", DetectionSeverity.Critical,
            [1, 4688], ["procdump.exe", "procdump64.exe"], Any: ["lsass"]),
        new("CA-003", "Comsvcs MiniDump targeting LSASS", "rundll32 invoked comsvcs MiniDump, a common LSASS dumping technique.", DetectionSeverity.Critical,
            [1, 4688], ["rundll32.exe"], All: ["comsvcs.dll", "minidump"]),
        new("CA-004", "Credential dumping tool indicators", "Command or script contains a known credential-dumping tool or module indicator.", DetectionSeverity.Critical,
            [1, 4688, 4103, 4104], Any:
            ["mimikatz", "sekurlsa::", "logonpasswords", "lsadump::", "nanodump", "handlekatz", "pypykatz", "safetykatz", "sharpdump", "dumpert", "outflank-dumpert"]),
        new("CA-005", "PowerShell credential dumping", "PowerShell content contains credential-dumping or LSASS dump indicators.", DetectionSeverity.Critical,
            [4103, 4104, 1, 4688], Any:
            ["invoke-mimikatz", "out-minidump", "invoke-ninjacopy", "get-keystrokes", "get-gpppassword", "invoke-credentialphish"]),
        new("CA-006", "SAM registry hive export", "Registry save/export targets SAM, SYSTEM, or SECURITY hives.", DetectionSeverity.Critical,
            [1, 4688], ["reg.exe", "regedit.exe"], Any:
            [@"save hklm\sam", @"save hklm\system", @"save hklm\security", @"export hklm\sam"]),
        new("CA-007", "NTDS IFM extraction", "NTDSUtil creates installation media or exposes NTDS.dit.", DetectionSeverity.Critical,
            [1, 4688], ["ntdsutil.exe"], Any: ["ifm", "create full", "activate instance ntds"]),
        new("CA-008", "NTDS database extraction", "A database utility references NTDS.dit.", DetectionSeverity.Critical,
            [1, 4688], ["esentutl.exe", "esentutl64.exe"], Any: ["ntds.dit"]),
        new("CA-009", "Volume shadow copy for credential theft", "A shadow copy command appears alongside NTDS/SAM extraction indicators.", DetectionSeverity.High,
            [1, 4688], ["vssadmin.exe", "wmic.exe", "diskshadow.exe"], Any: ["create shadow", "shadowcopy call create", "ntds", @"\sam"]),
        new("CA-010", "Credential Manager access", "A command enumerates or retrieves stored Windows credentials.", DetectionSeverity.Medium,
            [1, 4688], Any: ["cmdkey /list", "vaultcmd /list", "vaultcmd /listcreds", "get-storedcredential"]),
        new("CA-011", "DPAPI credential collection", "Command or script contains DPAPI credential collection indicators.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any: ["sekurlsa::dpapi", "dpapi::masterkey", "sharpdpapi", "mimikatz dpapi", @"\microsoft\credentials"]),
        new("CA-012", "Browser credential collection", "Known browser credential database or extraction tool was referenced.", DetectionSeverity.High,
            [1, 4688, 4103, 4104], Any:
            ["login data", "cookies.sqlite", "logins.json", "lazagne", "sharpchrome", "hackbrowserdata"]),
        new("CA-013", "DCSync indicators", "Command or script contains DCSync credential replication indicators.", DetectionSeverity.Critical,
            [1, 4688, 4103, 4104], Any: ["lsadump::dcsync", "replicating directory changes all", "get-adreplaccount"]),
        new("CA-014", "Kerberos ticket theft or forging", "Command or script contains Kerberos ticket extraction/forging indicators.", DetectionSeverity.Critical,
            [1, 4688, 4103, 4104], Any:
            ["kerberos::list", "kerberos::ptt", "kerberos::golden", "kerberos::silver", "rubeus", "asktgt", "asktgs", "kerberoast", "asreproast"]),
        new("CA-015", "Sensitive registry object access", "Object access targets SAM, SECURITY, or NTDS credential material.", DetectionSeverity.High,
            [4656, 4663], Any: [@"\sam", @"\security", "ntds.dit"])
    ];
}
