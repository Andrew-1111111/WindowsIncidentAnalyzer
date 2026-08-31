namespace WindowsIncidentAnalyzer.Configuration;

public sealed class DetectionRulesOptions
{
    public BruteForceOptions BruteForce { get; set; } = new();

    public SuspiciousPowerShellOptions SuspiciousPowerShell { get; set; } = new();

    public SuspiciousProcessCreationOptions SuspiciousProcessCreation { get; set; } = new();

    public SuspiciousScheduledTaskOptions SuspiciousScheduledTask { get; set; } = new();

    public NewUserOptions NewUser { get; set; } = new();

    public PrivilegeChangeOptions PrivilegeChange { get; set; } = new();

    public FailedLogonOptions FailedLogon { get; set; } = new();

    public SuccessfulLogonOptions SuccessfulLogon { get; set; } = new();

    public RdpActivityOptions RdpActivity { get; set; } = new();

    public ServiceInstallationOptions ServiceInstallation { get; set; } = new();

    public LogClearingOptions LogClearing { get; set; } = new();

    public KnownThreatSignaturesOptions KnownThreatSignatures { get; set; } = new();

    public SigmaRulesOptions SigmaRules { get; set; } = new();

    public CorrelationOptions Correlation { get; set; } = new();
}

public sealed class BruteForceOptions
{
    public bool Enabled { get; set; } = true;

    public int FailedAttemptsThreshold { get; set; } = 5;

    public int PasswordSprayAccountThreshold { get; set; } = 5;

    public int TimeWindowMinutes { get; set; } = 5;
}

public sealed class SuspiciousPowerShellOptions
{
    public bool Enabled { get; set; } = true;

    public bool DetectEncodedCommand { get; set; } = true;

    public bool DetectHiddenWindow { get; set; } = true;

    public bool DetectExecutionPolicyBypass { get; set; } = true;

    public bool DetectDownloadKeywords { get; set; } = true;

    public int LongBase64Length { get; set; } = 80;
}

public sealed class SuspiciousProcessCreationOptions
{
    public bool Enabled { get; set; } = true;

    public int LongCommandLineLength { get; set; } = 500;

    public List<string> SuspiciousProcessPaths { get; set; } =
    [
        @"\Temp\",
        @"\AppData\Local\Temp\",
        @"\Downloads\",
        @"\Загрузки\",
        @"\Документы\",
        @"\Рабочий стол\"
    ];

    public List<ParentChildRule> SuspiciousParentChild { get; set; } =
    [
        new() { Parent = "winword.exe", Child = "powershell.exe" },
        new() { Parent = "winword.exe", Child = "cmd.exe" },
        new() { Parent = "excel.exe", Child = "powershell.exe" },
        new() { Parent = "excel.exe", Child = "cmd.exe" },
        new() { Parent = "outlook.exe", Child = "powershell.exe" },
        new() { Parent = "outlook.exe", Child = "cmd.exe" },
        new() { Parent = "wmiprvse.exe", Child = "powershell.exe" },
        new() { Parent = "services.exe", Child = "cmd.exe" },
        new() { Parent = "winword.exe", Child = "mshta.exe" },
        new() { Parent = "winword.exe", Child = "wscript.exe" },
        new() { Parent = "excel.exe", Child = "mshta.exe" },
        new() { Parent = "outlook.exe", Child = "rundll32.exe" },
        new() { Parent = "acrord32.exe", Child = "powershell.exe" },
        new() { Parent = "w3wp.exe", Child = "cmd.exe" },
        new() { Parent = "w3wp.exe", Child = "powershell.exe" },
        new() { Parent = "sqlservr.exe", Child = "cmd.exe" },
        new() { Parent = "sqlservr.exe", Child = "powershell.exe" },
        new() { Parent = "spoolsv.exe", Child = "cmd.exe" },
        new() { Parent = "svchost.exe", Child = "whoami.exe" }
    ];
}

public sealed class ParentChildRule
{
    public string Parent { get; set; } = string.Empty;

    public string Child { get; set; } = string.Empty;
}

public sealed class SuspiciousScheduledTaskOptions
{
    public bool Enabled { get; set; } = true;

    public List<string> SuspiciousPaths { get; set; } =
    [
        @"\Temp\",
        @"\AppData\",
        @"\Downloads\",
        @"\Загрузки\",
        @"\Документы\",
        @"\Рабочий стол\"
    ];
}

public sealed class NewUserOptions
{
    public bool Enabled { get; set; } = true;

    public int PrivilegeWindowMinutes { get; set; } = 10;
}

public sealed class PrivilegeChangeOptions
{
    public bool Enabled { get; set; } = true;

    public List<string> PrivilegedGroups { get; set; } =
    [
        "Administrators",
        "Администраторы",
        "Domain Admins",
        "Администраторы домена",
        "Enterprise Admins",
        "Администраторы предприятия",
        "Schema Admins",
        "Администраторы схемы",
        "Backup Operators",
        "Операторы архива",
        "Account Operators",
        "Операторы учета",
        "Remote Desktop Users",
        "Пользователи удаленного рабочего стола"
    ];
}

public sealed class FailedLogonOptions
{
    public bool Enabled { get; set; } = true;

    public int ClusterThreshold { get; set; } = 3;
}

public sealed class SuccessfulLogonOptions
{
    public bool Enabled { get; set; } = true;
}

public sealed class RdpActivityOptions
{
    public bool Enabled { get; set; } = true;
}

public sealed class ServiceInstallationOptions
{
    public bool Enabled { get; set; } = true;
}

public sealed class LogClearingOptions
{
    public bool Enabled { get; set; } = true;
}

public sealed class KnownThreatSignaturesOptions
{
    public bool Enabled { get; set; } = true;
}

public sealed class SigmaRulesOptions
{
    public bool Enabled { get; set; } = true;

    public string RulesPath { get; set; } = "sigma-rules";

    public bool AutoLoadOnStartup { get; set; } = true;

    public bool IncludeExperimental { get; set; }

    public bool IncludeDeprecated { get; set; }

    public bool IncludeUnsupported { get; set; }
}

public sealed class CorrelationOptions
{
    public int CorrelationWindowMinutes { get; set; } = 10;
}
