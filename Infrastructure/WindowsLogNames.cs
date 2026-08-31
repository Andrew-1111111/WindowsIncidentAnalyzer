namespace WindowsIncidentAnalyzer.Infrastructure;

public static class WindowsLogNames
{
    public const string Security = "Security";
    public const string System = "System";
    public const string Application = "Application";
    public const string Sysmon = "Microsoft-Windows-Sysmon/Operational";
    public const string PowerShell = "Microsoft-Windows-PowerShell/Operational";

    private static readonly Dictionary<string, string> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Security"] = Security,
        ["Безопасность"] = Security,
        ["System"] = System,
        ["Система"] = System,
        ["Application"] = Application,
        ["Приложение"] = Application,
        ["Sysmon"] = Sysmon,
        ["PowerShell"] = PowerShell,
        ["PS"] = PowerShell
    };

    public static string Resolve(string? alias)
    {
        if (string.IsNullOrWhiteSpace(alias))
        {
            return Security;
        }

        var trimmed = alias.Trim();
        return Aliases.TryGetValue(trimmed, out var resolved) ? resolved : trimmed;
    }

    public static IReadOnlyList<string> DefaultCollectionLogs { get; } =
    [
        Security,
        System,
        Application,
        PowerShell,
        Sysmon
    ];
}
