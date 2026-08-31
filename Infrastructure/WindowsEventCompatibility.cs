namespace WindowsIncidentAnalyzer.Infrastructure;

using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma;

public readonly record struct SeverityValidationResult(bool Matches, DetectionSeverity Severity);

public static class WindowsEventCompatibility
{
    private static readonly HashSet<string> ContentDrivenDetectors = new(StringComparer.OrdinalIgnoreCase)
    {
        "CredentialAccess",
        "DefenseEvasion",
        "PersistenceAndLolbin",
        "MalwareBehavior",
        "LateralMovementAndDiscovery",
        "SecurityPolicyChange",
        "SigmaRules",
        "SuspiciousPowerShell",
        "SuspiciousProcessCreation",
        "SuspiciousScheduledTask"
    };

    private static readonly HashSet<string> BehavioralElevators = new(StringComparer.OrdinalIgnoreCase)
    {
        "BruteForce",
        "KerberosAndDirectoryAttack",
        "LogClearing",
        "PrivilegeChange",
        "NewUser"
    };

    public static bool IsSysmonEvent(WindowsEvent evt) =>
        evt.ProviderName?.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) == true;

    public static bool IsProcessCreationEvent(WindowsEvent evt) =>
        evt.EventId == 4688 || (evt.EventId == 1 && IsSysmonEvent(evt));

    public static bool IsPowerShellEvent(WindowsEvent evt) =>
        evt.EventId is 4103 or 4104 &&
        (evt.ProviderName?.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) ?? false);

    public static bool MatchesDeclaredEventIds(WindowsEvent evt, IReadOnlyList<int>? eventIds)
    {
        if (eventIds is not { Count: > 0 })
        {
            return true;
        }

        if (!eventIds.Contains(evt.EventId))
        {
            return false;
        }

        return evt.EventId switch
        {
            1 => IsSysmonEvent(evt),
            104 => evt.ProviderName?.Contains("Eventlog", StringComparison.OrdinalIgnoreCase) == true,
            4103 or 4104 => evt.ProviderName?.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) == true,
            _ => true
        };
    }

    public static void ApplyEventClassification(FindingContext context, WindowsEvent? evt)
    {
        if (evt == null)
        {
            context.EventType = null;
            context.CategoryMatchesEvent = null;
            context.SeverityMatchesEvent = null;
            return;
        }

        context.EventType = SigmaLogsourceCatalog.ClassifyEvent(evt);
        context.CategoryMatchesEvent = string.IsNullOrWhiteSpace(context.Category)
            ? null
            : SigmaLogsourceCatalog.CategoryMatchesEvent(evt, context.Category);
    }

    public static SeverityValidationResult ValidateSeverity(
        DetectionSeverity requested,
        WindowsEvent? evt,
        FindingContext context,
        string ruleName)
    {
        if (evt == null || requested <= DetectionSeverity.Medium)
        {
            context.SeverityMatchesEvent = true;
            return new SeverityValidationResult(true, requested);
        }

        if (context.CategoryMatchesEvent == false)
        {
            context.SeverityMatchesEvent = false;
            return new SeverityValidationResult(false, DetectionSeverity.Medium);
        }

        if (IsWeakEvent(evt))
        {
            context.SeverityMatchesEvent = false;
            return new SeverityValidationResult(false, DetectionSeverity.Medium);
        }

        if (IsContentDriven(ruleName) || IsBehavioralElevator(ruleName))
        {
            context.SeverityMatchesEvent = true;
            return new SeverityValidationResult(true, requested);
        }

        var ceiling = GetStructuralSeverityCeiling(evt);
        if (requested > ceiling)
        {
            context.SeverityMatchesEvent = false;
            return new SeverityValidationResult(false, ceiling);
        }

        context.SeverityMatchesEvent = true;
        return new SeverityValidationResult(true, requested);
    }

    public static DetectionSeverity GetStructuralSeverityCeiling(WindowsEvent evt)
    {
        if (evt.EventId == 1 && !IsSysmonEvent(evt))
        {
            return DetectionSeverity.Info;
        }

        if (evt.EventId == 104 &&
            evt.ProviderName?.Contains("Eventlog", StringComparison.OrdinalIgnoreCase) == true)
        {
            return DetectionSeverity.High;
        }

        if (IsPowerShellEvent(evt))
        {
            return DetectionSeverity.Critical;
        }

        if (IsSysmonEvent(evt))
        {
            return DetectionSeverity.Critical;
        }

        return evt.EventId switch
        {
            1102 => DetectionSeverity.Critical,
            1100 or 5013 => DetectionSeverity.High,
            5001 => DetectionSeverity.Critical,
            4662 => DetectionSeverity.Critical,
            4740 or 4768 or 4769 => DetectionSeverity.High,
            4719 or 4739 or 4794 => DetectionSeverity.High,
            4697 or 7045 => DetectionSeverity.High,
            4698 or 4699 or 4702 => DetectionSeverity.High,
            4720 or 4728 or 4732 or 4756 => DetectionSeverity.High,
            4672 => DetectionSeverity.High,
            4625 or 4771 or 4776 => DetectionSeverity.Medium,
            4624 or 4648 => DetectionSeverity.Medium,
            4688 => DetectionSeverity.High,
            _ => DetectionSeverity.High
        };
    }

    private static bool IsWeakEvent(WindowsEvent evt) =>
        evt.EventId == 1 && !IsSysmonEvent(evt);

    private static bool IsContentDriven(string ruleName) =>
        ContentDrivenDetectors.Contains(ruleName);

    private static bool IsBehavioralElevator(string ruleName) =>
        BehavioralElevators.Contains(ruleName);
}
