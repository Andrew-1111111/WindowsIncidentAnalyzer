using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Sigma;

public static class SigmaLogsourceCatalog
{
    private static readonly Dictionary<string, int[]> CategoryEventIds = new(StringComparer.OrdinalIgnoreCase)
    {
        ["process_creation"] = [1, 4688],
        ["process_termination"] = [5, 4689],
        ["network_connection"] = [3],
        ["dns_query"] = [22],
        ["registry_event"] = [12, 13, 14],
        ["registry_add"] = [12],
        ["registry_delete"] = [12],
        ["registry_set"] = [13],
        ["registry_rename"] = [14],
        ["file_event"] = [11],
        ["file_change"] = [2],
        ["file_delete"] = [23, 26],
        ["image_load"] = [7],
        ["driver_load"] = [6],
        ["create_remote_thread"] = [8],
        ["pipe_created"] = [17, 18],
        ["ps_script"] = [4104, 4103],
        ["ps_module"] = [4103],
        ["ps_classic_start"] = [400, 600],
        ["service_start"] = [7036],
        ["firewall_as"] = [2004, 2005, 2006, 2009],
        ["authentication"] = [4624, 4625, 4648, 4771, 4776],
        ["account_management"] = [4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756],
        ["privilege_escalation"] = [4672, 4673, 4674],
        ["log_clearing"] = [104, 1102],
        ["task_scheduler"] = [4698, 4699, 4700, 4701, 4702],
        ["service_installation"] = [4697, 7045],
        ["wmi_event"] = [5857, 5858, 5859, 5860, 5861],
        ["raw_access_thread"] = [9],
        ["clipboard_capture"] = [24],
        ["file_access"] = [25]
    };

    private static readonly HashSet<int> SysmonEventIds =
    [
        1, 2, 3, 5, 6, 7, 8, 9, 11, 12, 13, 14, 17, 18, 22, 23, 24, 25, 26
    ];

    private static readonly Dictionary<string, string[]> ServiceLogNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["security"] = ["Security", "Безопасность"],
        ["system"] = ["System", "Система"],
        ["application"] = ["Application", "Приложение"],
        ["powershell"] = ["Microsoft-Windows-PowerShell/Operational"],
        ["sysmon"] = ["Microsoft-Windows-Sysmon/Operational"]
    };

    public static IReadOnlyList<int> ResolveEventIds(SigmaLogsource logsource)
    {
        var ids = new HashSet<int>();
        if (!string.IsNullOrWhiteSpace(logsource.Category) &&
            CategoryEventIds.TryGetValue(logsource.Category, out var categoryIds))
        {
            foreach (var id in categoryIds)
            {
                ids.Add(id);
            }
        }

        if (!string.IsNullOrWhiteSpace(logsource.Service) &&
            ServiceLogNames.TryGetValue(logsource.Service, out var logs))
        {
            _ = logs;
        }

        return ids.Count == 0 ? [] : ids.OrderBy(x => x).ToArray();
    }

    public static bool MatchesEvent(SigmaRule rule, WindowsEvent evt)
    {
        var logsource = rule.Logsource;
        if (!string.IsNullOrWhiteSpace(logsource.Product) &&
            !logsource.Product.Equals("windows", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(logsource.Service) &&
            ServiceLogNames.TryGetValue(logsource.Service, out var expectedLogs))
        {
            var logName = evt.LogName ?? string.Empty;
            var provider = evt.ProviderName ?? string.Empty;
            var serviceMatch = expectedLogs.Any(log =>
                logName.Contains(log, StringComparison.OrdinalIgnoreCase) ||
                provider.Contains(log, StringComparison.OrdinalIgnoreCase) ||
                (logsource.Service!.Equals("sysmon", StringComparison.OrdinalIgnoreCase) &&
                 IsSysmonProvider(evt)));
            if (!serviceMatch)
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(logsource.Category) &&
            !CategoryMatchesEvent(evt, logsource.Category))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Returns the Sigma logsource category that best matches the actual Windows event.
    /// </summary>
    public static string? ClassifyEvent(WindowsEvent evt)
    {
        foreach (var (category, _) in CategoryEventIds)
        {
            if (CategoryMatchesEvent(evt, category))
            {
                return category;
            }
        }

        return null;
    }

    /// <summary>
    /// Checks whether a Sigma category or detector category aligns with the actual event.
    /// Unknown categories (built-in detector names) are treated as behavioral and always match.
    /// </summary>
    public static bool CategoryMatchesEvent(WindowsEvent evt, string? category)
    {
        if (string.IsNullOrWhiteSpace(category))
        {
            return true;
        }

        if (!CategoryEventIds.TryGetValue(category, out var allowedIds))
        {
            return true;
        }

        return EventSatisfiesCategory(evt, allowedIds);
    }

    public static IReadOnlyList<int> AggregateEventIds(IEnumerable<SigmaRule> rules)
    {
        var ids = new HashSet<int>();
        foreach (var rule in rules)
        {
            foreach (var id in rule.RelevantEventIds)
            {
                ids.Add(id);
            }
        }

        return ids.Count == 0 ? [] : ids.OrderBy(x => x).ToArray();
    }

    private static bool EventSatisfiesCategory(WindowsEvent evt, int[] allowedIds)
    {
        if (!allowedIds.Contains(evt.EventId))
        {
            return false;
        }

        if (SysmonEventIds.Contains(evt.EventId) && !IsSysmonProvider(evt))
        {
            return false;
        }

        if (evt.EventId == 104 &&
            !(evt.ProviderName?.Contains("Eventlog", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return false;
        }

        if (evt.EventId is 4103 or 4104 &&
            !(evt.ProviderName?.Contains("PowerShell", StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return false;
        }

        return true;
    }

    private static bool IsSysmonProvider(WindowsEvent evt) =>
        evt.ProviderName?.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) == true;
}
