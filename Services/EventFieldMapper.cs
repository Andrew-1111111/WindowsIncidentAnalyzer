using System.Globalization;
using System.Text;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public static class EventFieldMapper
{
    public static void Apply(WindowsEvent evt)
    {
        var p = evt.Properties;
        var provider = evt.ProviderName ?? string.Empty;
        var isSysmon = provider.Contains("Sysmon", StringComparison.OrdinalIgnoreCase);
        var isPowerShell = provider.Contains("PowerShell", StringComparison.OrdinalIgnoreCase);

        evt.TargetUserName = First(p, "TargetUserName", "TargetUser", "NewAccountName");
        evt.TargetDomainName = First(p, "TargetDomainName", "TargetDomain", "TargetAccountDomain");
        evt.WorkstationName = First(p, "WorkstationName", "Workstation", "ComputerName");
        evt.SourceIpAddress = First(p, "IpAddress", "SourceIp", "SourceAddress", "ClientAddress");
        evt.DestinationIpAddress = First(p, "DestAddress", "DestinationIp", "DestinationAddress");
        evt.CommandLine = First(p, "CommandLine");
        evt.ParentCommandLine = First(p, "ParentCommandLine");
        evt.Hashes = First(p, "Hashes", "Hash");
        evt.ProcessGuid = First(p, "ProcessGuid", "ProcessGUID");
        evt.ParentProcessGuid = First(p, "ParentProcessGuid", "ParentProcessGUID");
        evt.QueryName = First(p, "QueryName", "Query");
        evt.TaskName = First(p, "TaskName", "TaskContentName");
        evt.ServiceName = First(p, "ServiceName", "ServiceNameName");
        evt.LogonType = EventXmlParser.ParseInt(First(p, "LogonType"));
        evt.SourcePort = EventXmlParser.ParseInt(First(p, "SourcePort", "IpPort"));
        evt.DestinationPort = EventXmlParser.ParseInt(First(p, "DestinationPort", "DestPort"));

        if (isSysmon)
        {
            ApplySysmon(evt, p);
        }
        else if (isPowerShell)
        {
            ApplyPowerShell(evt, p);
        }
        else
        {
            ApplySecurity(evt, p);
        }

        evt.User ??= evt.TargetUserName ?? First(p, "SubjectUserName", "User", "AccountName");
        evt.Domain ??= evt.TargetDomainName ?? First(p, "SubjectDomainName", "Domain", "AccountDomain");

        if (evt.ProcessName == null)
        {
            var image = First(p, "NewProcessName", "ProcessName", "Image", "Application");
            evt.ProcessPath = image;
            evt.ProcessName = PathName.FileName(image) ?? image;
        }

        if (evt.ParentProcessName == null)
        {
            var parent = First(p, "ParentProcessName", "ParentImage");
            evt.ParentProcessName = PathName.FileName(parent) ?? parent;
        }

        evt.ProcessId ??= ParsePid(First(p, "NewProcessId", "ProcessId", "ProcessID"));
        evt.ParentProcessId ??= ParsePid(First(p, "ParentProcessId", "ParentProcessID"));

        if (evt.EventId == 4688)
        {
            evt.ProcessId = ParsePid(First(p, "NewProcessId"));
            evt.ParentProcessId = ParsePid(First(p, "ProcessId"));
        }

        ExtractScriptBlock(evt, p);

        if (!string.IsNullOrEmpty(evt.ScriptBlock) && string.IsNullOrEmpty(evt.ScriptBlockHash))
        {
            evt.ScriptBlockHash = TextHash.Sha256Hex(evt.ScriptBlock);
        }
    }

    private static void ApplySecurity(WindowsEvent evt, Dictionary<string, string> p)
    {
        switch (evt.EventId)
        {
            case 4624:
            case 4625:
            case 4634:
            case 4647:
            case 4648:
            case 4776:
                evt.User = First(p, "TargetUserName", "SubjectUserName");
                evt.Domain = First(p, "TargetDomainName", "SubjectDomainName");
                evt.SourceIpAddress ??= First(p, "IpAddress");
                evt.ProcessPath = First(p, "ProcessName");
                evt.ProcessName = PathName.FileName(evt.ProcessPath) ?? evt.ProcessPath;
                evt.ProcessId = ParsePid(First(p, "ProcessId"));
                break;
            case 4672:
                evt.User = First(p, "SubjectUserName");
                evt.Domain = First(p, "SubjectDomainName");
                break;
            case 4688:
                evt.ProcessPath = First(p, "NewProcessName");
                evt.ProcessName = PathName.FileName(evt.ProcessPath) ?? evt.ProcessPath;
                evt.ParentProcessName = PathName.FileName(First(p, "ParentProcessName")) ?? First(p, "ParentProcessName");
                evt.CommandLine = First(p, "CommandLine");
                evt.User = First(p, "SubjectUserName");
                evt.Domain = First(p, "SubjectDomainName");
                evt.TargetUserName = First(p, "TargetUserName");
                break;
            case 4689:
                evt.ProcessPath = First(p, "ProcessName");
                evt.ProcessName = PathName.FileName(evt.ProcessPath) ?? evt.ProcessPath;
                evt.User = First(p, "SubjectUserName");
                break;
            case 4697:
            case 7045:
                evt.ServiceName = First(p, "ServiceName");
                evt.ProcessPath = First(p, "ServiceFileName", "ImagePath");
                evt.ProcessName = PathName.FileName(evt.ProcessPath) ?? evt.ProcessPath;
                evt.User = First(p, "SubjectUserName", "AccountName");
                evt.CommandLine = First(p, "ServiceFileName", "ImagePath");
                break;
            case 4698:
            case 4699:
            case 4702:
                evt.TaskName = First(p, "TaskName");
                evt.User = First(p, "SubjectUserName");
                evt.CommandLine = First(p, "TaskContent", "TaskContentNew");
                break;
            case 4720:
            case 4722:
            case 4723:
            case 4724:
            case 4725:
            case 4726:
            case 4728:
            case 4732:
            case 4756:
                evt.User = First(p, "SubjectUserName");
                evt.Domain = First(p, "SubjectDomainName");
                evt.TargetUserName = First(p, "TargetUserName", "MemberName", "TargetSid");
                evt.TargetDomainName = First(p, "TargetDomainName");
                break;
            case 1102:
                evt.User = First(p, "SubjectUserName", "User");
                evt.Domain = First(p, "SubjectDomainName");
                break;
        }
    }

    private static void ApplySysmon(WindowsEvent evt, Dictionary<string, string> p)
    {
        evt.User = First(p, "User");
        evt.ProcessPath = First(p, "Image");
        evt.ProcessName = PathName.FileName(evt.ProcessPath) ?? evt.ProcessPath;
        evt.ParentProcessName = PathName.FileName(First(p, "ParentImage")) ?? First(p, "ParentImage");
        evt.CommandLine = First(p, "CommandLine");
        evt.ParentCommandLine = First(p, "ParentCommandLine");
        evt.ProcessId = ParsePid(First(p, "ProcessId", "ProcessID"));
        evt.ParentProcessId = ParsePid(First(p, "ParentProcessId", "ParentProcessID"));
        evt.Hashes = First(p, "Hashes", "Hash");
        evt.ProcessGuid = First(p, "ProcessGuid", "ProcessGUID");
        evt.ParentProcessGuid = First(p, "ParentProcessGuid", "ParentProcessGUID");

        switch (evt.EventId)
        {
            case 3:
                evt.SourceIpAddress = First(p, "SourceIp", "SourceAddress");
                evt.DestinationIpAddress = First(p, "DestinationIp", "DestinationAddress");
                evt.SourcePort = EventXmlParser.ParseInt(First(p, "SourcePort"));
                evt.DestinationPort = EventXmlParser.ParseInt(First(p, "DestinationPort"));
                break;
            case 11:
                evt.ProcessPath = First(p, "TargetFilename") ?? evt.ProcessPath;
                break;
            case 13:
                evt.CommandLine = First(p, "TargetObject") ?? evt.CommandLine;
                break;
            case 22:
                evt.QueryName = First(p, "QueryName");
                break;
        }

        SplitUserDomain(evt);
    }

    private static void ApplyPowerShell(WindowsEvent evt, Dictionary<string, string> p)
    {
        ExtractScriptBlock(evt, p);
        if (p.TryGetValue("ContextInfo", out var context) && !string.IsNullOrWhiteSpace(context))
        {
            var parsed = ParseContextInfo(context);
            foreach (var pair in parsed)
            {
                evt.Properties.TryAdd(pair.Key, pair.Value);
            }

            if (parsed.TryGetValue("User", out var user) ||
                parsed.TryGetValue("Пользователь", out user))
            {
                evt.User = user;
                SplitUserDomain(evt);
            }

            if (parsed.TryGetValue("Host Application", out var hostApp) ||
                parsed.TryGetValue("Хост-приложение", out hostApp) ||
                parsed.TryGetValue("Приложение узла", out hostApp))
            {
                evt.ProcessPath = hostApp;
                evt.ProcessName = PathName.FileName(hostApp) ?? hostApp;
                evt.CommandLine ??= hostApp;
            }
        }

        evt.User ??= First(p, "UserId", "User");
        if (string.IsNullOrEmpty(evt.ProcessName))
        {
            evt.ProcessName = "powershell.exe";
        }
    }

    private static void ExtractScriptBlock(WindowsEvent evt, Dictionary<string, string> p)
    {
        var script = First(p, "ScriptBlockText", "Payload", "ScriptBlock");
        if (!string.IsNullOrEmpty(script))
        {
            evt.ScriptBlock = script;
        }
    }

    public static Dictionary<string, string> ParseContextInfo(string context)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StringReader(context);
        while (reader.ReadLine() is { } line)
        {
            var idx = line.IndexOf('=');
            if (idx <= 0)
            {
                continue;
            }

            var key = line[..idx].Trim();
            var value = line[(idx + 1)..].Trim();
            if (key.Length > 0 && value.Length > 0)
            {
                result[key] = value;
            }
        }

        return result;
    }

    private static void SplitUserDomain(WindowsEvent evt)
    {
        if (string.IsNullOrEmpty(evt.User) || evt.User.IndexOf('\\') < 0)
        {
            return;
        }

        var parts = evt.User.Split('\\', 2);
        evt.Domain ??= parts[0];
        evt.User = parts[1];
    }

    private static string? First(Dictionary<string, string> properties, params string[] names)
    {
        foreach (var name in names)
        {
            if (properties.TryGetValue(name, out var value))
            {
                var cleaned = NullableText.Clean(value);
                if (cleaned != null)
                {
                    return cleaned;
                }
            }
        }

        return null;
    }

    private static int? ParsePid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var token = value.Trim();
        if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (int.TryParse(token.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            {
                return hex;
            }
        }

        if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid))
        {
            return pid;
        }

        return null;
    }

    public static string Describe(WindowsEvent evt)
    {
        var sb = new StringBuilder();
        sb.Append(evt.ProviderName ?? evt.LogName ?? "Event");
        sb.Append(" / ").Append(evt.EventId);
        switch (evt.EventId)
        {
            case 4624:
                sb.Append(" successful logon");
                if (evt.LogonType is { } lt)
                {
                    sb.Append(" type ").Append(lt);
                }

                break;
            case 4625:
                sb.Append(" failed logon");
                break;
            case 4634:
            case 4647:
                sb.Append(" logoff");
                break;
            case 4648:
                sb.Append(" explicit credentials logon");
                break;
            case 4672:
                sb.Append(" special privileges assigned");
                break;
            case 4688:
            case 1 when IsSysmon(evt):
                sb.Append(" process created");
                break;
            case 4689:
            case 5 when IsSysmon(evt):
                sb.Append(" process terminated");
                break;
            case 4697:
                sb.Append(" service installed");
                break;
            case 4698:
                sb.Append(" scheduled task created");
                break;
            case 4702:
                sb.Append(" scheduled task updated");
                break;
            case 4699:
                sb.Append(" scheduled task deleted");
                break;
            case 4720:
                sb.Append(" user account created");
                break;
            case 4728:
            case 4732:
                sb.Append(" group membership change");
                break;
            case 1102:
                sb.Append(" security log cleared");
                break;
            case 4103:
                sb.Append(" PowerShell module logging");
                break;
            case 4104:
                sb.Append(" PowerShell script block");
                break;
            case 3 when IsSysmon(evt):
                sb.Append(" network connection");
                break;
            case 22 when IsSysmon(evt):
                sb.Append(" DNS query");
                break;
            default:
                sb.Append(" event");
                break;
        }

        if (!string.IsNullOrEmpty(evt.User))
        {
            sb.Append(" user=").Append(evt.User);
        }

        if (!string.IsNullOrEmpty(evt.ProcessName))
        {
            sb.Append(" proc=").Append(evt.ProcessName);
        }

        if (!string.IsNullOrEmpty(evt.SourceIpAddress))
        {
            sb.Append(" ip=").Append(evt.SourceIpAddress);
        }

        return sb.ToString();
    }

    private static bool IsSysmon(WindowsEvent evt) =>
        evt.ProviderName?.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) == true;
}
