using System.Text;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Sigma;

public static class SigmaEventMapper
{
    public static IReadOnlyDictionary<string, string> Map(WindowsEvent evt)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void Add(string key, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            fields[key] = value;
        }

        Add("EventID", evt.EventId.ToString());
        Add("Event.System.EventID", evt.EventId.ToString());
        Add("Channel", evt.LogName);
        Add("Provider", evt.ProviderName);
        Add("Computer", evt.ComputerName);
        Add("ComputerName", evt.ComputerName);
        Add("User", evt.User);
        Add("SubjectUserName", evt.GetProperty("SubjectUserName") ?? evt.User);
        Add("TargetUserName", evt.TargetUserName);
        Add("TargetDomainName", evt.TargetDomainName);
        Add("Domain", evt.Domain);
        Add("Image", evt.ProcessPath ?? evt.ProcessName);
        Add("NewProcessName", evt.ProcessPath);
        Add("ProcessName", evt.ProcessName);
        Add("ParentImage", evt.ParentProcessName);
        Add("ParentProcessName", evt.ParentProcessName);
        Add("CommandLine", evt.CommandLine);
        Add("ParentCommandLine", evt.ParentCommandLine);
        Add("ProcessId", evt.ProcessId?.ToString());
        Add("ParentProcessId", evt.ParentProcessId?.ToString());
        Add("ProcessGuid", evt.ProcessGuid);
        Add("ParentProcessGuid", evt.ParentProcessGuid);
        Add("IpAddress", evt.SourceIpAddress);
        Add("SourceIp", evt.SourceIpAddress);
        Add("SourceIpAddress", evt.SourceIpAddress);
        Add("DestinationIp", evt.DestinationIpAddress);
        Add("DestinationIpAddress", evt.DestinationIpAddress);
        Add("DestinationPort", evt.DestinationPort?.ToString());
        Add("SourcePort", evt.SourcePort?.ToString());
        Add("QueryName", evt.QueryName);
        Add("ScriptBlockText", evt.ScriptBlock);
        Add("ScriptBlock", evt.ScriptBlock);
        Add("Hashes", evt.Hashes);
        Add("TaskName", evt.TaskName);
        Add("ServiceName", evt.ServiceName);
        Add("LogonType", evt.LogonType?.ToString());
        Add("WorkstationName", evt.WorkstationName);

        foreach (var (key, value) in evt.Properties)
        {
            Add(key, value);
        }

        var blob = BuildSearchBlob(evt, fields);
        Add("_sigma_blob", blob);
        return fields;
    }

    public static string? ResolveField(IReadOnlyDictionary<string, string> fields, string fieldName)
    {
        if (fields.TryGetValue(fieldName, out var direct))
        {
            return direct;
        }

        if (fieldName.Contains('.', StringComparison.Ordinal))
        {
            var leaf = fieldName.Split('.')[^1];
            if (fields.TryGetValue(leaf, out var leafValue))
            {
                return leafValue;
            }
        }

        return null;
    }

    private static string BuildSearchBlob(WindowsEvent evt, Dictionary<string, string> fields)
    {
        var builder = new StringBuilder();
        builder.AppendLine(evt.RawXml);
        foreach (var value in fields.Values)
        {
            builder.AppendLine(value);
        }

        return builder.ToString();
    }
}
