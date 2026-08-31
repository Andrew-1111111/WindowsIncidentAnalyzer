using System.Text;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class EventContextFormatter
{
    public static string FormatSummary(WindowsEvent evt, int maxFieldLength = 500)
    {
        var builder = new StringBuilder(256);
        Append(builder, "eventId", evt.EventId.ToString());
        Append(builder, "log", evt.LogName);
        Append(builder, "timeUtc", evt.TimeCreatedUtc.ToString("yyyy-MM-dd HH:mm:ss"));
        Append(builder, "host", evt.ComputerName);
        Append(builder, "user", evt.TargetUserName ?? evt.User);
        Append(builder, "process", evt.ProcessPath ?? evt.ProcessName);
        Append(builder, "parent", evt.ParentProcessName);
        Append(builder, "cmd", Trim(evt.CommandLine, maxFieldLength));
        Append(builder, "parentCmd", Trim(evt.ParentCommandLine, maxFieldLength));
        Append(builder, "srcIp", evt.SourceIpAddress);
        Append(builder, "dstIp", evt.DestinationIpAddress);
        Append(builder, "script", Trim(evt.ScriptBlock, maxFieldLength));
        return builder.ToString();
    }

    private static void Append(StringBuilder builder, string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        if (builder.Length > 0)
        {
            builder.Append("; ");
        }

        builder.Append(key).Append('=').Append(value);
    }

    private static string? Trim(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }
}
