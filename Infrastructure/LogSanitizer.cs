using System.Text;

namespace WindowsIncidentAnalyzer.Infrastructure;

internal static class LogSanitizer
{
    public static string ForLog(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value.All(static c => c is >= ' ' and <= '~'))
        {
            return value;
        }

        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(ch is >= ' ' and <= '~' ? ch : '?');
        }

        return builder.ToString();
    }
}
