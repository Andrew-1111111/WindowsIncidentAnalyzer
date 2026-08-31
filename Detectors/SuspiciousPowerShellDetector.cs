using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class SuspiciousPowerShellDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly SuspiciousPowerShellOptions _options = options.Value.SuspiciousPowerShell;

    private static readonly Regex EncodedCommand = new(
        @"(-enc|-encodedcommand|-ec)(\s+|:)\s*(?:['""])?([A-Za-z0-9+/]{20,}={0,2})",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LongBase64 = new(
        @"[A-Za-z0-9+/]{80,}={0,2}",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly string[] HiddenWindow =
    [
        "-w hidden", "-windowstyle hidden", "-window hidden", "-noprofile", " -nop "
    ];

    private static readonly string[] Download =
    [
        "downloadstring", "downloadfile", "invoke-webrequest", "invoke-restmethod",
        "net.webclient", "system.net.webclient", "httpclient", "webrequest",
        "wget ", "curl ", "bitsadmin", "start-bitstransfer", "certutil",
        "invoke-expression", "iex(", "iex ", "start-process", "new-object net.webclient"
    ];

    private static readonly string[] Obfuscation =
    [
        "frombase64string", "tochararray", "char[]", "[char]", "-join",
        "invoke-obfuscation", "encodedcommand", "compress-archive", "decompress",
        "gzipstream", "deflatestream", "reflection.assembly", "load(byte[]"
    ];

    private static readonly string[] Injection =
    [
        "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntunmapviewofsection", "rtlmovememory", "marshal.copy", "getdelegateforfunctionpointer",
        "invoke-reflectivepeinjection", "invoke-shellcode"
    ];

    public override string Name => "SuspiciousPowerShell";

    public override string Description =>
        "Flags PowerShell 4103/4104 and process command lines that contain encoded, hidden, bypass, or download indicators. Matching is textual only; nothing is executed.";

    public override DetectionSeverity Severity => DetectionSeverity.High;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4103, 4104, 4688, 1];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        foreach (var evt in events)
        {
            if (evt.EventId == 1 && !WindowsEventCompatibility.IsSysmonEvent(evt))
            {
                continue;
            }

            var blob = Combine(evt);
            if (string.IsNullOrWhiteSpace(blob))
            {
                continue;
            }

            var reasons = new List<string>();
            string? decodedPreview = null;

            if (_options.DetectEncodedCommand && EncodedCommand.IsMatch(blob))
            {
                reasons.Add("encoded command indicator");
                var match = EncodedCommand.Match(blob);
                decodedPreview = TryDecodeBase64AsText(match.Groups[3].Value);
            }
            else if (_options.DetectEncodedCommand && LongBase64.IsMatch(blob) && blob.Length >= _options.LongBase64Length)
            {
                reasons.Add("unusually long Base64 string");
                decodedPreview = TryDecodeBase64AsText(LongBase64.Match(blob).Value);
            }

            if (_options.DetectHiddenWindow && HiddenWindow.Any(t => blob.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                reasons.Add("hidden window / noprofile indicator");
            }

            if (_options.DetectExecutionPolicyBypass && ContainsBypass(blob))
            {
                reasons.Add("execution policy bypass indicator");
            }

            if (_options.DetectDownloadKeywords && Download.Any(t => blob.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                reasons.Add("download-related keyword");
            }

            if (Obfuscation.Count(t => blob.Contains(t, StringComparison.OrdinalIgnoreCase)) >= 2)
            {
                reasons.Add("script obfuscation or in-memory assembly indicator");
            }

            if (Injection.Any(t => blob.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                reasons.Add("process injection or shellcode indicator");
            }

            if (reasons.Count == 0)
            {
                continue;
            }

            var details = $"indicators={string.Join(",", reasons)}";
            if (!string.IsNullOrEmpty(decodedPreview))
            {
                details += $"; decodedTextPreview={Trim(decodedPreview, 300)}";
            }

            if (!string.IsNullOrEmpty(evt.ScriptBlockHash))
            {
                details += $"; scriptBlockSha256={evt.ScriptBlockHash}";
            }

            yield return CreateFinding(
                "Suspicious PowerShell activity",
                "PowerShell logging or process creation contained defensive detection indicators. The application does not execute or decode this content for launching.",
                reasons.Count >= 2 ? DetectionSeverity.High : DetectionSeverity.Medium,
                evt,
                details: details);
        }
    }

    private static bool ContainsBypass(string blob) =>
        blob.Contains("-ep bypass", StringComparison.OrdinalIgnoreCase) ||
        blob.Contains("-executionpolicy bypass", StringComparison.OrdinalIgnoreCase) ||
        blob.Contains("executionpolicy bypass", StringComparison.OrdinalIgnoreCase) ||
        blob.Contains("-ep unrestricted", StringComparison.OrdinalIgnoreCase);

    private static string Combine(WindowsEvent evt)
    {
        var parts = new[] { evt.CommandLine, evt.ScriptBlock, evt.ParentCommandLine, evt.RawXml };
        return string.Join('\n', parts.Where(p => !string.IsNullOrWhiteSpace(p)));
    }

    /// <summary>
    /// Converts Base64 to Unicode/UTF-8 text for analyst review only. The result is never passed to a shell.
    /// </summary>
    public static string? TryDecodeBase64AsText(string? encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded))
        {
            return null;
        }

        var token = encoded.Trim().Trim('\'', '"');
        token = token.PadRight(token.Length + (4 - token.Length % 4) % 4, '=');
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(token);
        }
        catch (FormatException)
        {
            return null;
        }

        try
        {
            if (bytes.Length >= 2 && bytes.Length % 2 == 0)
            {
                var unicode = Encoding.Unicode.GetString(bytes);
                if (unicode.Any(ch => !char.IsControl(ch) || ch is '\r' or '\n' or '\t'))
                {
                    return unicode;
                }
            }

            return Encoding.UTF8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    private static string Trim(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";
}
