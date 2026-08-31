using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SuspiciousPowerShellDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly SuspiciousPowerShellDetector _detector = new(Options.Create(new DetectionRulesOptions()));

    [Fact]
    public void Analyze_EncodedCommand_CreatesFinding()
    {
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Write-Output lab"));
        var xml = EventXmlFixtures.PowerShell4104(
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            $"powershell.exe -encodedcommand {encoded}");

        var findings = _detector.Analyze([_parser.Parse(xml)]).ToList();
        Assert.NotEmpty(findings);
        Assert.Contains(findings, f => f.Details?.Contains("encoded command", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public void Analyze_ExecutionPolicyBypass_CreatesFinding()
    {
        var xml = EventXmlFixtures.PowerShell4104(
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            "powershell.exe -ExecutionPolicy Bypass -File C:\\lab\\script.ps1");

        var findings = _detector.Analyze([_parser.Parse(xml)]).ToList();
        Assert.Contains(findings, f => f.Details?.Contains("bypass", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public void TryDecodeBase64AsText_Utf16Le_ReturnsText()
    {
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Get-Date"));
        var decoded = SuspiciousPowerShellDetector.TryDecodeBase64AsText(encoded);
        Assert.Equal("Get-Date", decoded);
    }

    [Fact]
    public void Analyze_BenignScript_NoFinding()
    {
        var xml = EventXmlFixtures.PowerShell4104(
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            "Get-Date | Out-String");
        Assert.Empty(_detector.Analyze([_parser.Parse(xml)]));
    }
}
