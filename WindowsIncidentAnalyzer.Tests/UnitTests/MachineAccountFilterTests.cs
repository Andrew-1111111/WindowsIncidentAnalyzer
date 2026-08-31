using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class MachineAccountFilterTests
{
    private readonly EventXmlParser _parser = new();
    private readonly SuccessfulLogonDetector _detector = new(Options.Create(new DetectionRulesOptions()));

    [Theory]
    [InlineData("labuser", "S-1-5-21-1000-1000-1000-1105", true)]
    [InlineData("SYSTEM", "S-1-5-18", false)]
    [InlineData("СИСТЕМА", "S-1-5-18", false)]
    [InlineData("NT AUTHORITY\\СИСТЕМА", "S-1-5-18", false)]
    [InlineData("АНОНИМНЫЙ ВХОД", "S-1-5-7", false)]
    [InlineData("ЛОКАЛЬНАЯ СЛУЖБА", "S-1-5-19", false)]
    [InlineData("СЕТЕВАЯ СЛУЖБА", "S-1-5-20", false)]
    [InlineData("LAB-HOST-01$", "S-1-5-21-1000-1000-1000-1000", false)]
    public void SuccessfulLogon_SkipsLocalizedAndMachineAccounts(string user, string sid, bool expectFinding)
    {
        var evt = _parser.Parse(EventXmlFixtures.SuccessfulLogon(
            "2026-08-01T12:00:00.0000000Z", user, "10.0.0.50", targetSid: sid));
        var findings = _detector.Analyze([evt]).ToList();
        Assert.Equal(expectFinding, findings.Count > 0);
    }
}
