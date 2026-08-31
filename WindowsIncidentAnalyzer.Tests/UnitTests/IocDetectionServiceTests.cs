using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class IocDetectionServiceTests
{
    private readonly EventXmlParser _parser = new();
    private readonly IocDetectionService _service = new(
        null!,
        null!,
        Options.Create(new AnalyzerOptions()),
        NullLogger<IocDetectionService>.Instance);

    [Fact]
    public void Scan_MatchesIpAndFilename()
    {
        var evt = _parser.Parse(EventXmlFixtures.SysmonEvent(
            3,
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            ("Image", @"C:\Tools\mimikatz.exe"),
            ("User", @"LAB\labuser"),
            ("SourceIp", "10.0.0.8"),
            ("DestinationIp", "10.10.10.10"),
            ("DestinationPort", "443"),
            ("ProcessId", "100")));

        var iocs = new[]
        {
            new Ioc { Type = "ip", Value = "10.10.10.10" },
            new Ioc { Type = "filename", Value = "mimikatz.exe" },
            new Ioc { Type = "domain", Value = "not-present.example" }
        };

        var service = _service;
        var matches = service.Scan([evt], iocs);
        Assert.Equal(2, matches.Count);
        Assert.Contains(matches, m => m.IocType == "ip" && m.IocValue == "10.10.10.10");
        Assert.Contains(matches, m => m.IocType == "filename");
    }

    [Fact]
    public void TryMatch_Hash_IsCaseInsensitive()
    {
        var evt = new WindowsEvent
        {
            EventId = 1,
            Hashes = "SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            TimeCreatedUtc = DateTime.UtcNow
        };
        var ioc = new Ioc { Type = "sha256", Value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
        Assert.True(IocDetectionService.TryMatch(evt, ioc, out var field));
        Assert.Equal("Hashes", field);
    }
}
