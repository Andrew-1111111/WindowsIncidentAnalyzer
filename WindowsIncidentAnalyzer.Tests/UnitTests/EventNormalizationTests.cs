using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class EventNormalizationTests
{
    private readonly EventXmlParser _parser = new();

    [Fact]
    public void Security4688_MapsParentAndCommandLine()
    {
        var xml = EventXmlFixtures.SecurityEvent(
            4688,
            "2026-08-01T08:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserSid", "S-1-5-21-1000-1000-1000-1105"),
            ("SubjectUserName", "labuser"),
            ("SubjectDomainName", "LAB"),
            ("NewProcessId", "0x1a2"),
            ("NewProcessName", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            ("ProcessId", "0x3e8"),
            ("CommandLine", "powershell.exe -NoProfile -Command Get-Date"),
            ("ParentProcessName", @"C:\Windows\explorer.exe"));

        var evt = _parser.Parse(xml);
        Assert.Equal("powershell.exe", evt.ProcessName);
        Assert.Equal("explorer.exe", evt.ParentProcessName);
        Assert.Equal(0x1a2, evt.ProcessId);
        Assert.Equal(0x3e8, evt.ParentProcessId);
        Assert.Contains("-NoProfile", evt.CommandLine);
        Assert.Equal("labuser", evt.User);
    }

    [Fact]
    public void Security4688_DoesNotUseProcessIdAsParentProcessId()
    {
        var xml = EventXmlFixtures.SecurityEvent(
            4697,
            "2026-08-01T08:00:30.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labuser"),
            ("ProcessId", "0xabc"),
            ("ServiceName", "TestSvc"),
            ("ServiceFileName", @"C:\Windows\System32\cmd.exe"));

        var evt = _parser.Parse(xml);
        Assert.Null(evt.ParentProcessId);
        Assert.Equal(0xabc, evt.ProcessId);
    }

    [Fact]
    public void SysmonNetwork_MapsAddressesAndPorts()
    {
        var xml = EventXmlFixtures.SysmonEvent(
            3,
            "2026-08-01T08:01:00.0000000Z",
            "LAB-HOST-01",
            ("ProcessGuid", "{11111111-2222-3333-4444-555555555555}"),
            ("ProcessId", "4242"),
            ("Image", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            ("User", @"LAB\labuser"),
            ("SourceIp", "10.0.0.8"),
            ("SourcePort", "51515"),
            ("DestinationIp", "10.10.10.10"),
            ("DestinationPort", "443"));

        var evt = _parser.Parse(xml);
        Assert.Equal("10.0.0.8", evt.SourceIpAddress);
        Assert.Equal("10.10.10.10", evt.DestinationIpAddress);
        Assert.Equal(51515, evt.SourcePort);
        Assert.Equal(443, evt.DestinationPort);
        Assert.Equal("powershell.exe", evt.ProcessName);
    }

    [Fact]
    public void SysmonDns_MapsQueryName()
    {
        var xml = EventXmlFixtures.SysmonEvent(
            22,
            "2026-08-01T08:02:00.0000000Z",
            "LAB-HOST-01",
            ("ProcessGuid", "{11111111-2222-3333-4444-555555555555}"),
            ("ProcessId", "4242"),
            ("QueryName", "example.com"),
            ("QueryStatus", "0"),
            ("Image", @"C:\Windows\System32\svchost.exe"));

        var evt = _parser.Parse(xml);
        Assert.Equal("example.com", evt.QueryName);
        Assert.Equal("0", evt.GetProperty("QueryStatus"));
    }

    [Fact]
    public void Describe_IncludesEventSemantics()
    {
        var evt = _parser.Parse(EventXmlFixtures.FailedLogon("2026-08-01T08:03:00.0000000Z", "labuser", "10.0.0.50"));
        var description = EventFieldMapper.Describe(evt);
        Assert.Contains("4625", description);
        Assert.Contains("failed logon", description, StringComparison.OrdinalIgnoreCase);
    }
}
