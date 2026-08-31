using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class EventXmlParserTests
{
    private readonly EventXmlParser _parser = new();

    [Fact]
    public void Parse_FailedLogon_ExtractsUserAndIp()
    {
        var xml = EventXmlFixtures.FailedLogon("2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50");
        var evt = _parser.Parse(xml);

        Assert.Equal(4625, evt.EventId);
        Assert.Equal("Security", evt.LogName);
        Assert.Equal("LAB-HOST-01", evt.ComputerName);
        Assert.Equal("labuser", evt.TargetUserName);
        Assert.Equal("labuser", evt.User);
        Assert.Equal("10.0.0.50", evt.SourceIpAddress);
        Assert.Equal("LAB", evt.TargetDomainName);
        Assert.False(string.IsNullOrWhiteSpace(evt.RawXml));
        Assert.Equal("0xc000006d", evt.GetProperty("Status"));
    }

    [Fact]
    public void Parse_MissingOptionalFields_DoesNotThrow()
    {
        var xml = """
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
              <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" />
                <EventID>9999</EventID>
                <EventRecordID>123456</EventRecordID>
                <TimeCreated SystemTime="2026-08-01T00:00:00.0000000Z" />
                <Channel>Security</Channel>
                <Computer>LAB-HOST-01</Computer>
              </System>
              <EventData />
            </Event>
            """;

        var evt = _parser.Parse(xml);
        Assert.Equal(9999, evt.EventId);
        Assert.Equal(123456, evt.EventRecordId);
        Assert.Null(evt.User);
        Assert.Null(evt.SourceIpAddress);
        Assert.Null(evt.ProcessName);
    }

    [Fact]
    public void Parse_CorruptXml_ThrowsInvalidOperation()
    {
        Assert.Throws<InvalidOperationException>(() => _parser.Parse("<not-xml"));
    }

    [Fact]
    public void Parse_SysmonProcessCreate_MapsImageAndHashes()
    {
        var xml = EventXmlFixtures.SysmonEvent(
            1,
            "2026-08-01T12:01:00.0000000Z",
            "LAB-HOST-01",
            ("RuleName", "process"),
            ("UtcTime", "2026-08-01 12:01:00.000"),
            ("ProcessGuid", "{11111111-2222-3333-4444-555555555555}"),
            ("ProcessId", "4242"),
            ("Image", @"C:\Users\labuser\Downloads\tool.exe"),
            ("CommandLine", @"C:\Users\labuser\Downloads\tool.exe -h"),
            ("ParentProcessGuid", "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"),
            ("ParentProcessId", "1000"),
            ("ParentImage", @"C:\Windows\explorer.exe"),
            ("ParentCommandLine", @"C:\Windows\explorer.exe"),
            ("User", @"LAB\labuser"),
            ("Hashes", "SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

        var evt = _parser.Parse(xml);
        Assert.Equal(1, evt.EventId);
        Assert.Equal("tool.exe", evt.ProcessName);
        Assert.Equal(@"C:\Users\labuser\Downloads\tool.exe", evt.ProcessPath);
        Assert.Equal("explorer.exe", evt.ParentProcessName);
        Assert.Equal(4242, evt.ProcessId);
        Assert.Equal(1000, evt.ParentProcessId);
        Assert.Equal("labuser", evt.User);
        Assert.Equal("LAB", evt.Domain);
        Assert.Contains("SHA256=", evt.Hashes);
    }

    [Fact]
    public void Parse_PowerShellScriptBlock_ComputesHash()
    {
        var xml = EventXmlFixtures.PowerShell4104(
            "2026-08-01T12:02:00.0000000Z",
            "LAB-HOST-01",
            "Write-Output 'lab-script'");

        var evt = _parser.Parse(xml);
        Assert.Equal(4104, evt.EventId);
        Assert.Equal("Write-Output 'lab-script'", evt.ScriptBlock);
        Assert.False(string.IsNullOrWhiteSpace(evt.ScriptBlockHash));
        Assert.Equal(64, evt.ScriptBlockHash!.Length);
    }
}
