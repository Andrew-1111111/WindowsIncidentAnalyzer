using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class FindingContextMapperTests
{
    [Fact]
    public void FromEvent_MapsWindowsEventFieldsAndHashes()
    {
        var evt = new WindowsEvent
        {
            Id = 10,
            EventId = 4688,
            EventRecordId = 123456,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            LogName = "Security",
            ComputerName = "HOST01",
            TargetDomainName = "DOMAIN",
            TargetUserName = "alice",
            ProcessName = "whoami.exe",
            ProcessPath = @"C:\Windows\System32\whoami.exe",
            ProcessId = 1000,
            ParentProcessId = 500,
            ParentProcessName = "cmd.exe",
            CommandLine = "whoami /all",
            ParentCommandLine = "cmd.exe",
            SourceIpAddress = "10.0.0.5",
            SourcePort = 445,
            DestinationIpAddress = "10.0.0.10",
            DestinationPort = 139,
            Hashes = "SHA256=ABCDEF,MD5=123456",
            RawXml = "<Event/>",
            Properties =
            {
                ["SubjectUserSid"] = "S-1-5-18",
                ["TargetLogonId"] = "0x3e7",
                ["IntegrityLevel"] = "High"
            }
        };

        var context = FindingContextMapper.FromEvent(evt);

        Assert.Equal(4688, context.EventId);
        Assert.Equal(123456L, context.EventRecordId);
        Assert.Equal("Microsoft-Windows-Security-Auditing", context.Provider);
        Assert.Equal("Security", context.Channel);
        Assert.Equal("HOST01", context.Host);
        Assert.Equal("DOMAIN", context.Domain);
        Assert.Equal("alice", context.User);
        Assert.Equal("S-1-5-18", context.UserSid);
        Assert.Equal("0x3e7", context.LogonId);
        Assert.Equal(1000, context.ProcessId);
        Assert.Equal(500, context.ParentProcessId);
        Assert.Equal("whoami.exe", context.ProcessName);
        Assert.Equal(@"C:\Windows\System32\whoami.exe", context.Image);
        Assert.Equal("whoami /all", context.CommandLine);
        Assert.Equal("cmd.exe", context.ParentImage);
        Assert.Equal("cmd.exe", context.ParentCommandLine);
        Assert.Equal("10.0.0.5", context.SourceIp);
        Assert.Equal(445, context.SourcePort);
        Assert.Equal("10.0.0.10", context.DestinationIp);
        Assert.Equal(139, context.DestinationPort);
        Assert.Equal("ABCDEF", context.Sha256);
        Assert.Equal("123456", context.Md5);
        Assert.Equal("High", context.IntegrityLevel);
        Assert.Equal("<Event/>", context.RawXml);
        Assert.Contains("\"eventId\":4688", context.RawEvent);
    }

    [Fact]
    public void FromEvent_NullEvent_ReturnsEmptyContextWithoutCrash()
    {
        var context = FindingContextMapper.FromEvent(null);

        Assert.Null(context.EventId);
        Assert.Null(context.CommandLine);
        Assert.Empty(context.MatchedFields);
    }

    [Fact]
    public void Serializer_RoundTripsStructuredContext()
    {
        var context = new FindingContext
        {
            RuleId = "CA-001",
            EventId = 4625,
            CommandLine = "powershell.exe",
            MatchedFields = ["Image"],
            MatchedValues = ["powershell.exe"],
            Reason = "Image contains powershell.exe"
        };

        var json = FindingContextSerializer.Serialize(context);
        var restored = FindingContextSerializer.Deserialize(json);

        Assert.Equal("CA-001", restored.RuleId);
        Assert.Equal(4625, restored.EventId);
        Assert.Equal("powershell.exe", restored.CommandLine);
        Assert.Equal(["Image"], restored.MatchedFields);
        Assert.Equal(["powershell.exe"], restored.MatchedValues);
        Assert.Equal("Image contains powershell.exe", restored.Reason);
    }
}
