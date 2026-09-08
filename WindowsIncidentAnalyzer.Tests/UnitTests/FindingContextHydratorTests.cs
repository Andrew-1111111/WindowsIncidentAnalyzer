using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class FindingContextHydratorTests
{
    [Fact]
    public void FillGaps_PopulatesEmptyContextFieldsFromEvent()
    {
        var finding = new SecurityFinding
        {
            Title = "test",
            RelatedEventRowIds = [10],
            Context = new FindingContext
            {
                RuleId = "sigma-1",
                CommandLine = "keep-me"
            }
        };

        var evt = new WindowsEvent
        {
            Id = 10,
            EventId = 4688,
            EventRecordId = 99,
            ComputerName = "HOST1",
            LogName = "Security",
            ProviderName = "Microsoft-Windows-Security-Auditing",
            TimeCreatedUtc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
            TargetUserName = "alice",
            ProcessName = "cmd.exe",
            ProcessPath = @"C:\Windows\System32\cmd.exe",
            CommandLine = "should-not-overwrite",
            SourceIpAddress = "10.0.0.8"
        };

        FindingContextHydrator.FillGaps(finding, evt);

        Assert.Equal("sigma-1", finding.Context.RuleId);
        Assert.Equal("keep-me", finding.Context.CommandLine);
        Assert.Equal(4688, finding.Context.EventId);
        Assert.Equal(99, finding.Context.EventRecordId);
        Assert.Equal("HOST1", finding.Context.Host);
        Assert.Equal("alice", finding.Context.User);
        Assert.Equal("cmd.exe", finding.Context.ProcessName);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", finding.Context.Image);
        Assert.Equal("10.0.0.8", finding.Context.SourceIp);
        Assert.Equal("HOST1", finding.ComputerName);
        Assert.Equal("alice", finding.User);
    }
}
