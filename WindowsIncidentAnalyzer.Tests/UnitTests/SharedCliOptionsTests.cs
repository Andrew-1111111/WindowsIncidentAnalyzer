using System.CommandLine;
using WindowsIncidentAnalyzer.Commands;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SharedCliOptionsTests
{
    private static ParseResult Parse(params string[] args)
    {
        var root = new RootCommand();
        root.Options.Add(SharedCliOptions.Hours);
        root.Options.Add(SharedCliOptions.From);
        root.Options.Add(SharedCliOptions.To);
        root.Options.Add(SharedCliOptions.Date);
        root.Options.Add(SharedCliOptions.EventId);
        root.Options.Add(SharedCliOptions.User);
        root.Options.Add(SharedCliOptions.Ip);
        root.Options.Add(SharedCliOptions.Process);
        root.Options.Add(SharedCliOptions.Keyword);
        root.Options.Add(SharedCliOptions.Limit);
        return root.Parse(args);
    }

    private static AnalyzerOptions Analyzer() => new()
    {
        Collection = new CollectionOptions
        {
            DefaultHours = 24,
            DefaultLimit = 5000
        }
    };

    [Fact]
    public void BuildFilter_ParsesEventIdsUserIpProcessKeywordAndLimit()
    {
        var parse = Parse(
            "--event-id", "4624,4625",
            "--user", "admin",
            "--ip", "10.0.0.1",
            "--process", "cmd.exe",
            "--keyword", "mimikatz",
            "--limit", "100");

        var filter = SharedCliOptions.BuildFilter(parse, Analyzer(), defaultHoursWhenMissing: false);

        Assert.Equal([4624, 4625], filter.EventIds);
        Assert.Equal("admin", filter.User);
        Assert.Equal("10.0.0.1", filter.IpAddress);
        Assert.Equal("cmd.exe", filter.ProcessName);
        Assert.Equal("mimikatz", filter.Keyword);
        Assert.Equal(100, filter.Limit);
        Assert.Null(filter.FromUtc);
        Assert.Null(filter.ToUtc);
    }

    [Fact]
    public void BuildFilter_Hours_SetsFromRelativeToTo()
    {
        var before = DateTime.UtcNow.AddSeconds(-2);
        var parse = Parse("--hours", "6");
        var filter = SharedCliOptions.BuildFilter(parse, Analyzer(), defaultHoursWhenMissing: false);
        var after = DateTime.UtcNow.AddSeconds(2);

        Assert.NotNull(filter.FromUtc);
        Assert.NotNull(filter.ToUtc);
        Assert.InRange(filter.ToUtc!.Value, before, after);
        Assert.Equal(6, (int)Math.Round((filter.ToUtc.Value - filter.FromUtc!.Value).TotalHours));
    }

    [Fact]
    public void BuildFilter_Date_UsesTimeRanges()
    {
        var parse = Parse("--date", "2026-08-29");
        var filter = SharedCliOptions.BuildFilter(parse, Analyzer(), defaultHoursWhenMissing: false);

        Assert.NotNull(filter.TimeRanges);
        Assert.Single(filter.TimeRanges!);
        Assert.Equal(filter.TimeRanges![0].FromUtc, filter.FromUtc);
        Assert.Equal(filter.TimeRanges[0].ToUtc, filter.ToUtc);
    }

    [Fact]
    public void BuildFilter_DefaultHoursWhenMissing_AppliesCollectionDefaults()
    {
        var parse = Parse();
        var filter = SharedCliOptions.BuildFilter(parse, Analyzer(), defaultHoursWhenMissing: true);

        Assert.NotNull(filter.FromUtc);
        Assert.NotNull(filter.ToUtc);
        Assert.Equal(5000, filter.Limit);
        Assert.InRange((filter.ToUtc!.Value - filter.FromUtc!.Value).TotalHours, 23.9, 24.1);
    }

    [Fact]
    public void BuildFilter_WithoutDefaults_UsesLimit1000AndNoTimeWindow()
    {
        var parse = Parse();
        var filter = SharedCliOptions.BuildFilter(parse, Analyzer(), defaultHoursWhenMissing: false);

        Assert.Null(filter.FromUtc);
        Assert.Null(filter.ToUtc);
        Assert.Equal(1000, filter.Limit);
    }

    [Fact]
    public void BuildFilter_FromAndTo_ParseExplicitRange()
    {
        var parse = Parse("--from", "2026-08-01 00:00:00", "--to", "2026-08-02 00:00:00");
        var filter = SharedCliOptions.BuildFilter(parse, Analyzer(), defaultHoursWhenMissing: false);

        Assert.Equal(new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc), filter.FromUtc);
        Assert.Equal(new DateTime(2026, 8, 2, 0, 0, 0, DateTimeKind.Utc), filter.ToUtc);
        Assert.Null(filter.TimeRanges);
    }
}
