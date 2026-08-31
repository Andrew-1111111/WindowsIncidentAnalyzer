using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class DateRangeParserTests
{
    [Fact]
    public void Parse_Empty_ReturnsNoRanges()
    {
        Assert.Empty(DateRangeParser.Parse(null));
        Assert.Empty(DateRangeParser.Parse("  "));
    }

    [Fact]
    public void Parse_SingleDate_CoversLocalCalendarDay()
    {
        var ranges = DateRangeParser.Parse("2026-08-29");
        Assert.Single(ranges);

        var localStart = new DateTime(2026, 8, 29, 0, 0, 0, DateTimeKind.Local);
        var localEnd = localStart.AddDays(1).AddTicks(-1);
        Assert.Equal(localStart.ToUniversalTime(), ranges[0].FromUtc);
        Assert.Equal(localEnd.ToUniversalTime(), ranges[0].ToUtc);
    }

    [Fact]
    public void Parse_CommaSeparatedAdjacentDates_MergesIntoOneRange()
    {
        var ranges = DateRangeParser.Parse("2026-08-28,2026-08-29");
        Assert.Single(ranges);

        var localStart = new DateTime(2026, 8, 28, 0, 0, 0, DateTimeKind.Local);
        var localEnd = new DateTime(2026, 8, 29, 0, 0, 0, DateTimeKind.Local).AddDays(1).AddTicks(-1);
        Assert.Equal(localStart.ToUniversalTime(), ranges[0].FromUtc);
        Assert.Equal(localEnd.ToUniversalTime(), ranges[0].ToUtc);
    }

    [Fact]
    public void Parse_RangeOperator_IncludesBothEnds()
    {
        var ranges = DateRangeParser.Parse("2026-08-01..2026-08-07");
        Assert.Single(ranges);

        var localStart = new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Local);
        var localEnd = new DateTime(2026, 8, 7, 0, 0, 0, DateTimeKind.Local).AddDays(1).AddTicks(-1);
        Assert.Equal(localStart.ToUniversalTime(), ranges[0].FromUtc);
        Assert.Equal(localEnd.ToUniversalTime(), ranges[0].ToUtc);
    }

    [Fact]
    public void Parse_NonAdjacentDates_KeepsSeparateRanges()
    {
        var ranges = DateRangeParser.Parse("2026-08-01,2026-08-15");
        Assert.Equal(2, ranges.Count);
        Assert.Equal(new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Local).ToUniversalTime(), ranges[0].FromUtc);
        Assert.Equal(new DateTime(2026, 8, 15, 0, 0, 0, DateTimeKind.Local).ToUniversalTime(), ranges[1].FromUtc);
    }

    [Fact]
    public void Parse_InvalidValue_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => DateRangeParser.Parse("29.08.2026"));
        Assert.Contains("yyyy-MM-dd", ex.Message);
    }
}
