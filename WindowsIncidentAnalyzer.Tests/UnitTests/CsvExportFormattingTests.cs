using System.Text.Json;
using WindowsIncidentAnalyzer.Exporters;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class CsvExportFormattingTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Cell_BlankInput_ReturnsEmpty(string? value)
    {
        Assert.Equal(string.Empty, CsvExportFormatting.Cell(value));
    }

    [Fact]
    public void Cell_ReplacesNewlinesTabsAndTrims()
    {
        var result = CsvExportFormatting.Cell("  line1\r\nline2\ttab  ");

        Assert.Equal("line1 line2 tab", result);
    }

    [Fact]
    public void Cell_TruncatesBeyondMaxLength()
    {
        var longValue = new string('x', 33_000);

        var result = CsvExportFormatting.Cell(longValue);

        Assert.Equal(32_000, result.Length);
        Assert.All(result, c => Assert.Equal('x', c));
    }

    [Fact]
    public void FormatUtc_UsesInvariantTimestampFormat()
    {
        var utc = new DateTime(2026, 8, 1, 12, 30, 45, DateTimeKind.Utc);

        Assert.Equal("2026-08-01 12:30:45", CsvExportFormatting.FormatUtc(utc));
    }

    [Fact]
    public void FormatIds_EmptyList_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, CsvExportFormatting.FormatIds([]));
    }

    [Fact]
    public void FormatIds_MultipleIds_JoinsWithCommaSpace()
    {
        Assert.Equal("1, 7, 42", CsvExportFormatting.FormatIds([1, 7, 42]));
    }

    [Fact]
    public void FormatList_EmptyList_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, CsvExportFormatting.FormatList([]));
    }

    [Fact]
    public void FormatList_MultipleValues_JoinsWithPipeAndNormalizesCells()
    {
        var result = CsvExportFormatting.FormatList(["alpha", "beta\r\nline"]);

        Assert.Equal("alpha | beta line", result);
    }

    [Theory]
    [InlineData(true, "yes")]
    [InlineData(false, "no")]
    [InlineData(null, "")]
    public void FormatNullableBool_MapsValues(bool? value, string expected)
    {
        Assert.Equal(expected, CsvExportFormatting.FormatNullableBool(value));
    }

    [Fact]
    public void FormatProperties_EmptyDictionary_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, CsvExportFormatting.FormatProperties(new Dictionary<string, string>()));
    }

    [Fact]
    public void FormatProperties_SerializesAndNormalizesThroughCell()
    {
        var properties = new Dictionary<string, string>
        {
            ["SubjectUserName"] = "alice",
            ["CommandLine"] = "cmd.exe\r\n/whoami"
        };

        var result = CsvExportFormatting.FormatProperties(properties);

        Assert.Contains("alice", result, StringComparison.Ordinal);
        Assert.Contains("CommandLine", result, StringComparison.Ordinal);
        Assert.DoesNotContain("\r\n", result, StringComparison.Ordinal);

        var roundTrip = JsonSerializer.Deserialize<Dictionary<string, string>>(result);
        Assert.NotNull(roundTrip);
        Assert.Equal("alice", roundTrip!["SubjectUserName"]);
        Assert.Equal("cmd.exe\r\n/whoami", roundTrip["CommandLine"]);
    }
}
