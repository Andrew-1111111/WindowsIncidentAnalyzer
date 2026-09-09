using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class TextUtilitiesTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TextHash_Sha256Hex_EmptyInput_ReturnsEmpty(string? text)
    {
        Assert.Equal(string.Empty, TextHash.Sha256Hex(text));
    }

    [Fact]
    public void TextHash_Sha256Hex_ComputesExpectedDigest()
    {
        const string input = "WindowsIncidentAnalyzer";
        var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));

        Assert.Equal(expected, TextHash.Sha256Hex(input));
    }

    [Fact]
    public void TextHash_Sha256Hex_IsDeterministic()
    {
        const string input = "same-input";

        Assert.Equal(TextHash.Sha256Hex(input), TextHash.Sha256Hex(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void DateTimeParser_Parse_BlankInput_ReturnsNull(string? value)
    {
        Assert.Null(DateTimeParser.Parse(value));
    }

    [Fact]
    public void DateTimeParser_Parse_SpaceSeparatedDateTime_ReturnsUtc()
    {
        var parsed = DateTimeParser.Parse("2026-08-01 12:30:45");

        Assert.NotNull(parsed);
        Assert.Equal(DateTimeKind.Utc, parsed!.Value.Kind);
        Assert.Equal(new DateTime(2026, 8, 1, 12, 30, 45, DateTimeKind.Utc), parsed.Value);
    }

    [Fact]
    public void DateTimeParser_Parse_Iso8601WithFractions_ReturnsUtc()
    {
        var parsed = DateTimeParser.Parse("2026-08-01T12:30:45.1234567Z");

        Assert.NotNull(parsed);
        Assert.Equal(DateTimeKind.Utc, parsed!.Value.Kind);
    }

    [Fact]
    public void DateTimeParser_Parse_QuotedValue_TrimsQuotes()
    {
        var parsed = DateTimeParser.Parse("\"2026-08-01 12:00:00\"");

        Assert.NotNull(parsed);
        Assert.Equal(new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc), parsed!.Value);
    }

    [Fact]
    public void DateTimeParser_Parse_DateOnly_ReturnsUtcMidnight()
    {
        var parsed = DateTimeParser.Parse("2026-08-01");

        Assert.NotNull(parsed);
        Assert.Equal(new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc), parsed!.Value);
    }

    [Fact]
    public void DateTimeParser_Parse_InvalidValue_ReturnsNull()
    {
        Assert.Null(DateTimeParser.Parse("not-a-date"));
    }

    [Fact]
    public void DateTimeParser_Iso_FormatsUtcWithRoundTripKind()
    {
        var utc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var iso = DateTimeParser.Iso(utc);

        Assert.Equal(DateTimeKind.Utc, DateTime.Parse(iso, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).Kind);
        Assert.StartsWith("2026-01-02T03:04:05", iso, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void EventIdParser_Parse_BlankInput_ReturnsEmpty(string? value)
    {
        Assert.Empty(EventIdParser.Parse(value));
    }

    [Fact]
    public void EventIdParser_Parse_CommaSeparatedIds_ReturnsAllValid()
    {
        var ids = EventIdParser.Parse(" 4688 , 4624, , 999 ");

        Assert.Equal([4688, 4624, 999], ids);
    }

    [Fact]
    public void EventIdParser_Parse_SkipsInvalidTokens()
    {
        var ids = EventIdParser.Parse("4688,abc,4624");

        Assert.Equal([4688, 4624], ids);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PathName_FileName_BlankInput_ReturnsNull(string? path)
    {
        Assert.Null(PathName.FileName(path));
    }

    [Fact]
    public void PathName_FileName_WindowsPath_ReturnsFileName()
    {
        Assert.Equal("cmd.exe", PathName.FileName(@"C:\Windows\System32\cmd.exe"));
    }

    [Fact]
    public void PathName_FileName_ForwardSlashes_NormalizesToFileName()
    {
        Assert.Equal("powershell.exe", PathName.FileName("/usr/bin/powershell.exe"));
    }

    [Fact]
    public void PathName_FileName_InvalidPath_DoesNotThrow()
    {
        const string invalid = "  <>bad|name  ";

        var result = PathName.FileName(invalid);

        Assert.False(string.IsNullOrEmpty(result));
        Assert.Contains("bad|name", result!, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("-")]
    [InlineData("?")]
    [InlineData("null")]
    [InlineData("NULL")]
    public void NullableText_Clean_SentinelValues_ReturnNull(string? value)
    {
        Assert.Null(NullableText.Clean(value));
    }

    [Fact]
    public void NullableText_Clean_TrimsAndPreservesMeaningfulText()
    {
        Assert.Equal("alice", NullableText.Clean("  alice  "));
    }

    [Fact]
    public void NullableText_Clean_RegularValue_NotTreatedAsNull()
    {
        Assert.Equal("unknown-user", NullableText.Clean("unknown-user"));
    }
}
