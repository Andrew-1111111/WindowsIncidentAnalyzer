using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class LogSanitizerTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("plain-ascii_123", "plain-ascii_123")]
    public void ForLog_AsciiOrEmpty_Unchanged(string? input, string expected)
    {
        Assert.Equal(expected, LogSanitizer.ForLog(input));
    }

    [Fact]
    public void ForLog_NonAsciiAndControlChars_AreReplacedWithQuestionMark()
    {
        var sanitized = LogSanitizer.ForLog("a\nb\tc\u0401d");
        Assert.Equal("a?b?c?d", sanitized);
    }

    [Fact]
    public void ForLog_PrintableAsciiRange_Preserved()
    {
        Assert.Equal(" ~", LogSanitizer.ForLog(" ~"));
        Assert.Equal("!", LogSanitizer.ForLog("!"));
    }
}
