using System.Globalization;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class EventIdentityTests
{
    private static readonly DateTime SampleTime = new(2026, 3, 15, 10, 30, 45, DateTimeKind.Utc);

    [Fact]
    public void BuildKey_WithEventRecordId_UsesRecordIdentity()
    {
        var key = EventIdentity.BuildKey("HOST01", "Security", "Microsoft-Windows-Security-Auditing", 4688, SampleTime, 987654L);

        Assert.Equal("host01|security|microsoft-windows-security-auditing|4688|record:987654", key);
    }

    [Fact]
    public void BuildKey_WithoutEventRecordId_UsesIsoTimeIdentity()
    {
        var key = EventIdentity.BuildKey("HOST01", "Security", "Provider", 4624, SampleTime, null);

        var expectedTime = DateTimeParser.Iso(SampleTime);
        Assert.Equal($"host01|security|provider|4624|time:{expectedTime}", key);
    }

    [Fact]
    public void BuildKey_FromWindowsEvent_DelegatesToOverload()
    {
        var evt = new WindowsEvent
        {
            ComputerName = "  WORKSTATION  ",
            LogName = "System",
            ProviderName = "Service Control Manager",
            EventId = 7036,
            TimeCreatedUtc = SampleTime,
            EventRecordId = 42
        };

        var key = EventIdentity.BuildKey(evt);

        Assert.Equal("workstation|system|service control manager|7036|record:42", key);
    }

    [Fact]
    public void BuildKey_NormalizesNullAndWhitespaceFields()
    {
        var key = EventIdentity.BuildKey(null, "  ", null, 1, SampleTime, 5L);

        Assert.Equal("|||1|record:5", key);
    }

    [Fact]
    public void BuildKey_NormalizesMixedCaseAndTrim()
    {
        var key = EventIdentity.BuildKey("  MyHost  ", "  Application  ", "  MyProvider  ", 100, SampleTime, 1L);

        Assert.StartsWith("myhost|application|myprovider|100|record:1", key);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ExtractRecordId_MissingOrBlankXml_ReturnsNull(string? rawXml)
    {
        Assert.Null(EventIdentity.ExtractRecordId(rawXml));
    }

    [Fact]
    public void ExtractRecordId_StandardXml_ReturnsId()
    {
        const string xml = "<Event><System><EventRecordID>123456789</EventRecordID></System></Event>";

        Assert.Equal(123456789L, EventIdentity.ExtractRecordId(xml));
    }

    [Fact]
    public void ExtractRecordId_XmlWithAttributes_ReturnsId()
    {
        const string xml = "<EventRecordID xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>999</EventRecordID>";

        Assert.Equal(999L, EventIdentity.ExtractRecordId(xml));
    }

    [Fact]
    public void ExtractRecordId_CaseInsensitiveTag_ReturnsId()
    {
        const string xml = "<eventrecordid>777</eventrecordid>";

        Assert.Equal(777L, EventIdentity.ExtractRecordId(xml));
    }

    [Fact]
    public void ExtractRecordId_NonNumericValue_ReturnsNull()
    {
        const string xml = "<EventRecordID>not-a-number</EventRecordID>";

        Assert.Null(EventIdentity.ExtractRecordId(xml));
    }

    [Fact]
    public void ExtractRecordId_NoMatchingTag_ReturnsNull()
    {
        Assert.Null(EventIdentity.ExtractRecordId("<Event><EventID>4688</EventID></Event>"));
    }

    [Fact]
    public void BuildKey_RecordIdZero_StillUsesRecordIdentity()
    {
        var key = EventIdentity.BuildKey("host", "log", "provider", 1, SampleTime, 0L);

        Assert.EndsWith("|record:0", key);
    }

    [Fact]
    public void BuildKey_EventIdUsesInvariantCulture()
    {
        var key = EventIdentity.BuildKey("h", "l", "p", 4688, SampleTime, 1L);

        Assert.Contains(
            4688.ToString(CultureInfo.InvariantCulture),
            key,
            StringComparison.Ordinal);
    }
}
