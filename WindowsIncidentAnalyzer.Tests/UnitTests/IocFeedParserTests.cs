using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class IocFeedParserTests
{
    [Fact]
    public void ParseSpamhausDrop_ParsesNdJsonLines()
    {
        const string body = """
            {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
            {"cidr":"2.26.75.0/24","sblid":"SBL698389","rir":"ripencc"}

            not-json
            """;

        var iocs = IocFeedParsers.ParseSpamhausDrop(body, "Spamhaus DROP v4").ToList();

        Assert.Equal(2, iocs.Count);
        Assert.All(iocs, ioc => Assert.Equal("ip", ioc.Type));
        Assert.Contains(iocs, ioc => ioc.Value == "1.10.16.0");
        Assert.Contains(iocs, ioc => ioc.Value == "2.26.75.0");
    }
}
