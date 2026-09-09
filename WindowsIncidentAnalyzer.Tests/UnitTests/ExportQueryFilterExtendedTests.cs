using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ExportQueryFilterExtendedTests
{
    private static readonly DateTime BaseTime = new(2026, 7, 1, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void HasCriteria_NullFilter_ReturnsFalse()
    {
        Assert.False(ExportQueryFilter.HasCriteria(null));
    }

    [Fact]
    public void HasCriteria_EmptyFilter_ReturnsFalse()
    {
        Assert.False(ExportQueryFilter.HasCriteria(new EventQueryFilter()));
    }

    [Theory]
    [InlineData("User", "alice")]
    [InlineData("IpAddress", "10.0.0.1")]
    [InlineData("ProcessName", "cmd.exe")]
    [InlineData("Keyword", "malware")]
    [InlineData("ComputerName", "HOST01")]
    [InlineData("LogName", "Security")]
    public void HasCriteria_StringField_ReturnsTrue(string property, string value)
    {
        var filter = property switch
        {
            "User" => new EventQueryFilter { User = value },
            "IpAddress" => new EventQueryFilter { IpAddress = value },
            "ProcessName" => new EventQueryFilter { ProcessName = value },
            "Keyword" => new EventQueryFilter { Keyword = value },
            "ComputerName" => new EventQueryFilter { ComputerName = value },
            "LogName" => new EventQueryFilter { LogName = value },
            _ => throw new InvalidOperationException()
        };

        Assert.True(ExportQueryFilter.HasCriteria(filter));
    }

    [Fact]
    public void HasCriteria_FromUtc_ReturnsTrue()
    {
        Assert.True(ExportQueryFilter.HasCriteria(new EventQueryFilter { FromUtc = BaseTime }));
    }

    [Fact]
    public void HasCriteria_ToUtc_ReturnsTrue()
    {
        Assert.True(ExportQueryFilter.HasCriteria(new EventQueryFilter { ToUtc = BaseTime }));
    }

    [Fact]
    public void HasCriteria_TimeRanges_ReturnsTrue()
    {
        var filter = new EventQueryFilter
        {
            TimeRanges = [new TimeRange(BaseTime, BaseTime.AddHours(1))]
        };

        Assert.True(ExportQueryFilter.HasCriteria(filter));
    }

    [Fact]
    public void HasCriteria_EventIds_ReturnsTrue()
    {
        Assert.True(ExportQueryFilter.HasCriteria(new EventQueryFilter { EventIds = [4688] }));
    }

    [Fact]
    public void FilterFindings_ByFromAndToUtc_ExcludesOutOfRange()
    {
        var findings = new[]
        {
            new SecurityFinding { Title = "early", TimeUtc = BaseTime.AddHours(-2), Context = new FindingContext() },
            new SecurityFinding { Title = "in-range", TimeUtc = BaseTime, Context = new FindingContext() },
            new SecurityFinding { Title = "late", TimeUtc = BaseTime.AddHours(2), Context = new FindingContext() }
        };

        var filter = new EventQueryFilter
        {
            FromUtc = BaseTime.AddHours(-1),
            ToUtc = BaseTime.AddHours(1)
        };

        var filtered = ExportQueryFilter.FilterFindings(findings, filter);

        Assert.Single(filtered);
        Assert.Equal("in-range", filtered[0].Title);
    }

    [Fact]
    public void FilterFindings_ByTimeRanges_UsesContextTimestampWhenPresent()
    {
        var findings = new[]
        {
            new SecurityFinding
            {
                Title = "match",
                TimeUtc = BaseTime.AddDays(-1),
                Context = new FindingContext { TimestampUtc = BaseTime }
            },
            new SecurityFinding
            {
                Title = "miss",
                TimeUtc = BaseTime,
                Context = new FindingContext { TimestampUtc = BaseTime.AddDays(1) }
            }
        };

        var filter = new EventQueryFilter
        {
            TimeRanges = [new TimeRange(BaseTime.AddHours(-1), BaseTime.AddHours(1))]
        };

        var filtered = ExportQueryFilter.FilterFindings(findings, filter);

        Assert.Single(filtered);
        Assert.Equal("match", filtered[0].Title);
    }

    [Fact]
    public void FilterFindings_ByEventIds_RequiresContextEventId()
    {
        var findings = new[]
        {
            new SecurityFinding
            {
                Title = "4688",
                TimeUtc = BaseTime,
                Context = new FindingContext { EventId = 4688 }
            },
            new SecurityFinding
            {
                Title = "4624",
                TimeUtc = BaseTime,
                Context = new FindingContext { EventId = 4624 }
            },
            new SecurityFinding
            {
                Title = "missing-id",
                TimeUtc = BaseTime,
                Context = new FindingContext()
            }
        };

        var filtered = ExportQueryFilter.FilterFindings(findings, new EventQueryFilter { EventIds = [4688] });

        Assert.Single(filtered);
        Assert.Equal("4688", filtered[0].Title);
    }

    [Fact]
    public void FilterFindings_Keyword_IsCaseInsensitive()
    {
        var findings = new[]
        {
            new SecurityFinding
            {
                Title = "Benign",
                Description = "Nothing here",
                TimeUtc = BaseTime,
                Context = new FindingContext()
            },
            new SecurityFinding
            {
                Title = "Alert",
                Description = "POWERSHELL encoded command",
                TimeUtc = BaseTime,
                Context = new FindingContext()
            }
        };

        var filtered = ExportQueryFilter.FilterFindings(findings, new EventQueryFilter { Keyword = "powershell" });

        Assert.Single(filtered);
        Assert.Equal("Alert", filtered[0].Title);
    }

    [Fact]
    public void FilterFindings_UserMatch_IsCaseInsensitiveAcrossContextAndDomain()
    {
        var findings = new[]
        {
            new SecurityFinding
            {
                Title = "match-context",
                User = "other",
                TimeUtc = BaseTime,
                Context = new FindingContext { User = "Alice", Domain = "CORP" }
            },
            new SecurityFinding
            {
                Title = "match-finding-user",
                User = "ALICE",
                TimeUtc = BaseTime,
                Context = new FindingContext()
            },
            new SecurityFinding
            {
                Title = "miss",
                User = "charlie",
                TimeUtc = BaseTime,
                Context = new FindingContext()
            }
        };

        var filtered = ExportQueryFilter.FilterFindings(findings, new EventQueryFilter { User = "alice" });

        Assert.Equal(2, filtered.Count);
        Assert.Contains(filtered, f => f.Title == "match-context");
        Assert.Contains(filtered, f => f.Title == "match-finding-user");
    }

    [Fact]
    public void FilterCorrelations_ByHostAndKeyword_FiltersCorrectly()
    {
        var correlations = new[]
        {
            new EventCorrelation
            {
                Title = "Lateral movement",
                Scenario = "RemoteLogon",
                ComputerName = "HOST01",
                TimeUtc = BaseTime,
                Interpretation = "Suspicious",
                Details = "More data"
            },
            new EventCorrelation
            {
                Title = "Other",
                Scenario = "Local",
                ComputerName = "HOST02",
                TimeUtc = BaseTime,
                Interpretation = "Benign",
                Details = "OK"
            }
        };

        var filtered = ExportQueryFilter.FilterCorrelations(
            correlations,
            new EventQueryFilter { ComputerName = "host01", Keyword = "LATERAL" });

        Assert.Single(filtered);
        Assert.Equal("Lateral movement", filtered[0].Title);
    }

    [Fact]
    public void FilterIocMatches_ByEventIdIpAndProcess_FiltersCorrectly()
    {
        var matches = new[]
        {
            new IocMatch
            {
                IocValue = "203.0.113.10",
                EventId = 4688,
                TimestampUtc = BaseTime,
                Host = "HOST01",
                RelatedProcess = "powershell.exe",
                RelatedUser = "alice",
                MatchedField = "DestinationIp"
            },
            new IocMatch
            {
                IocValue = "evil.com",
                EventId = 4624,
                TimestampUtc = BaseTime,
                Host = "HOST02",
                RelatedProcess = "cmd.exe",
                RelatedUser = "bob",
                MatchedField = "QueryName"
            }
        };

        var filtered = ExportQueryFilter.FilterIocMatches(
            matches,
            new EventQueryFilter
            {
                EventIds = [4688],
                IpAddress = "203.0.113",
                ProcessName = "POWERshell"
            });

        Assert.Single(filtered);
        Assert.Equal("203.0.113.10", filtered[0].IocValue);
    }

    [Fact]
    public void FilterIocMatches_IpMatchesMatchedField()
    {
        var matches = new[]
        {
            new IocMatch
            {
                IocValue = "hash-value",
                EventId = 1,
                TimestampUtc = BaseTime,
                MatchedField = "SourceIpAddress=10.0.0.99"
            },
            new IocMatch
            {
                IocValue = "other",
                EventId = 1,
                TimestampUtc = BaseTime,
                MatchedField = "CommandLine"
            }
        };

        var filtered = ExportQueryFilter.FilterIocMatches(matches, new EventQueryFilter { IpAddress = "10.0.0.99" });

        Assert.Single(filtered);
        Assert.Equal("hash-value", filtered[0].IocValue);
    }

    [Fact]
    public void FilterCveMatches_ByProductKeywordAndEventId_FiltersCorrectly()
    {
        var matches = new[]
        {
            new CveMatch
            {
                CveId = "CVE-2024-0001",
                Product = "Windows Server",
                EventId = 4688,
                TimestampUtc = BaseTime,
                Host = "HOST01",
                RelatedProcess = "svc.exe",
                RelatedUser = "SYSTEM",
                VulnerabilityName = "RCE",
                ShortDescription = "Critical remote code execution"
            },
            new CveMatch
            {
                CveId = "CVE-2024-0002",
                Product = "OtherProduct",
                EventId = 4624,
                TimestampUtc = BaseTime,
                Host = "HOST02",
                RelatedProcess = "app.exe",
                RelatedUser = "user",
                VulnerabilityName = "Info leak"
            }
        };

        var filtered = ExportQueryFilter.FilterCveMatches(
            matches,
            new EventQueryFilter
            {
                EventIds = [4688],
                ProcessName = "svc",
                Keyword = "remote code"
            });

        Assert.Single(filtered);
        Assert.Equal("CVE-2024-0001", filtered[0].CveId);
    }

    [Fact]
    public void FilterFindings_LogName_IsCaseInsensitive()
    {
        var findings = new[]
        {
            new SecurityFinding
            {
                Title = "security-log",
                TimeUtc = BaseTime,
                Context = new FindingContext { Channel = "Security" }
            },
            new SecurityFinding
            {
                Title = "system-log",
                TimeUtc = BaseTime,
                Context = new FindingContext { Channel = "System" }
            }
        };

        var filtered = ExportQueryFilter.FilterFindings(findings, new EventQueryFilter { LogName = "security" });

        Assert.Single(filtered);
        Assert.Equal("security-log", filtered[0].Title);
    }
}
