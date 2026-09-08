using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ExportQueryFilterTests
{
    [Fact]
    public void FilterFindings_ByUser_KeepsMatchingRows()
    {
        var findings = new[]
        {
            new SecurityFinding { Title = "a", User = "alice", TimeUtc = DateTime.UtcNow, Context = new FindingContext { User = "alice" } },
            new SecurityFinding { Title = "b", User = "bob", TimeUtc = DateTime.UtcNow, Context = new FindingContext { User = "bob" } }
        };

        var filtered = ExportQueryFilter.FilterFindings(findings, new EventQueryFilter { User = "alice" });
        Assert.Single(filtered);
        Assert.Equal("a", filtered[0].Title);
    }

    [Fact]
    public void HtmlExporter_DoesNotIncludeInvestigationFilter()
    {
        var html = HtmlExporter.Build(new InvestigationExport
        {
            Title = "Test",
            Findings = [],
            Filter = new EventQueryFilter { User = "alice", Limit = 500 }
        });

        Assert.DoesNotContain("Investigation filter", html);
        Assert.DoesNotContain("table-filter", html);
    }
}
