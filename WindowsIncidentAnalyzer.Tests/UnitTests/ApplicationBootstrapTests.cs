using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ApplicationBootstrapTests
{
    [Theory]
    [InlineData(new[] { "--help" }, true)]
    [InlineData(new[] { "-h" }, true)]
    [InlineData(new[] { "--version" }, true)]
    [InlineData(new[] { "--skip-bootstrap", "analyze" }, true)]
    [InlineData(new[] { "analyze" }, false)]
    [InlineData(new string[0], false)]
    public void ShouldSkip_RecognizesBootstrapSkipArguments(string[] args, bool expected)
    {
        Assert.Equal(expected, ApplicationBootstrap.ShouldSkip(args));
    }

    [Theory]
    [InlineData(new[] { "--help" }, true)]
    [InlineData(new[] { "--skip-bootstrap", "analyze" }, false)]
    [InlineData(new[] { "analyze" }, false)]
    public void IsHelpOrVersion_OnlyHelpAndVersion(string[] args, bool expected)
    {
        Assert.Equal(expected, ApplicationBootstrap.IsHelpOrVersion(args));
    }

    [Theory]
    [InlineData(new[] { "--skip-bootstrap" }, true)]
    [InlineData(new[] { "--no-bootstrap", "collect" }, true)]
    [InlineData(new[] { "analyze" }, false)]
    public void ShouldSkipThreatIntel_OnlyBootstrapFlags(string[] args, bool expected)
    {
        Assert.Equal(expected, ApplicationBootstrap.ShouldSkipThreatIntel(args));
    }
}
