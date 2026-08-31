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
}
