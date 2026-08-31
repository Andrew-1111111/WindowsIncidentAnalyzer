using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class CollectionParallelismTests
{
    [Theory]
    [InlineData(true, 5, true)]
    [InlineData(true, 1, false)]
    [InlineData(false, 5, false)]
    [InlineData(false, 1, false)]
    public void ShouldUseParallel_RespectsOptionsAndChannelCount(bool enabled, int channelCount, bool expected)
    {
        var options = new CollectionOptions { EnableParallelCollection = enabled };
        Assert.Equal(expected, CollectionParallelism.ShouldUseParallel(options, channelCount));
    }

    [Fact]
    public void ResolveMaxDegreeOfParallelism_CollectionOptions_UsesProcessorCountWhenZero()
    {
        var degree = ParallelAnalysis.ResolveMaxDegreeOfParallelism(new CollectionOptions());
        Assert.Equal(Math.Max(1, Environment.ProcessorCount), degree);
    }

    [Fact]
    public void ResolveIocFeedParallelism_CapsDefaultParallelism()
    {
        var degree = ParallelAnalysis.ResolveIocFeedParallelism(new IocFeedOptions());
        Assert.InRange(degree, 1, 4);
    }
}
