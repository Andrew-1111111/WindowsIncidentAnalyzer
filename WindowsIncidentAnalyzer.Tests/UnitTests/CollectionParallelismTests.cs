using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class CollectionParallelismTests
{
    [Theory]
    [InlineData(0, 5, true)]
    [InlineData(4, 5, true)]
    [InlineData(1, 5, false)]
    [InlineData(0, 1, false)]
    [InlineData(4, 1, false)]
    public void ShouldUseParallel_RespectsOptionsAndChannelCount(int maxDegree, int channelCount, bool expected)
    {
        var options = new AnalyzerOptions { MaxDegreeOfParallelism = maxDegree };
        Assert.Equal(expected, ParallelAnalysis.ShouldUseParallel(options, channelCount));
    }

    [Fact]
    public void ResolveMaxDegreeOfParallelism_Zero_IsUnlimited()
    {
        Assert.Equal(-1, ParallelAnalysis.ResolveMaxDegreeOfParallelism(0));
        Assert.Equal(-1, ParallelAnalysis.ResolveMaxDegreeOfParallelism(new AnalyzerOptions()));
    }

    [Fact]
    public void ResolveCollectionParallelism_Unlimited_UsesAllChannels()
    {
        var degree = ParallelAnalysis.ResolveCollectionParallelism(
            new AnalyzerOptions { MaxDegreeOfParallelism = 0 },
            channelCount: 50);
        Assert.Equal(50, degree);
    }

    [Fact]
    public void ResolveCollectionParallelism_ExplicitCap_IsRespected()
    {
        var degree = ParallelAnalysis.ResolveCollectionParallelism(
            new AnalyzerOptions { MaxDegreeOfParallelism = 4 },
            channelCount: 50);
        Assert.Equal(4, degree);
    }

    [Fact]
    public void ResolveCollectionParallelism_DoesNotExceedChannelCount()
    {
        var degree = ParallelAnalysis.ResolveCollectionParallelism(
            new AnalyzerOptions { MaxDegreeOfParallelism = 0 },
            channelCount: 3);
        Assert.Equal(3, degree);
    }

    [Fact]
    public void ResolveIocFeedParallelism_Zero_DownloadsAllFeeds()
    {
        const int feedCount = 16;
        var degree = ParallelAnalysis.ResolveIocFeedParallelism(new AnalyzerOptions(), feedCount);
        Assert.Equal(feedCount, degree);
    }

    [Fact]
    public void ResolveIocFeedParallelism_ExplicitValue_IsClampedToFeedCount()
    {
        Assert.Equal(4, ParallelAnalysis.ResolveIocFeedParallelism(new AnalyzerOptions { MaxDegreeOfParallelism = 4 }, feedCount: 16));
        Assert.Equal(16, ParallelAnalysis.ResolveIocFeedParallelism(new AnalyzerOptions { MaxDegreeOfParallelism = 32 }, feedCount: 16));
    }
}
