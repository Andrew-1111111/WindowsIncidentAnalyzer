using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class StartupCacheTests
{
    [Fact]
    public void ShouldRefresh_WhenNeverUpdated_IsTrue()
    {
        var cache = new StartupCache();
        Assert.True(cache.ShouldRefreshIoc(6));
        Assert.True(cache.ShouldRefreshSigma(24));
        Assert.True(cache.ShouldRefreshMitre(168));
        Assert.True(cache.ShouldRefreshCve(168));
    }

    [Fact]
    public void ShouldRefresh_WhenRefreshHoursZero_IsAlwaysTrue()
    {
        var cache = new StartupCache
        {
            IocUpdatedUtc = DateTime.UtcNow,
            SigmaUpdatedUtc = DateTime.UtcNow,
            MitreUpdatedUtc = DateTime.UtcNow,
            CveUpdatedUtc = DateTime.UtcNow
        };

        Assert.True(cache.ShouldRefreshIoc(0));
        Assert.True(cache.ShouldRefreshSigma(0));
        Assert.True(cache.ShouldRefreshMitre(0));
        Assert.True(cache.ShouldRefreshCve(0));
    }

    [Fact]
    public void ShouldRefresh_WhenRecentlyUpdated_IsFalse()
    {
        var cache = new StartupCache
        {
            IocUpdatedUtc = DateTime.UtcNow.AddMinutes(-30),
            SigmaUpdatedUtc = DateTime.UtcNow.AddHours(-1),
            MitreUpdatedUtc = DateTime.UtcNow.AddDays(-1),
            CveUpdatedUtc = DateTime.UtcNow.AddDays(-1)
        };

        Assert.False(cache.ShouldRefreshIoc(6));
        Assert.False(cache.ShouldRefreshSigma(24));
        Assert.False(cache.ShouldRefreshMitre(168));
        Assert.False(cache.ShouldRefreshCve(168));
    }

    [Fact]
    public void ShouldRefresh_WhenStale_IsTrue()
    {
        var cache = new StartupCache
        {
            IocUpdatedUtc = DateTime.UtcNow.AddHours(-7),
            SigmaUpdatedUtc = DateTime.UtcNow.AddHours(-25),
            MitreUpdatedUtc = DateTime.UtcNow.AddDays(-8),
            CveUpdatedUtc = DateTime.UtcNow.AddDays(-8)
        };

        Assert.True(cache.ShouldRefreshIoc(6));
        Assert.True(cache.ShouldRefreshSigma(24));
        Assert.True(cache.ShouldRefreshMitre(168));
        Assert.True(cache.ShouldRefreshCve(168));
    }
}
