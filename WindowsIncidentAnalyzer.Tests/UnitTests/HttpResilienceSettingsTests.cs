using Microsoft.Extensions.Http.Resilience;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class HttpResilienceSettingsTests
{
    [Fact]
    public void Merge_UsesClientOverrides()
    {
        var defaults = new HttpResilienceOptions
        {
            MaxRetryAttempts = 3,
            AttemptTimeoutSeconds = 30,
            EnableCircuitBreaker = true
        };

        var client = new HttpResilienceClientOptions
        {
            MaxRetryAttempts = 2,
            AttemptTimeoutSeconds = 90,
            EnableCircuitBreaker = false
        };

        var merged = HttpResilienceSettings.Merge(defaults, client);

        Assert.Equal(2, merged.MaxRetryAttempts);
        Assert.Equal(90, merged.AttemptTimeoutSeconds);
        Assert.False(merged.EnableCircuitBreaker);
        Assert.Equal(3, HttpResilienceSettings.Merge(defaults, clientOverride: null).MaxRetryAttempts);
    }

    [Theory]
    [InlineData(300, 30, 600)]
    [InlineData(120, 30, 240)]
    [InlineData(30, 60, 60)]
    public void ResolveCircuitBreakerSamplingDurationSeconds_EnforcesMinimumWindow(
        int attemptTimeoutSeconds,
        int configuredSamplingDurationSeconds,
        int expectedSeconds) =>
        Assert.Equal(
            expectedSeconds,
            HttpResilienceSettings.ResolveCircuitBreakerSamplingDurationSeconds(
                attemptTimeoutSeconds,
                configuredSamplingDurationSeconds));

    [Fact]
    public void Apply_WhenCircuitBreakerDisabled_StillSetsValidSamplingDuration()
    {
        var settings = HttpResilienceSettings.Merge(
            new HttpResilienceOptions
            {
                AttemptTimeoutSeconds = 30,
                CircuitBreakerSamplingDurationSeconds = 30
            },
            new HttpResilienceClientOptions { EnableCircuitBreaker = false });

        var options = new HttpStandardResilienceOptions();
        HttpClientResilienceExtensions.Apply(settings, options);

        Assert.False(settings.EnableCircuitBreaker);
        Assert.True(
            options.CircuitBreaker.SamplingDuration >= options.AttemptTimeout.Timeout * 2,
            "Polly validates sampling duration even when the circuit breaker is disabled.");
    }
}
