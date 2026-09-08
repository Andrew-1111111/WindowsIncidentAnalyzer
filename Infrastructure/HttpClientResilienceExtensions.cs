using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http.Resilience;
using Polly;
using WindowsIncidentAnalyzer.Configuration;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class HttpClientResilienceExtensions
{
    public static IHttpClientBuilder AddWiaResilienceHandler(
        this IHttpClientBuilder builder,
        HttpResilienceOptions defaults,
        string clientName)
    {
        defaults.Clients.TryGetValue(clientName, out var clientOverride);
        var settings = HttpResilienceSettings.Merge(defaults, clientOverride);

        builder.AddStandardResilienceHandler(options => Apply(settings, options));
        return builder;
    }

    internal static void Apply(HttpResilienceSettings settings, HttpStandardResilienceOptions options)
    {
        options.Retry.MaxRetryAttempts = Math.Max(0, settings.MaxRetryAttempts);
        options.Retry.Delay = TimeSpan.FromSeconds(Math.Max(0, settings.RetryDelaySeconds));
        options.Retry.BackoffType = DelayBackoffType.Exponential;
        options.Retry.UseJitter = true;
        options.Retry.MaxDelay = TimeSpan.FromSeconds(Math.Max(1, settings.MaxRetryDelaySeconds));

        options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(Math.Max(1, settings.AttemptTimeoutSeconds));
        options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(Math.Max(1, settings.TotalRequestTimeoutSeconds));

        var attemptTimeoutSeconds = Math.Max(1, settings.AttemptTimeoutSeconds);
        var samplingDurationSeconds = HttpResilienceSettings.ResolveCircuitBreakerSamplingDurationSeconds(
            attemptTimeoutSeconds,
            settings.CircuitBreakerSamplingDurationSeconds);

        options.CircuitBreaker.FailureRatio = Math.Clamp(settings.CircuitBreakerFailureRatio, 0.0, 1.0);
        options.CircuitBreaker.MinimumThroughput = Math.Max(1, settings.CircuitBreakerMinimumThroughput);
        options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(samplingDurationSeconds);
        options.CircuitBreaker.BreakDuration = TimeSpan.FromSeconds(
            Math.Max(1, settings.CircuitBreakerBreakDurationSeconds));

        if (!settings.EnableCircuitBreaker)
        {
            options.CircuitBreaker.ShouldHandle = static _ => ValueTask.FromResult(false);
        }
    }
}
