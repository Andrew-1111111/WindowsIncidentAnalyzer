namespace WindowsIncidentAnalyzer.Configuration;

public sealed class HttpResilienceOptions
{
    public int MaxRetryAttempts { get; set; } = 3;

    public int RetryDelaySeconds { get; set; } = 2;

    public int MaxRetryDelaySeconds { get; set; } = 30;

    public int AttemptTimeoutSeconds { get; set; } = 30;

    public int TotalRequestTimeoutSeconds { get; set; } = 120;

    public bool EnableCircuitBreaker { get; set; } = true;

    public double CircuitBreakerFailureRatio { get; set; } = 0.5;

    public int CircuitBreakerMinimumThroughput { get; set; } = 10;

    public int CircuitBreakerSamplingDurationSeconds { get; set; } = 60;

    public int CircuitBreakerBreakDurationSeconds { get; set; } = 30;

    public Dictionary<string, HttpResilienceClientOptions> Clients { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class HttpResilienceClientOptions
{
    public int? MaxRetryAttempts { get; set; }

    public int? RetryDelaySeconds { get; set; }

    public int? MaxRetryDelaySeconds { get; set; }

    public int? AttemptTimeoutSeconds { get; set; }

    public int? TotalRequestTimeoutSeconds { get; set; }

    public bool? EnableCircuitBreaker { get; set; }

    public double? CircuitBreakerFailureRatio { get; set; }

    public int? CircuitBreakerMinimumThroughput { get; set; }

    public int? CircuitBreakerSamplingDurationSeconds { get; set; }

    public int? CircuitBreakerBreakDurationSeconds { get; set; }
}

public sealed record HttpResilienceSettings(
    int MaxRetryAttempts,
    int RetryDelaySeconds,
    int MaxRetryDelaySeconds,
    int AttemptTimeoutSeconds,
    int TotalRequestTimeoutSeconds,
    bool EnableCircuitBreaker,
    double CircuitBreakerFailureRatio,
    int CircuitBreakerMinimumThroughput,
    int CircuitBreakerSamplingDurationSeconds,
    int CircuitBreakerBreakDurationSeconds)
{
    public static HttpResilienceSettings Merge(
        HttpResilienceOptions defaults,
        HttpResilienceClientOptions? clientOverride) =>
        new(
            MaxRetryAttempts: clientOverride?.MaxRetryAttempts ?? defaults.MaxRetryAttempts,
            RetryDelaySeconds: clientOverride?.RetryDelaySeconds ?? defaults.RetryDelaySeconds,
            MaxRetryDelaySeconds: clientOverride?.MaxRetryDelaySeconds ?? defaults.MaxRetryDelaySeconds,
            AttemptTimeoutSeconds: clientOverride?.AttemptTimeoutSeconds ?? defaults.AttemptTimeoutSeconds,
            TotalRequestTimeoutSeconds: clientOverride?.TotalRequestTimeoutSeconds ?? defaults.TotalRequestTimeoutSeconds,
            EnableCircuitBreaker: clientOverride?.EnableCircuitBreaker ?? defaults.EnableCircuitBreaker,
            CircuitBreakerFailureRatio: clientOverride?.CircuitBreakerFailureRatio ?? defaults.CircuitBreakerFailureRatio,
            CircuitBreakerMinimumThroughput: clientOverride?.CircuitBreakerMinimumThroughput ?? defaults.CircuitBreakerMinimumThroughput,
            CircuitBreakerSamplingDurationSeconds: clientOverride?.CircuitBreakerSamplingDurationSeconds ?? defaults.CircuitBreakerSamplingDurationSeconds,
            CircuitBreakerBreakDurationSeconds: clientOverride?.CircuitBreakerBreakDurationSeconds ?? defaults.CircuitBreakerBreakDurationSeconds);

    public static int ResolveCircuitBreakerSamplingDurationSeconds(
        int attemptTimeoutSeconds,
        int configuredSamplingDurationSeconds) =>
        Math.Max(Math.Max(1, configuredSamplingDurationSeconds), Math.Max(1, attemptTimeoutSeconds) * 2);
}
