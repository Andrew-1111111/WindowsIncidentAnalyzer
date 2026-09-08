using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Data;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Sigma;

namespace WindowsIncidentAnalyzer;

public static class ServiceRegistration
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<AnalyzerOptions>(configuration);
        services.Configure<DetectionRulesOptions>(configuration);

        var httpResilience = configuration.GetSection(nameof(AnalyzerOptions.HttpResilience)).Get<HttpResilienceOptions>()
            ?? new HttpResilienceOptions();

        AddWiaHttpClient(services, httpResilience, WebDownloadClients.Default);
        AddWiaHttpClient(
            services,
            httpResilience,
            WebDownloadClients.IocFeeds,
            static client => client.Timeout = Timeout.InfiniteTimeSpan,
            static () => new SocketsHttpHandler
            {
                ConnectTimeout = TimeSpan.FromSeconds(15),
                MaxConnectionsPerServer = 16,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5)
            });
        AddWiaHttpClient(services, httpResilience, WebDownloadClients.Sigma);
        AddWiaHttpClient(services, httpResilience, WebDownloadClients.Mitre);
        AddWiaHttpClient(services, httpResilience, WebDownloadClients.Cve);

        services.AddSingleton<IWebDownloadService, WebDownloadService>();
        services.AddSingleton<InvestigationDatabase>();
        services.AddDbContextFactory<InvestigationDbContext>((sp, options) =>
        {
            var database = sp.GetRequiredService<InvestigationDatabase>();
            options.UseSqlite(database.ConnectionString);
        });
        services.AddSingleton<CliErrorHandler>();
        services.AddSingleton<EventXmlParser>();
        services.AddSingleton<EventRecordNormalizer>();

        services.AddSingleton<IEventRepository, EventRepository>();
        services.AddSingleton<IFindingRepository, FindingRepository>();
        services.AddSingleton<IIocRepository, IocRepository>();
        services.AddSingleton<ICveRepository, CveRepository>();
        services.AddSingleton<IMitreAttackRepository, MitreAttackRepository>();
        services.AddSingleton<IIncidentRepository, IncidentRepository>();
        services.AddSingleton<ICorrelationRepository, CorrelationRepository>();
        services.AddSingleton<ISigmaRuleRepository, SigmaRuleRepository>();

        services.AddSingleton<SigmaRuleEngine>();
        services.AddSingleton<ISigmaRuleService, SigmaRuleService>();
        services.AddSingleton<IMitreAttackService, MitreAttackService>();
        services.AddSingleton<ICveDatabaseService, CveDatabaseService>();
        services.AddSingleton<IMitreAttackEnrichmentService, MitreAttackEnrichmentService>();
        services.AddSingleton<ICveDetectionService, CveDetectionService>();

        services.AddSingleton<IEventLogService, EventLogService>();
        services.AddSingleton<IEvtxParserService, EvtxParserService>();
        services.AddSingleton<IEventIngestionService, EventIngestionService>();
        services.AddSingleton<ITimelineService, TimelineService>();
        services.AddSingleton<ICorrelationService, CorrelationService>();
        services.AddSingleton<ISuspiciousActivityService, SuspiciousActivityService>();
        services.AddSingleton<IIocDetectionService, IocDetectionService>();
        services.AddSingleton<IIocFeedService, IocFeedService>();
        services.AddSingleton<IExportService, ExportService>();
        services.AddSingleton<IStatisticsService, StatisticsService>();
        services.AddSingleton<IInvestigationService, InvestigationService>();

        services.AddSingleton<IDetectionRule, FailedLogonDetector>();
        services.AddSingleton<IDetectionRule, SuccessfulLogonDetector>();
        services.AddSingleton<IDetectionRule, BruteForceDetector>();
        services.AddSingleton<IDetectionRule, NewUserDetector>();
        services.AddSingleton<IDetectionRule, PrivilegeChangeDetector>();
        services.AddSingleton<IDetectionRule, ProcessCreationDetector>();
        services.AddSingleton<IDetectionRule, SuspiciousPowerShellDetector>();
        services.AddSingleton<IDetectionRule, ScheduledTaskDetector>();
        services.AddSingleton<IDetectionRule, ServiceInstallationDetector>();
        services.AddSingleton<IDetectionRule, RdpActivityDetector>();
        services.AddSingleton<IDetectionRule, LogClearingDetector>();
        services.AddSingleton<IDetectionRule, CredentialAccessDetector>();
        services.AddSingleton<IDetectionRule, DefenseEvasionDetector>();
        services.AddSingleton<IDetectionRule, PersistenceAndLolbinDetector>();
        services.AddSingleton<IDetectionRule, LateralMovementAndDiscoveryDetector>();
        services.AddSingleton<IDetectionRule, SecurityPolicyChangeDetector>();
        services.AddSingleton<IDetectionRule, MalwareBehaviorDetector>();
        services.AddSingleton<IDetectionRule, KerberosAndDirectoryAttackDetector>();
        services.AddSingleton<IDetectionRule, SigmaRuleDetector>();

        services.AddSingleton<IExporter, CsvExporter>();
        services.AddSingleton<IExporter, JsonExporter>();
        services.AddSingleton<IExporter, HtmlExporter>();

        return services;
    }

    private static void AddWiaHttpClient(
        IServiceCollection services,
        HttpResilienceOptions resilience,
        string clientName,
        Action<HttpClient>? configureClient = null,
        Func<SocketsHttpHandler>? configureHandler = null)
    {
        var builder = services.AddHttpClient(clientName, client =>
        {
            ConfigureHttpClient(client);
            configureClient?.Invoke(client);
        });

        if (configureHandler != null)
        {
            builder.ConfigurePrimaryHttpMessageHandler(configureHandler);
        }

        builder.AddWiaResilienceHandler(resilience, clientName);
    }

    private static void ConfigureHttpClient(HttpClient client)
    {
        client.DefaultRequestHeaders.UserAgent.ParseAdd("WindowsIncidentAnalyzer/1.0 (defensive DFIR; +local investigation)");
        client.DefaultRequestHeaders.Accept.ParseAdd("text/plain, application/json, */*");
    }
}
