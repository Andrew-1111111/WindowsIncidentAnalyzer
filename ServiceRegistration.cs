using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WindowsIncidentAnalyzer.Configuration;
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

        services.AddSingleton<SqliteDatabase>();
        services.AddSingleton<CliErrorHandler>();
        services.AddSingleton<EventXmlParser>();

        services.AddSingleton<IEventRepository, EventRepository>();
        services.AddSingleton<IFindingRepository, FindingRepository>();
        services.AddSingleton<IIocRepository, IocRepository>();
        services.AddSingleton<IIncidentRepository, IncidentRepository>();
        services.AddSingleton<ICorrelationRepository, CorrelationRepository>();
        services.AddSingleton<ISigmaRuleRepository, SigmaRuleRepository>();

        services.AddSingleton<SigmaRuleEngine>();
        services.AddSingleton<ISigmaRuleService, SigmaRuleService>();

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
}
