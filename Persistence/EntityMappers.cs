using System.Text.Json;
using WindowsIncidentAnalyzer.Persistence.Entities;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Persistence;

public static class EntityMappers
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static EventEntity ToEntity(WindowsEvent evt, string eventKey, int completenessScore) =>
        new()
        {
            ComputerName = evt.ComputerName,
            LogName = evt.LogName,
            ProviderName = evt.ProviderName,
            EventId = evt.EventId,
            EventRecordId = evt.EventRecordId,
            EventKey = eventKey,
            CompletenessScore = completenessScore,
            TimeCreatedUtc = evt.TimeCreatedUtc,
            Level = evt.Level,
            User = evt.User,
            Domain = evt.Domain,
            ProcessName = evt.ProcessName,
            ProcessId = evt.ProcessId,
            ParentProcessName = evt.ParentProcessName,
            ParentProcessId = evt.ParentProcessId,
            CommandLine = evt.CommandLine,
            SourceIpAddress = evt.SourceIpAddress,
            DestinationIpAddress = evt.DestinationIpAddress,
            WorkstationName = evt.WorkstationName,
            TargetUserName = evt.TargetUserName,
            TargetDomainName = evt.TargetDomainName,
            RawXml = evt.RawXml,
            PropertiesJson = JsonSerializer.Serialize(evt.Properties, JsonOptions),
            ScriptBlock = evt.ScriptBlock,
            ScriptBlockHash = evt.ScriptBlockHash,
            Hashes = evt.Hashes,
            ProcessGuid = evt.ProcessGuid,
            ParentProcessGuid = evt.ParentProcessGuid,
            ParentCommandLine = evt.ParentCommandLine,
            SourcePort = evt.SourcePort,
            DestinationPort = evt.DestinationPort,
            QueryName = evt.QueryName,
            TaskName = evt.TaskName,
            ServiceName = evt.ServiceName,
            LogonType = evt.LogonType,
            ProcessPath = evt.ProcessPath
        };

    public static void MergeRicher(EventEntity target, WindowsEvent source, int completenessScore)
    {
        target.ComputerName = Coalesce(source.ComputerName, target.ComputerName);
        target.LogName = Coalesce(source.LogName, target.LogName);
        target.ProviderName = Coalesce(source.ProviderName, target.ProviderName);
        target.EventId = source.EventId;
        target.EventRecordId = source.EventRecordId ?? target.EventRecordId;
        target.CompletenessScore = completenessScore;
        target.TimeCreatedUtc = source.TimeCreatedUtc;
        target.Level = Coalesce(source.Level, target.Level);
        target.User = Coalesce(source.User, target.User);
        target.Domain = Coalesce(source.Domain, target.Domain);
        target.ProcessName = Coalesce(source.ProcessName, target.ProcessName);
        target.ProcessId = source.ProcessId ?? target.ProcessId;
        target.ParentProcessName = Coalesce(source.ParentProcessName, target.ParentProcessName);
        target.ParentProcessId = source.ParentProcessId ?? target.ParentProcessId;
        target.CommandLine = Coalesce(source.CommandLine, target.CommandLine);
        target.SourceIpAddress = Coalesce(source.SourceIpAddress, target.SourceIpAddress);
        target.DestinationIpAddress = Coalesce(source.DestinationIpAddress, target.DestinationIpAddress);
        target.WorkstationName = Coalesce(source.WorkstationName, target.WorkstationName);
        target.TargetUserName = Coalesce(source.TargetUserName, target.TargetUserName);
        target.TargetDomainName = Coalesce(source.TargetDomainName, target.TargetDomainName);
        target.RawXml = Coalesce(source.RawXml, target.RawXml);
        var propsJson = JsonSerializer.Serialize(source.Properties, JsonOptions);
        target.PropertiesJson = Coalesce(propsJson, target.PropertiesJson);
        target.ScriptBlock = Coalesce(source.ScriptBlock, target.ScriptBlock);
        target.ScriptBlockHash = Coalesce(source.ScriptBlockHash, target.ScriptBlockHash);
        target.Hashes = Coalesce(source.Hashes, target.Hashes);
        target.ProcessGuid = Coalesce(source.ProcessGuid, target.ProcessGuid);
        target.ParentProcessGuid = Coalesce(source.ParentProcessGuid, target.ParentProcessGuid);
        target.ParentCommandLine = Coalesce(source.ParentCommandLine, target.ParentCommandLine);
        target.SourcePort = source.SourcePort ?? target.SourcePort;
        target.DestinationPort = source.DestinationPort ?? target.DestinationPort;
        target.QueryName = Coalesce(source.QueryName, target.QueryName);
        target.TaskName = Coalesce(source.TaskName, target.TaskName);
        target.ServiceName = Coalesce(source.ServiceName, target.ServiceName);
        target.LogonType = source.LogonType ?? target.LogonType;
        target.ProcessPath = Coalesce(source.ProcessPath, target.ProcessPath);
    }

    public static WindowsEvent ToDomain(EventEntity entity) =>
        new()
        {
            Id = entity.Id,
            ComputerName = entity.ComputerName,
            LogName = entity.LogName,
            ProviderName = entity.ProviderName,
            EventId = entity.EventId,
            EventRecordId = entity.EventRecordId,
            TimeCreatedUtc = entity.TimeCreatedUtc,
            Level = entity.Level,
            User = entity.User,
            Domain = entity.Domain,
            ProcessName = entity.ProcessName,
            ProcessId = entity.ProcessId,
            ParentProcessName = entity.ParentProcessName,
            ParentProcessId = entity.ParentProcessId,
            CommandLine = entity.CommandLine,
            SourceIpAddress = entity.SourceIpAddress,
            DestinationIpAddress = entity.DestinationIpAddress,
            WorkstationName = entity.WorkstationName,
            TargetUserName = entity.TargetUserName,
            TargetDomainName = entity.TargetDomainName,
            RawXml = entity.RawXml,
            Properties = DeserializeProperties(entity.PropertiesJson),
            ScriptBlock = entity.ScriptBlock,
            ScriptBlockHash = entity.ScriptBlockHash,
            Hashes = entity.Hashes,
            ProcessGuid = entity.ProcessGuid,
            ParentProcessGuid = entity.ParentProcessGuid,
            ParentCommandLine = entity.ParentCommandLine,
            SourcePort = entity.SourcePort,
            DestinationPort = entity.DestinationPort,
            QueryName = entity.QueryName,
            TaskName = entity.TaskName,
            ServiceName = entity.ServiceName,
            LogonType = entity.LogonType,
            ProcessPath = entity.ProcessPath
        };

    public static FindingEntity ToEntity(SecurityFinding finding) =>
        new()
        {
            RuleName = finding.RuleName,
            Title = finding.Title,
            Description = finding.Description,
            Severity = finding.Severity.ToString(),
            TimeUtc = finding.TimeUtc,
            ComputerName = finding.ComputerName,
            User = finding.User,
            SourceIpAddress = finding.SourceIpAddress,
            ProcessName = finding.ProcessName,
            Details = finding.Details,
            RelatedEventRowIds = JsonSerializer.Serialize(finding.RelatedEventRowIds),
            ContextJson = FindingContextSerializer.Serialize(finding.Context),
            CreatedUtc = finding.CreatedUtc
        };

    public static SecurityFinding ToDomain(FindingEntity entity)
    {
        var finding = new SecurityFinding
        {
            Id = entity.Id,
            RuleName = entity.RuleName,
            Title = entity.Title,
            Description = entity.Description ?? string.Empty,
            Severity = Enum.TryParse<DetectionSeverity>(entity.Severity, out var sev) ? sev : DetectionSeverity.Info,
            TimeUtc = entity.TimeUtc,
            ComputerName = entity.ComputerName,
            User = entity.User,
            SourceIpAddress = entity.SourceIpAddress,
            ProcessName = entity.ProcessName,
            Details = entity.Details,
            RelatedEventRowIds = DeserializeIds(entity.RelatedEventRowIds),
            CreatedUtc = entity.CreatedUtc
        };

        FindingContextMapper.SyncLegacyFields(finding, FindingContextSerializer.Deserialize(entity.ContextJson));
        return finding;
    }

    public static IocEntity ToEntity(Ioc ioc) =>
        new()
        {
            Type = ioc.Type.Trim().ToLowerInvariant(),
            Value = ioc.Value.Trim(),
            Source = ioc.Source,
            Comment = ioc.Comment,
            ImportedUtc = ioc.ImportedUtc
        };

    public static Ioc ToDomain(IocEntity entity) =>
        new()
        {
            Id = entity.Id,
            Type = entity.Type,
            Value = entity.Value,
            Source = entity.Source,
            Comment = entity.Comment,
            ImportedUtc = entity.ImportedUtc
        };

    public static IncidentEntity ToEntity(Incident incident) =>
        new()
        {
            Title = incident.Title,
            CreatedUtc = incident.CreatedUtc,
            EventsAnalyzed = incident.EventsAnalyzed,
            FindingsCritical = incident.FindingsCritical,
            FindingsHigh = incident.FindingsHigh,
            FindingsMedium = incident.FindingsMedium,
            FindingsLow = incident.FindingsLow,
            FindingsInfo = incident.FindingsInfo,
            SummaryJson = incident.SummaryJson
        };

    public static Incident ToDomain(IncidentEntity entity) =>
        new()
        {
            Id = entity.Id,
            Title = entity.Title,
            CreatedUtc = entity.CreatedUtc,
            EventsAnalyzed = entity.EventsAnalyzed,
            FindingsCritical = entity.FindingsCritical,
            FindingsHigh = entity.FindingsHigh,
            FindingsMedium = entity.FindingsMedium,
            FindingsLow = entity.FindingsLow,
            FindingsInfo = entity.FindingsInfo,
            SummaryJson = entity.SummaryJson
        };

    public static CorrelationEntity ToEntity(EventCorrelation item) =>
        new()
        {
            Scenario = item.Scenario,
            Title = item.Title,
            Interpretation = item.Interpretation,
            Severity = item.Severity.ToString(),
            TimeUtc = item.TimeUtc,
            User = item.User,
            ComputerName = item.ComputerName,
            SourceIpAddress = item.SourceIpAddress,
            Details = item.Details,
            RelatedEventRowIds = JsonSerializer.Serialize(item.RelatedEventRowIds),
            CreatedUtc = item.CreatedUtc
        };

    public static EventCorrelation ToDomain(CorrelationEntity entity) =>
        new()
        {
            Id = entity.Id,
            Scenario = entity.Scenario,
            Title = entity.Title,
            Interpretation = entity.Interpretation ?? string.Empty,
            Severity = Enum.TryParse<DetectionSeverity>(entity.Severity, out var sev) ? sev : DetectionSeverity.Medium,
            TimeUtc = entity.TimeUtc,
            User = entity.User,
            ComputerName = entity.ComputerName,
            SourceIpAddress = entity.SourceIpAddress,
            Details = entity.Details ?? string.Empty,
            RelatedEventRowIds = DeserializeIds(entity.RelatedEventRowIds),
            CreatedUtc = entity.CreatedUtc
        };

    public static CveEntity ToEntity(CveRecord record) =>
        new()
        {
            CveId = record.CveId,
            VendorProject = record.VendorProject,
            Product = record.Product,
            VulnerabilityName = record.VulnerabilityName,
            ShortDescription = record.ShortDescription,
            RequiredAction = record.RequiredAction,
            DateAddedUtc = record.DateAddedUtc,
            DueDateUtc = record.DueDateUtc,
            KnownRansomwareUse = record.KnownRansomwareUse,
            Notes = record.Notes,
            Source = record.Source,
            ImportedUtc = record.ImportedUtc
        };

    public static CveRecord ToDomain(CveEntity entity) =>
        new()
        {
            CveId = entity.CveId,
            VendorProject = entity.VendorProject,
            Product = entity.Product,
            VulnerabilityName = entity.VulnerabilityName,
            ShortDescription = entity.ShortDescription,
            RequiredAction = entity.RequiredAction,
            DateAddedUtc = entity.DateAddedUtc,
            DueDateUtc = entity.DueDateUtc,
            KnownRansomwareUse = entity.KnownRansomwareUse,
            Notes = entity.Notes,
            Source = entity.Source,
            ImportedUtc = entity.ImportedUtc
        };

    public static List<long> DeserializeIds(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<long>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static Dictionary<string, string> DeserializeProperties(string? propsJson)
    {
        try
        {
            return string.IsNullOrWhiteSpace(propsJson)
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : JsonSerializer.Deserialize<Dictionary<string, string>>(propsJson, JsonOptions)
                  ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private static string? Coalesce(string? preferred, string? fallback) =>
        preferred ?? fallback;
}
