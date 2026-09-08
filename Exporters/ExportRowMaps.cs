using CsvHelper.Configuration;

namespace WindowsIncidentAnalyzer.Exporters;

public sealed class FindingCsvRowMap : ClassMap<FindingCsvRow>
{
    public FindingCsvRowMap()
    {
        Map(m => m.Severity).Name("Severity").Index(0);
        Map(m => m.FindingId).Name("Finding ID").Index(1);
        Map(m => m.RuleName).Name("Rule").Index(2);
        Map(m => m.RuleId).Name("Rule ID").Index(3);
        Map(m => m.RuleTitle).Name("Rule Title").Index(4);
        Map(m => m.Title).Name("Title").Index(5);
        Map(m => m.Category).Name("Category").Index(6);
        Map(m => m.EventType).Name("Event Type").Index(7);
        Map(m => m.CategoryMatchesEvent).Name("Category Matches Event").Index(8);
        Map(m => m.SeverityMatchesEvent).Name("Severity Matches Event").Index(9);
        Map(m => m.RequestedSeverity).Name("Requested Severity").Index(10);
        Map(m => m.TimeUtc).Name("Time UTC").Index(11);
        Map(m => m.CreatedUtc).Name("Created UTC").Index(12);
        Map(m => m.Host).Name("Host").Index(13);
        Map(m => m.Domain).Name("Domain").Index(14);
        Map(m => m.User).Name("User").Index(15);
        Map(m => m.UserSid).Name("User SID").Index(16);
        Map(m => m.LogonId).Name("Logon ID").Index(17);
        Map(m => m.EventId).Name("Event ID").Index(18);
        Map(m => m.EventRecordId).Name("Event Record ID").Index(19);
        Map(m => m.Provider).Name("Provider").Index(20);
        Map(m => m.Channel).Name("Channel").Index(21);
        Map(m => m.ProcessId).Name("PID").Index(22);
        Map(m => m.ParentProcessId).Name("PPID").Index(23);
        Map(m => m.ProcessName).Name("Process").Index(24);
        Map(m => m.Image).Name("Image").Index(25);
        Map(m => m.CommandLine).Name("Command Line").Index(26);
        Map(m => m.ParentImage).Name("Parent Image").Index(27);
        Map(m => m.ParentCommandLine).Name("Parent Command Line").Index(28);
        Map(m => m.WorkingDirectory).Name("Working Directory").Index(29);
        Map(m => m.IntegrityLevel).Name("Integrity Level").Index(30);
        Map(m => m.ElevationType).Name("Elevation").Index(31);
        Map(m => m.SourceIp).Name("Source IP").Index(32);
        Map(m => m.SourcePort).Name("Source Port").Index(33);
        Map(m => m.DestinationIp).Name("Destination IP").Index(34);
        Map(m => m.DestinationPort).Name("Destination Port").Index(35);
        Map(m => m.FilePath).Name("File Path").Index(36);
        Map(m => m.Sha256).Name("SHA256").Index(37);
        Map(m => m.Md5).Name("MD5").Index(38);
        Map(m => m.Signer).Name("Signer").Index(39);
        Map(m => m.OriginalFileName).Name("Original File Name").Index(40);
        Map(m => m.SigmaId).Name("Sigma ID").Index(41);
        Map(m => m.SigmaStatus).Name("Sigma Status").Index(42);
        Map(m => m.MitreTactic).Name("MITRE Tactic").Index(43);
        Map(m => m.MitreTechnique).Name("MITRE Technique").Index(44);
        Map(m => m.MitreTechniqueName).Name("MITRE Technique Name").Index(45);
        Map(m => m.MitreTacticName).Name("MITRE Tactic Name").Index(46);
        Map(m => m.MitreUrl).Name("MITRE URL").Index(47);
        Map(m => m.MitreTags).Name("MITRE Tags").Index(48);
        Map(m => m.MatchedSelection).Name("Sigma Selection").Index(49);
        Map(m => m.MatchedFields).Name("Matched Fields").Index(50);
        Map(m => m.MatchedValues).Name("Matched Values").Index(51);
        Map(m => m.Condition).Name("Condition").Index(52);
        Map(m => m.Reason).Name("Reason").Index(53);
        Map(m => m.Description).Name("Description").Index(54);
        Map(m => m.Details).Name("Details").Index(55);
        Map(m => m.RelatedEventRowIds).Name("Related Event IDs").Index(56);
        Map(m => m.RawEvent).Name("Raw Event JSON").Index(57);
        Map(m => m.RawXml).Name("Raw XML").Index(58);
    }
}

public sealed class TimelineCsvRowMap : ClassMap<TimelineCsvRow>
{
    public TimelineCsvRowMap()
    {
        Map(m => m.TimestampUtc).Name("Time UTC").Index(0);
        Map(m => m.EventRowId).Name("Event Row ID").Index(1);
        Map(m => m.Host).Name("Host").Index(2);
        Map(m => m.EventId).Name("Event ID").Index(3);
        Map(m => m.Source).Name("Source").Index(4);
        Map(m => m.User).Name("User").Index(5);
        Map(m => m.Process).Name("Process").Index(6);
        Map(m => m.Ip).Name("IP").Index(7);
        Map(m => m.Description).Name("Description").Index(8);
        Map(m => m.Severity).Name("Severity").Index(9);
    }
}

public sealed class IocCsvRowMap : ClassMap<IocCsvRow>
{
    public IocCsvRowMap()
    {
        Map(m => m.IocType).Name("IOC Type").Index(0);
        Map(m => m.IocValue).Name("IOC Value").Index(1);
        Map(m => m.EventId).Name("Event ID").Index(2);
        Map(m => m.EventRowId).Name("Event Row ID").Index(3);
        Map(m => m.TimestampUtc).Name("Time UTC").Index(4);
        Map(m => m.Host).Name("Host").Index(5);
        Map(m => m.RelatedProcess).Name("Process").Index(6);
        Map(m => m.RelatedUser).Name("User").Index(7);
        Map(m => m.MatchedField).Name("Matched Field").Index(8);
    }
}

public sealed class CveCsvRowMap : ClassMap<CveCsvRow>
{
    public CveCsvRowMap()
    {
        Map(m => m.CveId).Name("CVE ID").Index(0);
        Map(m => m.VulnerabilityName).Name("Vulnerability Name").Index(1);
        Map(m => m.ShortDescription).Name("Description").Index(2);
        Map(m => m.VendorProject).Name("Vendor").Index(3);
        Map(m => m.Product).Name("Product").Index(4);
        Map(m => m.KnownRansomwareUse).Name("Known Ransomware Use").Index(5);
        Map(m => m.EventId).Name("Event ID").Index(6);
        Map(m => m.EventRowId).Name("Event Row ID").Index(7);
        Map(m => m.TimestampUtc).Name("Time UTC").Index(8);
        Map(m => m.Host).Name("Host").Index(9);
        Map(m => m.RelatedProcess).Name("Process").Index(10);
        Map(m => m.RelatedUser).Name("User").Index(11);
        Map(m => m.MatchedField).Name("Matched Field").Index(12);
    }
}

public sealed class CorrelationCsvRowMap : ClassMap<CorrelationCsvRow>
{
    public CorrelationCsvRowMap()
    {
        Map(m => m.CorrelationId).Name("Correlation ID").Index(0);
        Map(m => m.Severity).Name("Severity").Index(1);
        Map(m => m.Scenario).Name("Scenario").Index(2);
        Map(m => m.Title).Name("Title").Index(3);
        Map(m => m.TimeUtc).Name("Time UTC").Index(4);
        Map(m => m.CreatedUtc).Name("Created UTC").Index(5);
        Map(m => m.User).Name("User").Index(6);
        Map(m => m.SourceIpAddress).Name("Source IP").Index(7);
        Map(m => m.ComputerName).Name("Host").Index(8);
        Map(m => m.Interpretation).Name("Interpretation").Index(9);
        Map(m => m.Details).Name("Details").Index(10);
        Map(m => m.RelatedEventRowIds).Name("Related Event IDs").Index(11);
    }
}

public sealed class EventCsvRowMap : ClassMap<EventCsvRow>
{
    public EventCsvRowMap()
    {
        Map(m => m.EventRowId).Name("Event Row ID").Index(0);
        Map(m => m.TimeCreatedUtc).Name("Time UTC").Index(1);
        Map(m => m.ComputerName).Name("Host").Index(2);
        Map(m => m.LogName).Name("Log").Index(3);
        Map(m => m.ProviderName).Name("Provider").Index(4);
        Map(m => m.EventId).Name("Event ID").Index(5);
        Map(m => m.EventRecordId).Name("Event Record ID").Index(6);
        Map(m => m.Level).Name("Level").Index(7);
        Map(m => m.User).Name("User").Index(8);
        Map(m => m.Domain).Name("Domain").Index(9);
        Map(m => m.TargetUserName).Name("Target User").Index(10);
        Map(m => m.TargetDomainName).Name("Target Domain").Index(11);
        Map(m => m.ProcessName).Name("Process").Index(12);
        Map(m => m.ProcessPath).Name("Image").Index(13);
        Map(m => m.ProcessId).Name("PID").Index(14);
        Map(m => m.ParentProcessName).Name("Parent Process").Index(15);
        Map(m => m.ParentProcessId).Name("PPID").Index(16);
        Map(m => m.ParentCommandLine).Name("Parent Command Line").Index(17);
        Map(m => m.CommandLine).Name("Command Line").Index(18);
        Map(m => m.SourceIpAddress).Name("Source IP").Index(19);
        Map(m => m.DestinationIpAddress).Name("Destination IP").Index(20);
        Map(m => m.SourcePort).Name("Source Port").Index(21);
        Map(m => m.DestinationPort).Name("Destination Port").Index(22);
        Map(m => m.WorkstationName).Name("Workstation").Index(23);
        Map(m => m.LogonType).Name("Logon Type").Index(24);
        Map(m => m.ScriptBlock).Name("Script Block").Index(25);
        Map(m => m.ScriptBlockHash).Name("Script Block Hash").Index(26);
        Map(m => m.Hashes).Name("Hashes").Index(27);
        Map(m => m.ProcessGuid).Name("Process GUID").Index(28);
        Map(m => m.ParentProcessGuid).Name("Parent Process GUID").Index(29);
        Map(m => m.QueryName).Name("DNS Query").Index(30);
        Map(m => m.TaskName).Name("Task Name").Index(31);
        Map(m => m.ServiceName).Name("Service Name").Index(32);
        Map(m => m.PropertiesJson).Name("Properties JSON").Index(33);
        Map(m => m.RawXml).Name("Raw XML").Index(34);
    }
}

public sealed class StatisticsCsvRowMap : ClassMap<StatisticsCsvRow>
{
    public StatisticsCsvRowMap()
    {
        Map(m => m.Section).Name("Section").Index(0);
        Map(m => m.Key).Name("Key").Index(1);
        Map(m => m.Value).Name("Value").Index(2);
    }
}
