using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ExportRowBuilderTests
{
    private static readonly DateTime SampleTime = new(2026, 6, 1, 14, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void BuildEventMap_IndexesEventsById()
    {
        var data = new InvestigationExport
        {
            Events =
            [
                new WindowsEvent { Id = 1, EventId = 4624 },
                new WindowsEvent { Id = 2, EventId = 4688 }
            ]
        };

        var map = ExportRowBuilder.BuildEventMap(data);

        Assert.Equal(2, map.Count);
        Assert.Equal(4624, map[1].EventId);
        Assert.Equal(4688, map[2].EventId);
    }

    [Fact]
    public void BuildFindingRows_FallsBackToRelatedEventWhenContextMissingFields()
    {
        var evt = new WindowsEvent
        {
            Id = 7,
            EventId = 4688,
            EventRecordId = 555,
            ComputerName = "HOST01",
            TargetDomainName = "CORP",
            TargetUserName = "alice",
            ProviderName = "Microsoft-Windows-Security-Auditing",
            LogName = "Security",
            ProcessName = "whoami.exe",
            ProcessPath = @"C:\Windows\System32\whoami.exe",
            ProcessId = 1000,
            ParentProcessId = 500,
            ParentProcessName = "cmd.exe",
            CommandLine = "whoami /all",
            ParentCommandLine = "cmd.exe",
            SourceIpAddress = "10.0.0.5",
            SourcePort = 445,
            DestinationIpAddress = "10.0.0.10",
            DestinationPort = 139,
            RawXml = "<Event/>"
        };

        var finding = new SecurityFinding
        {
            Id = 99,
            Severity = DetectionSeverity.High,
            RuleName = "SuspiciousProcess",
            Title = "Process spawned",
            Description = "desc",
            Details = "details",
            TimeUtc = SampleTime,
            CreatedUtc = SampleTime.AddHours(1),
            RelatedEventRowIds = [7],
            Context = new FindingContext()
        };

        var rows = ExportRowBuilder.BuildFindingRows([finding], new Dictionary<long, WindowsEvent> { [7] = evt }).ToList();

        Assert.Single(rows);
        var row = rows[0];
        Assert.Equal("High", row.Severity);
        Assert.Equal(99, row.FindingId);
        Assert.Equal("HOST01", row.Host);
        Assert.Equal("CORP", row.Domain);
        Assert.Equal("alice", row.User);
        Assert.Equal(4688, row.EventId);
        Assert.Equal(555L, row.EventRecordId);
        Assert.Equal("Microsoft-Windows-Security-Auditing", row.Provider);
        Assert.Equal("Security", row.Channel);
        Assert.Equal(1000, row.ProcessId);
        Assert.Equal(500, row.ParentProcessId);
        Assert.Equal("whoami.exe", row.ProcessName);
        Assert.Equal(@"C:\Windows\System32\whoami.exe", row.Image);
        Assert.Equal("whoami /all", row.CommandLine);
        Assert.Equal("cmd.exe", row.ParentImage);
        Assert.Equal("cmd.exe", row.ParentCommandLine);
        Assert.Equal("10.0.0.5", row.SourceIp);
        Assert.Equal(445, row.SourcePort);
        Assert.Equal("10.0.0.10", row.DestinationIp);
        Assert.Equal(139, row.DestinationPort);
        Assert.Equal("<Event/>", row.RawXml);
        Assert.Equal("7", row.RelatedEventRowIds);
    }

    [Fact]
    public void BuildFindingRows_PrefersContextOverFindingAndEvent()
    {
        var evt = new WindowsEvent
        {
            Id = 1,
            ComputerName = "EVENT-HOST",
            TargetUserName = "event-user",
            CommandLine = "event-cmd"
        };

        var finding = new SecurityFinding
        {
            Id = 1,
            Severity = DetectionSeverity.Medium,
            RuleName = "Rule",
            Title = "Title",
            ComputerName = "FINDING-HOST",
            User = "finding-user",
            ProcessName = "finding.exe",
            TimeUtc = SampleTime,
            CreatedUtc = SampleTime,
            RelatedEventRowIds = [1],
            Context = new FindingContext
            {
                Host = "CTX-HOST",
                User = "ctx-user",
                CommandLine = "ctx-cmd",
                TimestampUtc = SampleTime.AddMinutes(5),
                CategoryMatchesEvent = true,
                SeverityMatchesEvent = false,
                RequestedSeverity = DetectionSeverity.Critical,
                MitreTags = ["attack.execution"]
            }
        };

        var row = ExportRowBuilder.BuildFindingRows([finding], new Dictionary<long, WindowsEvent> { [1] = evt }).Single();

        Assert.Equal("CTX-HOST", row.Host);
        Assert.Equal("ctx-user", row.User);
        Assert.Equal("ctx-cmd", row.CommandLine);
        Assert.Equal("2026-06-01 14:05:00", row.TimeUtc);
        Assert.Equal("yes", row.CategoryMatchesEvent);
        Assert.Equal("no", row.SeverityMatchesEvent);
        Assert.Equal("Critical", row.RequestedSeverity);
        Assert.Equal("attack.execution", row.MitreTags);
    }

    [Fact]
    public void BuildTimelineRows_MapsAllFields()
    {
        var item = new TimelineItem
        {
            TimestampUtc = SampleTime,
            EventRowId = 3,
            Host = "HOST01",
            EventId = 4624,
            Source = "Security",
            User = "bob",
            Process = "logon.exe",
            Ip = "192.168.1.1",
            Description = "Successful logon",
            Severity = DetectionSeverity.Info
        };

        var row = ExportRowBuilder.BuildTimelineRows([item]).Single();

        Assert.Equal("2026-06-01 14:00:00", row.TimestampUtc);
        Assert.Equal(3, row.EventRowId);
        Assert.Equal("HOST01", row.Host);
        Assert.Equal(4624, row.EventId);
        Assert.Equal("Security", row.Source);
        Assert.Equal("bob", row.User);
        Assert.Equal("logon.exe", row.Process);
        Assert.Equal("192.168.1.1", row.Ip);
        Assert.Equal("Successful logon", row.Description);
        Assert.Equal("Info", row.Severity);
    }

    [Fact]
    public void BuildIocRows_MapsAllFields()
    {
        var match = new IocMatch
        {
            IocType = "ip",
            IocValue = "203.0.113.10",
            EventId = 3,
            EventRowId = 11,
            TimestampUtc = SampleTime,
            Host = "HOST01",
            RelatedProcess = "powershell.exe",
            RelatedUser = "alice",
            MatchedField = "DestinationIp"
        };

        var row = ExportRowBuilder.BuildIocRows([match]).Single();

        Assert.Equal("ip", row.IocType);
        Assert.Equal("203.0.113.10", row.IocValue);
        Assert.Equal(3, row.EventId);
        Assert.Equal(11, row.EventRowId);
        Assert.Equal("2026-06-01 14:00:00", row.TimestampUtc);
        Assert.Equal("HOST01", row.Host);
        Assert.Equal("powershell.exe", row.RelatedProcess);
        Assert.Equal("alice", row.RelatedUser);
        Assert.Equal("DestinationIp", row.MatchedField);
    }

    [Fact]
    public void BuildCveRows_MapsAllFields()
    {
        var match = new CveMatch
        {
            CveId = "CVE-2024-0001",
            VulnerabilityName = "Remote Code Execution",
            ShortDescription = "A critical flaw",
            VendorProject = "Vendor",
            Product = "ProductX",
            KnownRansomwareUse = "Known",
            EventId = 4688,
            EventRowId = 22,
            TimestampUtc = SampleTime,
            Host = "HOST02",
            RelatedProcess = "svc.exe",
            RelatedUser = "SYSTEM",
            MatchedField = "ProductVersion"
        };

        var row = ExportRowBuilder.BuildCveRows([match]).Single();

        Assert.Equal("CVE-2024-0001", row.CveId);
        Assert.Equal("Remote Code Execution", row.VulnerabilityName);
        Assert.Equal("A critical flaw", row.ShortDescription);
        Assert.Equal("Vendor", row.VendorProject);
        Assert.Equal("ProductX", row.Product);
        Assert.Equal("Known", row.KnownRansomwareUse);
        Assert.Equal(4688, row.EventId);
        Assert.Equal(22, row.EventRowId);
        Assert.Equal("HOST02", row.Host);
        Assert.Equal("svc.exe", row.RelatedProcess);
        Assert.Equal("SYSTEM", row.RelatedUser);
        Assert.Equal("ProductVersion", row.MatchedField);
    }

    [Fact]
    public void BuildCorrelationRows_MapsAllFields()
    {
        var correlation = new EventCorrelation
        {
            Id = 5,
            Severity = DetectionSeverity.High,
            Scenario = "LateralMovement",
            Title = "Multiple hosts",
            TimeUtc = SampleTime,
            CreatedUtc = SampleTime.AddHours(2),
            User = "admin",
            SourceIpAddress = "10.0.0.1",
            ComputerName = "HOST03",
            Interpretation = "Suspicious pattern",
            Details = "More info",
            RelatedEventRowIds = [1, 2, 3]
        };

        var row = ExportRowBuilder.BuildCorrelationRows([correlation]).Single();

        Assert.Equal(5, row.CorrelationId);
        Assert.Equal("High", row.Severity);
        Assert.Equal("LateralMovement", row.Scenario);
        Assert.Equal("Multiple hosts", row.Title);
        Assert.Equal("2026-06-01 14:00:00", row.TimeUtc);
        Assert.Equal("2026-06-01 16:00:00", row.CreatedUtc);
        Assert.Equal("admin", row.User);
        Assert.Equal("10.0.0.1", row.SourceIpAddress);
        Assert.Equal("HOST03", row.ComputerName);
        Assert.Equal("Suspicious pattern", row.Interpretation);
        Assert.Equal("More info", row.Details);
        Assert.Equal("1, 2, 3", row.RelatedEventRowIds);
    }

    [Fact]
    public void BuildEventRows_MapsAllFieldsAndPropertiesJson()
    {
        var evt = new WindowsEvent
        {
            Id = 42,
            TimeCreatedUtc = SampleTime,
            ComputerName = "HOST01",
            LogName = "Security",
            ProviderName = "Provider",
            EventId = 4688,
            EventRecordId = 100,
            Level = "Information",
            User = "alice",
            Domain = "CORP",
            TargetUserName = "bob",
            TargetDomainName = "CORP",
            ProcessName = "cmd.exe",
            ProcessPath = @"C:\Windows\System32\cmd.exe",
            ProcessId = 100,
            ParentProcessName = "explorer.exe",
            ParentProcessId = 50,
            ParentCommandLine = "explorer.exe",
            CommandLine = "cmd.exe /c whoami",
            SourceIpAddress = "1.2.3.4",
            DestinationIpAddress = "5.6.7.8",
            SourcePort = 1234,
            DestinationPort = 5678,
            WorkstationName = "WS01",
            LogonType = 3,
            ScriptBlock = "Get-Process",
            ScriptBlockHash = "abc123",
            Hashes = "SHA256=deadbeef",
            ProcessGuid = "{guid1}",
            ParentProcessGuid = "{guid2}",
            QueryName = "evil.com",
            TaskName = "Task",
            ServiceName = "Service",
            Properties = { ["Key"] = "Value" },
            RawXml = "<Event/>"
        };

        var row = ExportRowBuilder.BuildEventRows([evt]).Single();

        Assert.Equal(42, row.EventRowId);
        Assert.Equal("2026-06-01 14:00:00", row.TimeCreatedUtc);
        Assert.Equal("HOST01", row.ComputerName);
        Assert.Equal("Security", row.LogName);
        Assert.Equal("Provider", row.ProviderName);
        Assert.Equal(4688, row.EventId);
        Assert.Equal(100L, row.EventRecordId);
        Assert.Equal("Information", row.Level);
        Assert.Equal("alice", row.User);
        Assert.Equal("CORP", row.Domain);
        Assert.Equal("bob", row.TargetUserName);
        Assert.Equal("CORP", row.TargetDomainName);
        Assert.Equal("cmd.exe", row.ProcessName);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", row.ProcessPath);
        Assert.Equal(100, row.ProcessId);
        Assert.Equal("explorer.exe", row.ParentProcessName);
        Assert.Equal(50, row.ParentProcessId);
        Assert.Equal("explorer.exe", row.ParentCommandLine);
        Assert.Equal("cmd.exe /c whoami", row.CommandLine);
        Assert.Equal("1.2.3.4", row.SourceIpAddress);
        Assert.Equal("5.6.7.8", row.DestinationIpAddress);
        Assert.Equal(1234, row.SourcePort);
        Assert.Equal(5678, row.DestinationPort);
        Assert.Equal("WS01", row.WorkstationName);
        Assert.Equal(3, row.LogonType);
        Assert.Equal("Get-Process", row.ScriptBlock);
        Assert.Equal("abc123", row.ScriptBlockHash);
        Assert.Equal("SHA256=deadbeef", row.Hashes);
        Assert.Equal("{guid1}", row.ProcessGuid);
        Assert.Equal("{guid2}", row.ParentProcessGuid);
        Assert.Equal("evil.com", row.QueryName);
        Assert.Equal("Task", row.TaskName);
        Assert.Equal("Service", row.ServiceName);
        Assert.Contains("Value", row.PropertiesJson, StringComparison.Ordinal);
        Assert.Equal("<Event/>", row.RawXml);
    }
}
