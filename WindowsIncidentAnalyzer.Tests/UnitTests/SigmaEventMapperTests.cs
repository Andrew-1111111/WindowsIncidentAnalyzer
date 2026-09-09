using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaEventMapperTests
{
    [Fact]
    public void Map_PopulatesStandardSigmaFields()
    {
        var evt = new WindowsEvent
        {
            EventId = 4688,
            LogName = "Security",
            ProviderName = "Microsoft-Windows-Security-Auditing",
            ComputerName = "HOST01",
            User = "alice",
            ProcessPath = @"C:\Windows\System32\cmd.exe",
            ProcessName = "cmd.exe",
            CommandLine = "cmd.exe /c whoami",
            ParentProcessName = "explorer.exe",
            ProcessId = 1234,
            ParentProcessId = 5678,
            SourceIpAddress = "10.0.0.1",
            DestinationIpAddress = "10.0.0.2",
            DestinationPort = 443,
            SourcePort = 51234,
            RawXml = "<Event><System><EventID>4688</EventID></System></Event>"
        };
        evt.Properties["SubjectUserName"] = "alice";

        var fields = SigmaEventMapper.Map(evt);

        Assert.Equal("4688", fields["EventID"]);
        Assert.Equal("4688", fields["Event.System.EventID"]);
        Assert.Equal("Security", fields["Channel"]);
        Assert.Equal("Microsoft-Windows-Security-Auditing", fields["Provider"]);
        Assert.Equal("HOST01", fields["Computer"]);
        Assert.Equal("alice", fields["SubjectUserName"]);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", fields["Image"]);
        Assert.Equal("cmd.exe", fields["ProcessName"]);
        Assert.Equal("cmd.exe /c whoami", fields["CommandLine"]);
        Assert.Equal("explorer.exe", fields["ParentImage"]);
        Assert.Equal("1234", fields["ProcessId"]);
        Assert.Equal("5678", fields["ParentProcessId"]);
        Assert.Equal("10.0.0.1", fields["SourceIp"]);
        Assert.Equal("10.0.0.2", fields["DestinationIp"]);
        Assert.Equal("443", fields["DestinationPort"]);
        Assert.Equal("51234", fields["SourcePort"]);
    }

    [Fact]
    public void Map_ImageFallsBackToProcessNameWhenPathMissing()
    {
        var evt = new WindowsEvent
        {
            EventId = 1,
            ProcessName = "notepad.exe"
        };

        var fields = SigmaEventMapper.Map(evt);

        Assert.Equal("notepad.exe", fields["Image"]);
    }

    [Fact]
    public void Map_SkipsBlankValues()
    {
        var evt = new WindowsEvent
        {
            EventId = 1,
            ProcessName = "cmd.exe",
            CommandLine = "   "
        };

        var fields = SigmaEventMapper.Map(evt);

        Assert.True(fields.ContainsKey("ProcessName"));
        Assert.False(fields.ContainsKey("CommandLine"));
    }

    [Fact]
    public void Map_MergesCustomProperties()
    {
        var evt = new WindowsEvent
        {
            EventId = 4104,
            Properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ScriptBlockText"] = "Invoke-Mimikatz"
            }
        };

        var fields = SigmaEventMapper.Map(evt);

        Assert.Equal("Invoke-Mimikatz", fields["ScriptBlockText"]);
    }

    [Fact]
    public void Map_BuildsSearchBlobFromRawXmlAndFieldValues()
    {
        var evt = new WindowsEvent
        {
            EventId = 1,
            ProcessName = "cmd.exe",
            RawXml = "<Event><EventData><Data Name='Image'>cmd.exe</Data></EventData></Event>"
        };

        var fields = SigmaEventMapper.Map(evt);

        Assert.True(fields.ContainsKey("_sigma_blob"));
        Assert.Contains("<Event>", fields["_sigma_blob"]);
        Assert.Contains("cmd.exe", fields["_sigma_blob"]);
    }

    [Fact]
    public void ResolveField_ReturnsDirectMatch()
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CommandLine"] = "whoami /all"
        };

        Assert.Equal("whoami /all", SigmaEventMapper.ResolveField(fields, "CommandLine"));
    }

    [Fact]
    public void ResolveField_UsesDottedLeafName()
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["EventID"] = "4688"
        };

        Assert.Equal("4688", SigmaEventMapper.ResolveField(fields, "Event.System.EventID"));
    }

    [Fact]
    public void ResolveField_UsesHayabusaAliasesWhenLoaded()
    {
        var dir = Path.Combine(Path.GetTempPath(), "wia-mapper-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(
                Path.Combine(dir, "eventkey_alias.txt"),
                """
                CommandLine,Event.EventData.CommandLine
                """);

            HayabusaEventMetadata.LoadFromConfigDirectory(dir);

            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["CommandLine"] = "powershell -enc payload"
            };

            Assert.Equal(
                "powershell -enc payload",
                SigmaEventMapper.ResolveField(fields, "Event.EventData.CommandLine"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void ResolveField_ReturnsNullWhenMissing()
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = "cmd.exe"
        };

        Assert.Null(SigmaEventMapper.ResolveField(fields, "MissingField"));
    }
}
