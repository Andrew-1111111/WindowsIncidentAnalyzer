using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class HayabusaEventMetadataTests
{
    [Fact]
    public void LoadFromConfigDirectory_ParsesChannelTitlesAndAliases()
    {
        var dir = Path.Combine(Path.GetTempPath(), "wia-hayabusa-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(
                Path.Combine(dir, "channel_eid_info.txt"),
                """
                Channel,EventID,EventTitle
                Security,4624,Successful Logon
                Microsoft-Windows-Sysmon/Operational,1,Process Creation
                """);

            File.WriteAllText(
                Path.Combine(dir, "eventkey_alias.txt"),
                """
                CommandLine,Event.EventData.CommandLine
                SubjectUserName,Event.EventData.SubjectUserName
                """);

            HayabusaEventMetadata.LoadFromConfigDirectory(dir);

            Assert.True(HayabusaEventMetadata.TryGetEventTitle("Security", 4624, out var title));
            Assert.Equal("Successful Logon", title);
            Assert.Equal("CommandLine", HayabusaEventMetadata.ResolveLeafFieldName("CommandLine"));
            Assert.Contains(
                "SubjectUserName",
                HayabusaEventMetadata.GetLookupNames("Event.EventData.SubjectUserName"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("hayabusa-rules-main/sigma/builtin/foo.yml", "sigma/builtin/foo.yml")]
    [InlineData("hayabusa-rules-main/hayabusa/builtin/bar.yml", "hayabusa/builtin/bar.yml")]
    [InlineData("hayabusa-rules-main/config/channel_eid_info.txt", "config/channel_eid_info.txt")]
    public void GetRelativePath_ExtractsHayabusaArchivePaths(string entry, string expected) =>
        Assert.Equal(expected, HayabusaRulesArchive.GetRelativePath(entry));
}
