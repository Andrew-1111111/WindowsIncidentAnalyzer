using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class WindowsEvtxLogCatalogTests
{
    [Theory]
    [InlineData("Security", "Security.evtx")]
    [InlineData("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon%4Operational.evtx")]
    [InlineData("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell%4Operational.evtx")]
    public void ChannelNameToEvtxFileName_EncodesForwardSlash(string channelName, string expectedFileName) =>
        Assert.Equal(expectedFileName, WindowsEvtxLogCatalog.ChannelNameToEvtxFileName(channelName));

    [Theory]
    [InlineData("Security.evtx", "Security")]
    [InlineData("Microsoft-Windows-Sysmon%4Operational.evtx", "Microsoft-Windows-Sysmon/Operational")]
    public void EvtxFileNameToChannelName_DecodesForwardSlash(string fileName, string expectedChannel) =>
        Assert.Equal(expectedChannel, WindowsEvtxLogCatalog.EvtxFileNameToChannelName(fileName));

    [Fact]
    public void IsReadableEvtxFile_RejectsMissingAndTinyFiles()
    {
        Assert.False(WindowsEvtxLogCatalog.IsReadableEvtxFile(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".evtx")));

        var tiny = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".evtx");
        File.WriteAllBytes(tiny, [1, 2, 3]);
        try
        {
            Assert.False(WindowsEvtxLogCatalog.IsReadableEvtxFile(tiny));
        }
        finally
        {
            File.Delete(tiny);
        }
    }

    [Fact]
    public void DiscoverEvtxFilePaths_OnWindows_ReturnsAtLeastClassicLogs()
    {
        var files = WindowsEvtxLogCatalog.DiscoverEvtxFilePaths();

        Assert.NotEmpty(files);
        Assert.Contains(
            files,
            path => string.Equals(
                Path.GetFileName(path),
                WindowsEvtxLogCatalog.ChannelNameToEvtxFileName(WindowsLogNames.Security),
                StringComparison.OrdinalIgnoreCase));
    }
}
