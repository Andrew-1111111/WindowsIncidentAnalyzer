using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Services;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class EventRecordNormalizerTests
{
    [Theory]
    [InlineData(WindowsLogNames.Security, "Microsoft-Windows-Security-Auditing", true)]
    [InlineData(WindowsLogNames.Sysmon, "Microsoft-Windows-Sysmon", true)]
    [InlineData(WindowsLogNames.PowerShell, "Microsoft-Windows-PowerShell", true)]
    [InlineData("Application", "Application Error", false)]
    [InlineData("Microsoft-Windows-Kernel-General/Operational", "Microsoft-Windows-Kernel-General", false)]
    public void ShouldTryNativeXml_OnlyForForensicChannels(
        string logName,
        string providerName,
        bool expected) =>
        Assert.Equal(expected, EventRecordNormalizer.ShouldTryNativeXml(logName, providerName));
}
