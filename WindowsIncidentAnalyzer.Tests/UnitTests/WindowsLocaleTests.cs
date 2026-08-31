using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class WindowsLocaleTests
{
    [Theory]
    [InlineData("Security", WindowsLogNames.Security)]
    [InlineData("SECURITY", WindowsLogNames.Security)]
    [InlineData("Безопасность", WindowsLogNames.Security)]
    [InlineData("Система", WindowsLogNames.System)]
    [InlineData("Приложение", WindowsLogNames.Application)]
    [InlineData("powershell", WindowsLogNames.PowerShell)]
    public void LogAlias_ResolvesEnglishAndRussianNames(string alias, string expected) =>
        Assert.Equal(expected, WindowsLogNames.Resolve(alias));

    [Theory]
    [InlineData("Access is denied.", true)]
    [InlineData("Отказано в доступе.", true)]
    [InlineData("Недостаточно прав для выполнения операции.", true)]
    [InlineData("The channel was not found.", false)]
    public void AccessDenied_RecognizesEnglishAndRussianMessages(string message, bool expected) =>
        Assert.Equal(expected, WindowsLocale.LooksLikeAccessDenied(message));

    [Theory]
    [InlineData("Administrators", "S-1-5-32-544", true)]
    [InlineData("Администраторы", null, true)]
    [InlineData("Администраторы домена", "S-1-5-21-1-2-3-512", true)]
    [InlineData("Пользователи удаленного рабочего стола", null, true)]
    [InlineData("Users", "S-1-5-32-545", false)]
    [InlineData("Пользователи", null, false)]
    public void PrivilegedGroup_MatchesEnglishRussianAndSids(string name, string? sid, bool expected) =>
        Assert.Equal(expected, WindowsLocale.IsPrivilegedGroup(name, sid));

    [Fact]
    public void SuspiciousPath_MatchesRussianDownloadsFolder() =>
        Assert.True(WindowsLocale.MatchesSuspiciousPath(@"C:\Users\lab\Загрузки\payload.exe", []));

    [Fact]
    public void WellKnownAccountSids_IncludesNtAuthorityAndBuiltinAliases()
    {
        Assert.Contains("S-1-5-18", WindowsLocale.WellKnownAccountSids);
        Assert.Contains("S-1-5-19", WindowsLocale.WellKnownAccountSids);
        Assert.Contains("S-1-5-20", WindowsLocale.WellKnownAccountSids);
        Assert.Contains("S-1-5-7", WindowsLocale.WellKnownAccountSids);
        Assert.Contains("S-1-5-17", WindowsLocale.WellKnownAccountSids);
        Assert.Contains("S-1-5-32-544", WindowsLocale.WellKnownAccountSids);
        Assert.Contains("S-1-5-32-555", WindowsLocale.WellKnownAccountSids);
        Assert.Contains("S-1-5-32-573", WindowsLocale.WellKnownAccountSids);
        Assert.True(WindowsLocale.WellKnownAccountSids.Count >= 80);
    }

    [Theory]
    [InlineData("S-1-5-18", true)]
    [InlineData("S-1-5-32-544", true)]
    [InlineData("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", true)]
    [InlineData("S-1-5-82-1234567890", true)]
    [InlineData("S-1-5-5-0-12345", true)]
    [InlineData("S-1-5-21-1000-1000-1000-1105", false)]
    public void IsWellKnownAccountSid_MatchesCatalogAndPrefixes(string sid, bool expected) =>
        Assert.Equal(expected, WindowsLocale.IsWellKnownAccountSid(sid));

    [Theory]
    [InlineData("S-1-5-18", true)]
    [InlineData("S-1-5-80-1-2-3-4-5", true)]
    [InlineData("S-1-5-32-544", false)]
    [InlineData("S-1-5-11", false)]
    [InlineData("S-1-5-21-1000-1000-1000-1105", false)]
    public void IsBuiltInServiceSid_OnlyServicePrincipals(string sid, bool expected) =>
        Assert.Equal(expected, WindowsLocale.IsBuiltInServiceSid(sid));
}

public sealed class PrivilegeChangeDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly PrivilegeChangeDetector _detector = new(Options.Create(new DetectionRulesOptions()));

    [Fact]
    public void Analyze_RussianAdministratorsGroup_IsPrivileged()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4732,
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "helpdesk"),
            ("TargetUserName", "Администраторы"),
            ("TargetSid", "S-1-5-32-544"),
            ("MemberName", @"LAB\tempadmin"),
            ("MemberSid", "S-1-5-21-1000-1000-1000-1110")));

        var findings = _detector.Analyze([evt]).ToList();
        Assert.Contains(findings, f => f.Title.Contains("privileged group", StringComparison.OrdinalIgnoreCase));
    }
}
