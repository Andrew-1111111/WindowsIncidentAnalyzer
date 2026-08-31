namespace WindowsIncidentAnalyzer.Tests.Fixtures;

public static class EventXmlFixtures
{
    public const string SecurityNs = "http://schemas.microsoft.com/win/2004/08/events/event";

    public static string SecurityEvent(
        int eventId,
        string timeUtc,
        string computer,
        params (string Name, string Value)[] data)
    {
        var dataXml = string.Join(
            Environment.NewLine,
            data.Select(d => $"      <Data Name=\"{d.Name}\">{System.Net.WebUtility.HtmlEncode(d.Value)}</Data>"));

        return $"""
            <Event xmlns="{SecurityNs}">
              <System>
                <Provider Name="Microsoft-Windows-Security-Auditing" />
                <EventID>{eventId}</EventID>
                <Level>0</Level>
                <TimeCreated SystemTime="{timeUtc}" />
                <Channel>Security</Channel>
                <Computer>{computer}</Computer>
                <Security />
              </System>
              <EventData>
            {dataXml}
              </EventData>
            </Event>
            """;
    }

    public static string SysmonEvent(
        int eventId,
        string timeUtc,
        string computer,
        params (string Name, string Value)[] data)
    {
        var dataXml = string.Join(
            Environment.NewLine,
            data.Select(d => $"      <Data Name=\"{d.Name}\">{System.Net.WebUtility.HtmlEncode(d.Value)}</Data>"));

        return $"""
            <Event xmlns="{SecurityNs}">
              <System>
                <Provider Name="Microsoft-Windows-Sysmon" />
                <EventID>{eventId}</EventID>
                <Level>4</Level>
                <TimeCreated SystemTime="{timeUtc}" />
                <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
                <Computer>{computer}</Computer>
              </System>
              <EventData>
            {dataXml}
              </EventData>
            </Event>
            """;
    }

    public static string PowerShell4104(string timeUtc, string computer, string script, string userSid = "S-1-5-21-1000-1000-1000-1105")
    {
        var encoded = System.Net.WebUtility.HtmlEncode(script);
        return $"""
            <Event xmlns="{SecurityNs}">
              <System>
                <Provider Name="Microsoft-Windows-PowerShell" />
                <EventID>4104</EventID>
                <Level>5</Level>
                <TimeCreated SystemTime="{timeUtc}" />
                <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
                <Computer>{computer}</Computer>
                <Security UserID="{userSid}" />
              </System>
              <EventData>
                <Data Name="MessageNumber">1</Data>
                <Data Name="MessageTotal">1</Data>
                <Data Name="ScriptBlockText">{encoded}</Data>
                <Data Name="ScriptBlockId">11111111-2222-3333-4444-555555555555</Data>
                <Data Name="Path"></Data>
              </EventData>
            </Event>
            """;
    }

    public static string FailedLogon(string timeUtc, string user, string ip, string computer = "LAB-HOST-01") =>
        SecurityEvent(4625, timeUtc, computer,
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "SYSTEM"),
            ("SubjectDomainName", "NT AUTHORITY"),
            ("TargetUserSid", "S-1-0-0"),
            ("TargetUserName", user),
            ("TargetDomainName", "LAB"),
            ("Status", "0xc000006d"),
            ("FailureReason", "%%2313"),
            ("SubStatus", "0xc000006a"),
            ("LogonType", "3"),
            ("IpAddress", ip),
            ("WorkstationName", "WS-01"),
            ("ProcessName", "-"));

    public static string SuccessfulLogon(
        string timeUtc,
        string user,
        string ip,
        int logonType = 3,
        string computer = "LAB-HOST-01",
        string targetSid = "S-1-5-21-1000-1000-1000-1105") =>
        SecurityEvent(4624, timeUtc, computer,
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", "SYSTEM"),
            ("SubjectDomainName", "NT AUTHORITY"),
            ("TargetUserSid", targetSid),
            ("TargetUserName", user),
            ("TargetDomainName", "LAB"),
            ("LogonType", logonType.ToString()),
            ("IpAddress", ip),
            ("WorkstationName", "WS-01"),
            ("ProcessName", "C:\\Windows\\System32\\svchost.exe"),
            ("ProcessId", "0x2e0"));

    public static string SpecialPrivileges(string timeUtc, string user, string computer = "LAB-HOST-01") =>
        SecurityEvent(4672, timeUtc, computer,
            ("SubjectUserSid", "S-1-5-21-1000-1000-1000-1105"),
            ("SubjectUserName", user),
            ("SubjectDomainName", "LAB"),
            ("PrivilegeList", "SeDebugPrivilege"));
}
