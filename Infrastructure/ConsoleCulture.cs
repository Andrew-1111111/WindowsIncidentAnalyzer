using System.Globalization;

namespace WindowsIncidentAnalyzer.Infrastructure;

internal static class ConsoleCulture
{
    public static void UseEnglish()
    {
        var english = CultureInfo.GetCultureInfo("en-US");
        CultureInfo.DefaultThreadCurrentUICulture = english;
        CultureInfo.CurrentUICulture = english;
    }
}
