using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace WindowsIncidentAnalyzer.Infrastructure;

internal static class AppRuntime
{
    public static bool LimitedMode { get; set; }
}

internal static class ProcessElevation
{
    public const string LimitedFlag = "--limited";

    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity is not null && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Returns remaining CLI args after consuming startup flags.
    /// Exits the current process when a relaunch is started.
    /// </summary>
    public static string[] EnsurePrivileges(string[] args)
    {
        var (limited, rest) = StripFlag(args, LimitedFlag);
        AppRuntime.LimitedMode = limited || !IsAdministrator();

        if (IsAdministrator() || limited)
        {
            return rest;
        }

        if (System.Diagnostics.Debugger.IsAttached)
        {
            AppRuntime.LimitedMode = true;
            return rest;
        }

        if (!ConsoleLaunch.IsInteractive || IsHelpOrVersion(rest))
        {
            AppRuntime.LimitedMode = true;
            return rest;
        }

        if (TryRelaunchElevated(rest) || TryRelaunchLimited(rest))
        {
            Environment.Exit(0);
        }

        AppRuntime.LimitedMode = true;
        return rest;
    }

    private static bool TryRelaunchLimited(string[] args)
    {
        try
        {
            Process.Start(CreateStartInfo([LimitedFlag, .. args], elevate: false));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryRelaunchElevated(string[] args)
    {
        try
        {
            using var _ = Process.Start(CreateStartInfo(args, elevate: true));
            return true;
        }
        catch (Win32Exception)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static ProcessStartInfo CreateStartInfo(string[] args, bool elevate)
    {
        var exe = ResolveExecutable();
        var info = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = QuoteArguments(args),
            WorkingDirectory = AppPaths.ExecutableDirectory,
            UseShellExecute = true
        };

        if (elevate)
        {
            info.Verb = "runas";
        }

        return info;
    }

    private static string ResolveExecutable()
    {
        var apphost = Path.Combine(AppPaths.ExecutableDirectory, "wia.exe");
        if (File.Exists(apphost))
        {
            return apphost;
        }

        return Environment.ProcessPath
               ?? Process.GetCurrentProcess().MainModule?.FileName
               ?? apphost;
    }

    private static (bool Present, string[] Remaining) StripFlag(string[] args, string flag)
    {
        var present = args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
        var remaining = args.Where(a => !string.Equals(a, flag, StringComparison.OrdinalIgnoreCase)).ToArray();
        return (present, remaining);
    }

    private static bool IsHelpOrVersion(string[] args) =>
        args.Any(a => a is "-h" or "-?" or "--help" or "--version" or "/?");

    private static string QuoteArguments(IEnumerable<string> args) =>
        string.Join(" ", args.Select(static a =>
            a.Length == 0 || a.Any(char.IsWhiteSpace) || a.Contains('"')
                ? "\"" + a.Replace("\"", "\\\"") + "\""
                : a));
}
