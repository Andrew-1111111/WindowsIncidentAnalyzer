using System.Runtime.InteropServices;

namespace WindowsIncidentAnalyzer.Infrastructure;

internal static class ConsoleIcon
{
    private const int WmSetIcon = 0x0080;
    private const int IconSmall = 0;
    private const int IconBig = 1;
    private const uint ImageIcon = 1;
    private const uint LrLoadFromFile = 0x0010;

    public static void Apply()
    {
        try
        {
            var hwnd = GetConsoleWindow();
            if (hwnd == IntPtr.Zero)
            {
                return;
            }

            if (!TryExtractFromExecutable(hwnd) && !TryLoadFromFile(hwnd))
            {
                return;
            }
        }
        catch
        {
            // Cosmetic only — never fail application startup.
        }
    }

    private static bool TryExtractFromExecutable(IntPtr hwnd)
    {
        var exe = ResolveExecutablePath();
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
        {
            return false;
        }

        if (ExtractIconEx(exe, 0, out var large, out var small, 1) < 1)
        {
            return false;
        }

        ApplyHandles(hwnd, small, large);
        return small != IntPtr.Zero || large != IntPtr.Zero;
    }

    private static bool TryLoadFromFile(IntPtr hwnd)
    {
        foreach (var path in CandidateIconFiles())
        {
            if (!File.Exists(path))
            {
                continue;
            }

            var small = LoadImage(IntPtr.Zero, path, ImageIcon, 16, 16, LrLoadFromFile);
            var large = LoadImage(IntPtr.Zero, path, ImageIcon, 32, 32, LrLoadFromFile);
            if (small == IntPtr.Zero && large == IntPtr.Zero)
            {
                continue;
            }

            ApplyHandles(hwnd, small, large);
            return true;
        }

        return false;
    }

    private static void ApplyHandles(IntPtr hwnd, IntPtr small, IntPtr large)
    {
        if (small != IntPtr.Zero)
        {
            SendMessage(hwnd, WmSetIcon, IconSmall, small);
        }

        if (large != IntPtr.Zero)
        {
            SendMessage(hwnd, WmSetIcon, IconBig, large);
        }
    }

    private static string? ResolveExecutablePath()
    {
        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(processPath) &&
            !string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            return processPath;
        }

        var apphost = Path.Combine(AppContext.BaseDirectory, "wia.exe");
        return File.Exists(apphost) ? apphost : processPath;
    }

    private static IEnumerable<string> CandidateIconFiles()
    {
        yield return Path.Combine(AppContext.BaseDirectory, "Resources", "wia.ico");
        yield return Path.Combine(AppContext.BaseDirectory, "wia.ico");
        yield return Path.Combine(Directory.GetCurrentDirectory(), "Resources", "wia.ico");
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern uint ExtractIconEx(string lpszFile, int nIconIndex, out IntPtr phiconLarge, out IntPtr phiconSmall, uint nIcons);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadImage(IntPtr hInst, string name, uint type, int cx, int cy, uint fuLoad);
}
