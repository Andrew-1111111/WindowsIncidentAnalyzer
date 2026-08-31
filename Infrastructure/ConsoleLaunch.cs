using System.Runtime.InteropServices;

namespace WindowsIncidentAnalyzer.Infrastructure;

internal static class ConsoleLaunch
{
    public static bool OwnsConsoleWindow()
    {
        try
        {
            var buffer = new uint[8];
            var count = GetConsoleProcessList(buffer, (uint)buffer.Length);
            return count <= 1;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsInteractive =>
        !Console.IsInputRedirected && !Console.IsOutputRedirected;

    public static void PauseIfNeeded(string? message = null)
    {
        if (!OwnsConsoleWindow() || !IsInteractive)
        {
            return;
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(message))
            {
                Console.WriteLine(message);
            }

            Console.WriteLine();
            Console.Write("Press any key to exit...");
            Console.ReadKey(true);
        }
        catch
        {
            // Ignore if stdin is gone.
        }
    }

    [DllImport("kernel32.dll")]
    private static extern uint GetConsoleProcessList(uint[] processList, uint count);
}
