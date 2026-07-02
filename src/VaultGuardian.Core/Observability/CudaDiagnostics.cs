using System.Diagnostics;

namespace VaultGuardian.Core.Observability;

/// <summary>
/// Diagnostic logging utility for CUDA/CUPTI initialization issues.
/// Logs to debug output, event log, and can be integrated with structured logging.
/// </summary>
internal static class CudaDiagnostics
{
    private const string EventLogSource = "VaultGuardian";

    /// <summary>
    /// Logs a message about CUDA library availability and paths.
    /// </summary>
    public static void LogCudaLibraryStatus()
    {
        var missing = CudaLibraryLoader.CheckAvailableLibraries().ToList();

        if (missing.Any())
        {
            var missingList = string.Join(", ", missing);
            LogWarning($"CUDA libraries missing: {missingList}. GPU profiling will be unavailable.");
        }
        else
        {
            LogInfo("All required CUDA libraries found. GPU profiling initialized.");
        }
    }

    /// <summary>
    /// Logs an info message to debug output and event log.
    /// </summary>
    public static void LogInfo(string message)
    {
        Debug.WriteLine($"[CUDA] {message}", "VaultGuardian.CUDA");
        TryLogToEventLog(message, EventLogEntryType.Information);
    }

    /// <summary>
    /// Logs a warning message to debug output and event log.
    /// </summary>
    public static void LogWarning(string message)
    {
        Debug.WriteLine($"[CUDA WARNING] {message}", "VaultGuardian.CUDA");
        TryLogToEventLog(message, EventLogEntryType.Warning);
    }

    /// <summary>
    /// Logs an error message to debug output and event log.
    /// </summary>
    public static void LogError(string message, Exception? ex = null)
    {
        var fullMessage = ex != null ? $"{message}\n{ex}" : message;
        Debug.WriteLine($"[CUDA ERROR] {fullMessage}", "VaultGuardian.CUDA");
        TryLogToEventLog(fullMessage, EventLogEntryType.Error);
    }

    private static void TryLogToEventLog(string message, EventLogEntryType type)
    {
        try
        {
            if (!EventLog.SourceExists(EventLogSource))
                EventLog.CreateEventSource(EventLogSource, "Application");

            using var eventLog = new EventLog("Application") { Source = EventLogSource };
            eventLog.WriteEntry(message, type, 1000);
        }
        catch
        {
            // Silently fail if event log is not available (e.g., in non-admin context)
        }
    }
}
