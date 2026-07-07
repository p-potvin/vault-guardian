using Microsoft.Extensions.Logging;

namespace VaultGuardian.UI.Logging;

/// <summary>
/// Minimal dependency-free logger that appends to a daily rolling file so the
/// app's lifecycle and heartbeat survive a multi-day stability run (console
/// output from a WinUI app is not persisted). Captures every ILogger source in
/// the app plus the diagnostics added for the stability test.
/// </summary>
public sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly string _directory;
    private readonly LogLevel _minLevel;
    private readonly object _gate = new();
    private StreamWriter? _writer;
    private DateOnly _writerDate;

    public FileLoggerProvider(string directory, LogLevel minLevel = LogLevel.Information)
    {
        _directory = directory;
        _minLevel = minLevel;
        Directory.CreateDirectory(_directory);
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(this, categoryName);

    internal bool IsEnabled(LogLevel level) => level != LogLevel.None && level >= _minLevel;

    internal void Write(LogLevel level, string category, string message, Exception? exception)
    {
        var shortCategory = category.Contains('.') ? category[(category.LastIndexOf('.') + 1)..] : category;
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff} [{Abbreviate(level)}] {shortCategory}: {message}";

        lock (_gate)
        {
            try
            {
                EnsureWriter();
                _writer!.WriteLine(line);
                if (exception != null)
                {
                    _writer.WriteLine(exception);
                }
            }
            catch
            {
                // Never let logging take down the app during a stability run.
            }
        }
    }

    private void EnsureWriter()
    {
        var today = DateOnly.FromDateTime(DateTime.Now);
        if (_writer != null && today == _writerDate)
        {
            return;
        }

        _writer?.Dispose();
        var path = Path.Combine(_directory, $"vaultguardian-{today:yyyyMMdd}.log");
        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        _writer = new StreamWriter(stream) { AutoFlush = true };
        _writerDate = today;
    }

    private static string Abbreviate(LogLevel level) => level switch
    {
        LogLevel.Trace => "TRC",
        LogLevel.Debug => "DBG",
        LogLevel.Information => "INF",
        LogLevel.Warning => "WRN",
        LogLevel.Error => "ERR",
        LogLevel.Critical => "CRT",
        _ => "???"
    };

    public void Dispose()
    {
        lock (_gate)
        {
            _writer?.Dispose();
            _writer = null;
        }
    }

    private sealed class FileLogger(FileLoggerProvider provider, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => provider.IsEnabled(logLevel);

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            provider.Write(logLevel, category, formatter(state, exception), exception);
        }
    }
}
