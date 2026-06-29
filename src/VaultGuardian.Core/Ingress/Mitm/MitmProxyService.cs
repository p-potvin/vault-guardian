using System.Globalization;
using VaultGuardian.Core.Diagnostics;

namespace VaultGuardian.Core.Ingress.Mitm;

public sealed class MitmProxyService
{
    private readonly IManagedProcessLauncher _processLauncher;
    private readonly MitmProxyOptions _options;
    private IManagedProcess? _mitmProcess;
    private IManagedProcess? _browserProcess;
    private MitmProxyStatus _status;

    public MitmProxyService(IManagedProcessLauncher processLauncher, MitmProxyOptions options)
    {
        _processLauncher = processLauncher;
        _options = options;
        _status = new MitmProxyStatus(MitmProxyState.Stopped, options.ListenPort, options.BrowserProfilePath, null, 0);
    }

    public MitmProxyStatus GetStatus() => _status;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            _status = _status with { State = MitmProxyState.Starting, LastError = null };
            Directory.CreateDirectory(_options.BrowserProfilePath);

            _mitmProcess = _processLauncher.Start(
                _options.MitmDumpPath,
                ["--listen-port", _options.ListenPort.ToString(CultureInfo.InvariantCulture), "--set", "block_global=false"]);

            _browserProcess = _processLauncher.Start(
                _options.BrowserExecutablePath,
                [$"--user-data-dir={_options.BrowserProfilePath}", $"--proxy-server=http://127.0.0.1:{_options.ListenPort}", "--no-first-run"]);

            _status = _status with { State = MitmProxyState.Running };
            await Task.CompletedTask.ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _status = _status with { State = MitmProxyState.Faulted, LastError = ex.Message };
            throw;
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _browserProcess?.Stop();
        _browserProcess?.Dispose();
        _browserProcess = null;
        _mitmProcess?.Stop();
        _mitmProcess?.Dispose();
        _mitmProcess = null;
        _status = _status with { State = MitmProxyState.Stopped };
        return Task.CompletedTask;
    }
}
