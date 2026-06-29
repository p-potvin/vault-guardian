using System.Globalization;
using VaultGuardian.Core.Diagnostics;

namespace VaultGuardian.Core.Ingress.Mitm;

public sealed class MitmProxyService
{
    private const string AddonScript = """
        from mitmproxy import ctx
        import json
        from datetime import datetime, timezone

        def load(loader):
            loader.add_option("vaultguardian_flow_path", str, "", "VaultGuardian JSONL flow export path")

        def response(flow):
            _write_flow(flow)

        def error(flow):
            _write_flow(flow)

        def _headers(headers):
            return {str(key): str(value) for key, value in headers.items()}

        def _text(message):
            if message is None:
                return ""
            try:
                return message.get_text(strict=False)
            except Exception:
                return ""

        def _timestamp(value):
            try:
                return datetime.fromtimestamp(value, timezone.utc).isoformat()
            except Exception:
                return datetime.now(timezone.utc).isoformat()

        def _write_flow(flow):
            path = ctx.options.vaultguardian_flow_path
            if not path:
                return
            item = {
                "id": flow.id,
                "request": {
                    "method": flow.request.method,
                    "url": flow.request.pretty_url,
                    "headers": _headers(flow.request.headers),
                    "text": _text(flow.request),
                },
                "response": None if flow.response is None else {
                    "status_code": flow.response.status_code,
                    "headers": _headers(flow.response.headers),
                    "text": _text(flow.response),
                },
                "timestamp_start": _timestamp(flow.request.timestamp_start),
            }
            with open(path, "a", encoding="utf-8") as output:
                output.write(json.dumps(item, ensure_ascii=False) + "\n")
        """;

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
    public string FlowExportPath => _options.FlowExportPath;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            _status = _status with { State = MitmProxyState.Starting, LastError = null };
            Directory.CreateDirectory(_options.BrowserProfilePath);
            var scriptDirectory = Path.GetDirectoryName(_options.AddonScriptPath);
            if (!string.IsNullOrWhiteSpace(scriptDirectory))
            {
                Directory.CreateDirectory(scriptDirectory);
            }

            var flowDirectory = Path.GetDirectoryName(_options.FlowExportPath);
            if (!string.IsNullOrWhiteSpace(flowDirectory))
            {
                Directory.CreateDirectory(flowDirectory);
            }

            await File.WriteAllTextAsync(_options.AddonScriptPath, AddonScript, cancellationToken).ConfigureAwait(false);

            _mitmProcess = _processLauncher.Start(
                _options.MitmDumpPath,
                [
                    "--listen-port",
                    _options.ListenPort.ToString(CultureInfo.InvariantCulture),
                    "--set",
                    "block_global=false",
                    "-s",
                    _options.AddonScriptPath,
                    "--set",
                    $"vaultguardian_flow_path={_options.FlowExportPath}"
                ]);

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

    public void RecordImportedFlows(int count)
    {
        if (count <= 0)
        {
            return;
        }

        _status = _status with { ImportedFlows = _status.ImportedFlows + count, LastError = null };
    }

    public void RecordImportError(string message)
    {
        _status = _status with { LastError = message };
    }
}
