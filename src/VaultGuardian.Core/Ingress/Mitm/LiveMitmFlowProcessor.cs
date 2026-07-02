using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Ingress.Mitm;

public sealed class LiveMitmFlowProcessor : IAsyncDisposable
{
    private static readonly TimeSpan DefaultPollInterval = TimeSpan.FromMilliseconds(1000);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly MitmProxyService _mitmProxyService;
    private readonly MitmFlowImporter _mitmFlowImporter;
    private readonly PrivacyWatchProfileStore _profileStore;
    private readonly PrivacyTelemetryStore _telemetryStore;
    private readonly FullTraceManager _fullTraceManager;
    private readonly TimeSpan _pollInterval;
    private CancellationTokenSource? _loopCts;
    private Task? _loopTask;
    private long _nextLineNumber;

    public LiveMitmFlowProcessor(
        MitmProxyService mitmProxyService,
        MitmFlowImporter mitmFlowImporter,
        PrivacyWatchProfileStore profileStore,
        PrivacyTelemetryStore telemetryStore,
        FullTraceManager fullTraceManager,
        TimeSpan? pollInterval = null)
    {
        _mitmProxyService = mitmProxyService;
        _mitmFlowImporter = mitmFlowImporter;
        _profileStore = profileStore;
        _telemetryStore = telemetryStore;
        _fullTraceManager = fullTraceManager;
        _pollInterval = pollInterval ?? DefaultPollInterval;
    }

    public void Start()
    {
        if (_loopTask != null) return;
        _loopCts = new CancellationTokenSource();
        _loopTask = Task.Run(() => RunLoopAsync(_loopCts.Token));
    }

    public async Task StopAsync()
    {
        if (_loopCts == null) return;
        _loopCts.Cancel();
        try { if (_loopTask != null) await _loopTask.ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        _loopCts.Dispose();
        _loopCts = null;
        _loopTask = null;
    }

    private async Task RunLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await ProcessNewFlowsAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await Task.Delay(_pollInterval, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    // Public so tests (and any manual "kick" callers) can drive one iteration
    // without owning the background loop.
    public async Task ProcessNewFlowsAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_mitmProxyService.GetStatus().State != MitmProxyState.Running ||
                !File.Exists(_mitmProxyService.FlowExportPath))
            {
                return;
            }

            try
            {
                var profile = await _profileStore.LoadAsync(cancellationToken).ConfigureAwait(false);
                var pipeline = new IngressTelemetryPipeline(
                    _mitmFlowImporter,
                    new PrivacyTelemetryAnalyzer(profile),
                    _telemetryStore,
                    _fullTraceManager);

                var result = await pipeline
                    .ProcessMitmJsonLinesAsync(_mitmProxyService.FlowExportPath, _nextLineNumber, cancellationToken)
                    .ConfigureAwait(false);

                _nextLineNumber = result.NextLineNumber ?? _nextLineNumber;
                _mitmProxyService.RecordImportedFlows(result.EventsProcessed);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Broad on purpose: this runs on a background loop that must never
                // die from a single bad line, a stopped proxy, a disposed process
                // handle, or any wrapper-layer surprise. Record and move on.
                _mitmProxyService.RecordImportError(ex.Message);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _gate.Dispose();
    }
}
