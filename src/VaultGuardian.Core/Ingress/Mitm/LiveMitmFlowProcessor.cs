using System.Text.Json;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Ingress.Mitm;

public sealed class LiveMitmFlowProcessor
{
    private readonly object _gate = new();
    private readonly MitmProxyService _mitmProxyService;
    private readonly MitmFlowImporter _mitmFlowImporter;
    private readonly PrivacyWatchProfileStore _profileStore;
    private readonly PrivacyTelemetryStore _telemetryStore;
    private readonly FullTraceManager _fullTraceManager;
    private long _nextLineNumber;

    public LiveMitmFlowProcessor(
        MitmProxyService mitmProxyService,
        MitmFlowImporter mitmFlowImporter,
        PrivacyWatchProfileStore profileStore,
        PrivacyTelemetryStore telemetryStore,
        FullTraceManager fullTraceManager)
    {
        _mitmProxyService = mitmProxyService;
        _mitmFlowImporter = mitmFlowImporter;
        _profileStore = profileStore;
        _telemetryStore = telemetryStore;
        _fullTraceManager = fullTraceManager;
    }

    public void ProcessNewFlows()
    {
        lock (_gate)
        {
            if (_mitmProxyService.GetStatus().State != MitmProxyState.Running ||
                !File.Exists(_mitmProxyService.FlowExportPath))
            {
                return;
            }

            try
            {
                var profile = _profileStore.LoadAsync().GetAwaiter().GetResult();
                var pipeline = new IngressTelemetryPipeline(
                    _mitmFlowImporter,
                    new PrivacyTelemetryAnalyzer(profile),
                    _telemetryStore,
                    _fullTraceManager);

                var result = pipeline.ProcessMitmJsonLinesAsync(_mitmProxyService.FlowExportPath, _nextLineNumber)
                    .GetAwaiter()
                    .GetResult();

                _nextLineNumber = result.NextLineNumber ?? _nextLineNumber;
                _mitmProxyService.RecordImportedFlows(result.EventsProcessed);
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                _mitmProxyService.RecordImportError(ex.Message);
            }
        }
    }
}
