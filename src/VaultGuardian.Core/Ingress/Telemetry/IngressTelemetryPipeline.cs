using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Ingress.Telemetry;

public sealed record IngressTelemetryPipelineResult(
    int EventsProcessed,
    int HitsDetected,
    FullTraceStatus FullTrace);

public sealed class IngressTelemetryPipeline
{
    private readonly MitmFlowImporter _mitmFlowImporter;
    private readonly PrivacyTelemetryAnalyzer _analyzer;
    private readonly PrivacyTelemetryStore _telemetryStore;
    private readonly FullTraceManager _fullTraceManager;

    public IngressTelemetryPipeline(
        MitmFlowImporter mitmFlowImporter,
        PrivacyTelemetryAnalyzer analyzer,
        PrivacyTelemetryStore telemetryStore,
        FullTraceManager fullTraceManager)
    {
        _mitmFlowImporter = mitmFlowImporter;
        _analyzer = analyzer;
        _telemetryStore = telemetryStore;
        _fullTraceManager = fullTraceManager;
    }

    public async Task<IngressTelemetryPipelineResult> ProcessMitmFileAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        var events = await _mitmFlowImporter.ImportAsync(path, cancellationToken).ConfigureAwait(false);
        var hits = new List<PrivacyTelemetryHit>();

        foreach (var contentEvent in events)
        {
            var analysis = _analyzer.Analyze(contentEvent);
            hits.AddRange(analysis.Hits);

            foreach (var hit in analysis.Hits)
            {
                _fullTraceManager.Trigger(new FullTraceTrigger(
                    FullTraceScopeKind.BrowserProfile,
                    Flow: null,
                    $"privacy selector `{hit.SelectorLabel}` matched",
                    hit.DetectedAt));
            }
        }

        await _telemetryStore.AppendAsync(hits, cancellationToken).ConfigureAwait(false);
        return new IngressTelemetryPipelineResult(events.Count, hits.Count, _fullTraceManager.GetStatus());
    }
}
