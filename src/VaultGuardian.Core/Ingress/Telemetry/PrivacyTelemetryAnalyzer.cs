namespace VaultGuardian.Core.Ingress.Telemetry;

public sealed record PrivacyTelemetryAnalysis(
    IngressContentEvent ContentEvent,
    IReadOnlyList<PrivacyTelemetryHit> Hits,
    IReadOnlyList<string> Tags);

public sealed class PrivacyTelemetryAnalyzer
{
    private readonly PrivacyWatchProfile _profile;

    public PrivacyTelemetryAnalyzer(PrivacyWatchProfile profile)
    {
        _profile = profile;
    }

    public PrivacyTelemetryAnalysis Analyze(IngressContentEvent contentEvent)
    {
        var tags = new List<string>();
        if (LooksLikeTelemetry(contentEvent))
        {
            tags.Add("telemetry.endpoint");
        }

        if (contentEvent.Source is IngressContentSource.MitmRequest or IngressContentSource.MitmResponse)
        {
            tags.Add("decrypted.browser-profile");
        }

        var hits = PrivacySelectorMatcher.Match(_profile, contentEvent.Text, contentEvent.CapturedAt, contentEvent);
        return new PrivacyTelemetryAnalysis(contentEvent, hits, tags);
    }

    private static bool LooksLikeTelemetry(IngressContentEvent contentEvent)
    {
        var combined = $"{contentEvent.Host} {contentEvent.Path} {contentEvent.Url}";
        return combined.Contains("analytics", StringComparison.OrdinalIgnoreCase) ||
               combined.Contains("telemetry", StringComparison.OrdinalIgnoreCase) ||
               combined.Contains("collect", StringComparison.OrdinalIgnoreCase) ||
               combined.Contains("beacon", StringComparison.OrdinalIgnoreCase) ||
               combined.Contains("metrics", StringComparison.OrdinalIgnoreCase);
    }
}
