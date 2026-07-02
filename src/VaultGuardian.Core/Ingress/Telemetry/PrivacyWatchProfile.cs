using System.Text.RegularExpressions;

namespace VaultGuardian.Core.Ingress.Telemetry;

public enum PrivacySelectorKind
{
    Literal,
    Regex
}

public enum PrivacyHitConfidence
{
    Low,
    Medium,
    High
}

public sealed record PrivacySelector(
    string Label,
    PrivacySelectorKind Kind,
    string Value,
    bool Enabled);

public sealed record PrivacyWatchProfile(IReadOnlyList<PrivacySelector> Selectors)
{
    public static PrivacyWatchProfile Empty { get; } = new([]);
}

public sealed record PrivacyTelemetryHit(
    DateTimeOffset DetectedAt,
    string SelectorLabel,
    PrivacyHitConfidence Confidence,
    string Summary,
    string EvidencePreview,
    string? Host,
    string? Url,
    string Source);

public static class PrivacySelectorMatcher
{
    public static IReadOnlyList<PrivacyTelemetryHit> Match(
        PrivacyWatchProfile profile,
        string? text,
        DateTimeOffset detectedAt,
        IngressContentEvent? contentEvent = null)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        var hits = new List<PrivacyTelemetryHit>();
        foreach (var selector in profile.Selectors.Where(selector => selector.Enabled))
        {
            bool matched;
            try
            {
                matched = selector.Kind switch
                {
                    PrivacySelectorKind.Literal => text.Contains(selector.Value, StringComparison.OrdinalIgnoreCase),
                    PrivacySelectorKind.Regex => Regex.IsMatch(
                        text,
                        selector.Value,
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                        TimeSpan.FromMilliseconds(250)),
                    _ => false
                };
            }
            catch (ArgumentException)
            {
                // User-supplied selector.Value isn't a valid regex; treat as no match
                // rather than tearing down the entire selector loop.
                matched = false;
            }
            catch (RegexMatchTimeoutException)
            {
                matched = false;
            }

            if (!matched)
            {
                continue;
            }

            hits.Add(new PrivacyTelemetryHit(
                detectedAt,
                selector.Label,
                PrivacyHitConfidence.High,
                $"Privacy selector `{selector.Label}` matched local content.",
                BuildEvidencePreview(text, selector),
                contentEvent?.Host,
                contentEvent?.Url,
                contentEvent?.Source.ToString() ?? "Unknown"));
        }

        return hits;
    }

    private static string BuildEvidencePreview(string text, PrivacySelector selector)
    {
        if (selector.Kind == PrivacySelectorKind.Literal)
        {
            return text.Replace(selector.Value, "[redacted]", StringComparison.OrdinalIgnoreCase);
        }

        try
        {
            return Regex.Replace(
                text,
                selector.Value,
                "[redacted]",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                TimeSpan.FromMilliseconds(250));
        }
        catch (ArgumentException)
        {
            return "[redacted]";
        }
        catch (RegexMatchTimeoutException)
        {
            return "[redacted]";
        }
    }
}
