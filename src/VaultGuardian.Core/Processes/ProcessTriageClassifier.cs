namespace VaultGuardian.Core.Processes;

/// <summary>
/// Turns <see cref="ProcessFacts"/> into a <see cref="ProcessTriageVerdict"/> so
/// the operator can act on a resource hog fast instead of retracing the tree by
/// hand. Kill-safety is driven by the kernel critical-process bit and a curated
/// list of OS images; disposition is driven by signature and image-path trust,
/// enriched by any network hostnames correlated to the process.
/// </summary>
public static class ProcessTriageClassifier
{
    // Killing any of these bugchecks Windows or forces a sign-out, even when the
    // kernel critical bit is not readable without higher privilege.
    private static readonly HashSet<string> CriticalImages = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "registry", "smss", "csrss", "wininit", "winlogon", "services",
        "lsass", "lsaiso", "fontdrvhost", "dwm", "memory compression"
    };

    // User-writable locations that legitimate system software rarely runs from.
    private static readonly string[] UntrustedPathMarkers =
    [
        @"\appdata\local\temp\", @"\appdata\roaming\", @"\temp\", @"\downloads\",
        @"\users\public\", @"\programdata\temp\"
    ];

    public static ProcessTriageVerdict Classify(ProcessFacts facts)
    {
        var reasons = new List<string>();
        var killSafety = ClassifyKillSafety(facts, reasons);
        var disposition = ClassifyDisposition(facts, reasons);
        return new ProcessTriageVerdict(disposition, killSafety, reasons);
    }

    private static KillSafety ClassifyKillSafety(ProcessFacts facts, List<string> reasons)
    {
        var normalizedName = StripExeSuffix(facts.Name);

        if (facts.IsCriticalProcess)
        {
            reasons.Add("Marked critical by the kernel — terminating it bugchecks Windows.");
            return KillSafety.BreaksWindows;
        }

        if (CriticalImages.Contains(normalizedName))
        {
            reasons.Add($"'{facts.Name}' is a core Windows process; terminating it crashes or signs out the session.");
            return KillSafety.BreaksWindows;
        }

        if (facts.RunsInUtilityVm)
        {
            reasons.Add("Aggregate for a Hyper-V utility VM (e.g. WSL2); drill in from inside the VM rather than killing the host process.");
            return KillSafety.RiskyToShutdown;
        }

        if (facts.IsServiceHost || facts.HostedServices.Count > 0)
        {
            var services = facts.HostedServices.Count > 0
                ? string.Join(", ", facts.HostedServices)
                : "one or more services";
            reasons.Add($"Hosts {services}; terminating it stops those services.");
            return KillSafety.RiskyToShutdown;
        }

        return KillSafety.SafeToShutdown;
    }

    private static ProcessDisposition ClassifyDisposition(ProcessFacts facts, List<string> reasons)
    {
        var suspicious = false;

        if (facts.Signature == SignatureStatus.Unsigned)
        {
            reasons.Add("Image is unsigned.");
            suspicious = true;
        }
        else if (facts.Signature == SignatureStatus.SignedUntrusted)
        {
            reasons.Add("Image is signed but the certificate does not chain to a trusted root.");
            suspicious = true;
        }

        if (HasUntrustedPath(facts.ImagePath))
        {
            reasons.Add($"Runs from a user-writable location ({facts.ImagePath}).");
            suspicious = true;
        }

        if (facts.Hostnames.Count > 0)
        {
            reasons.Add($"Network activity to: {string.Join(", ", facts.Hostnames)}.");
        }

        if (suspicious)
        {
            return ProcessDisposition.Suspicious;
        }

        if (facts.Signature == SignatureStatus.SignedTrusted)
        {
            if (!string.IsNullOrWhiteSpace(facts.Publisher))
            {
                reasons.Add($"Signed by {facts.Publisher}.");
            }

            return ProcessDisposition.Legit;
        }

        return ProcessDisposition.Unknown;
    }

    private static bool HasUntrustedPath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            return false;
        }

        foreach (var marker in UntrustedPathMarkers)
        {
            if (imagePath.Contains(marker, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string StripExeSuffix(string name) =>
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? name[..^4]
            : name;
}
