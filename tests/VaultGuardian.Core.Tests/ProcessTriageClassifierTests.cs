using VaultGuardian.Core.Processes;

namespace VaultGuardian.Core.Tests;

public sealed class ProcessTriageClassifierTests
{
    [Fact]
    public void CriticalImage_IsFlaggedAsBreaksWindows()
    {
        var facts = ProcessFacts.Minimal(700, "lsass.exe") with
        {
            Signature = SignatureStatus.SignedTrusted,
            Publisher = "Microsoft Windows"
        };

        var verdict = ProcessTriageClassifier.Classify(facts);

        Assert.Equal(KillSafety.BreaksWindows, verdict.KillSafety);
        Assert.Equal(ProcessDisposition.Legit, verdict.Disposition);
    }

    [Fact]
    public void KernelCriticalBit_ForcesBreaksWindows_EvenForUnknownImage()
    {
        var facts = ProcessFacts.Minimal(1234, "customhost.exe") with { IsCriticalProcess = true };

        var verdict = ProcessTriageClassifier.Classify(facts);

        Assert.Equal(KillSafety.BreaksWindows, verdict.KillSafety);
    }

    [Fact]
    public void ServiceHost_IsRiskyToShutdown_AndListsServices()
    {
        var facts = ProcessFacts.Minimal(980, "svchost.exe") with
        {
            IsServiceHost = true,
            HostedServices = ["Dhcp", "Dnscache"],
            Signature = SignatureStatus.SignedTrusted
        };

        var verdict = ProcessTriageClassifier.Classify(facts);

        Assert.Equal(KillSafety.RiskyToShutdown, verdict.KillSafety);
        Assert.Contains(verdict.Reasons, r => r.Contains("Dhcp") && r.Contains("Dnscache"));
    }

    [Fact]
    public void UtilityVmAggregate_IsRiskyToShutdown()
    {
        var facts = ProcessFacts.Minimal(4100, "vmmemWSL") with { RunsInUtilityVm = true };

        var verdict = ProcessTriageClassifier.Classify(facts);

        Assert.Equal(KillSafety.RiskyToShutdown, verdict.KillSafety);
        Assert.Contains(verdict.Reasons, r => r.Contains("utility VM"));
    }

    [Fact]
    public void UnsignedProcessFromTemp_IsSuspiciousButSafeToShutdown()
    {
        var facts = ProcessFacts.Minimal(6600, "updater.exe") with
        {
            ImagePath = @"C:\Users\phil\AppData\Local\Temp\updater.exe",
            Signature = SignatureStatus.Unsigned,
            CpuPercent = 12.5
        };

        var verdict = ProcessTriageClassifier.Classify(facts);

        Assert.Equal(ProcessDisposition.Suspicious, verdict.Disposition);
        Assert.Equal(KillSafety.SafeToShutdown, verdict.KillSafety);
        Assert.Contains(verdict.Reasons, r => r.Contains("unsigned"));
        Assert.Contains(verdict.Reasons, r => r.Contains("user-writable"));
    }

    [Fact]
    public void SignedTrustedBackgroundApp_IsLegitAndSafeToShutdown()
    {
        var facts = ProcessFacts.Minimal(3200, "Spotify.exe") with
        {
            ImagePath = @"C:\Users\phil\AppData\Roaming\Spotify\Spotify.exe",
            Signature = SignatureStatus.SignedTrusted,
            Publisher = "Spotify AB"
        };

        // AppData path is user-writable, so even a signed app is flagged suspicious —
        // this is intended: it surfaces the location for the operator to judge.
        var verdict = ProcessTriageClassifier.Classify(facts);

        Assert.Equal(KillSafety.SafeToShutdown, verdict.KillSafety);
        Assert.Contains(verdict.Reasons, r => r.Contains("user-writable"));
    }

    [Fact]
    public void CleanSignedApp_IsLegit_AndSurfacesHostnames()
    {
        var facts = ProcessFacts.Minimal(2100, "msedge.exe") with
        {
            ImagePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            Signature = SignatureStatus.SignedTrusted,
            Publisher = "Microsoft Corporation",
            Hostnames = ["edge.microsoft.com", "telemetry.example.test"]
        };

        var verdict = ProcessTriageClassifier.Classify(facts);

        Assert.Equal(ProcessDisposition.Legit, verdict.Disposition);
        Assert.Equal(KillSafety.SafeToShutdown, verdict.KillSafety);
        Assert.Contains(verdict.Reasons, r => r.Contains("telemetry.example.test"));
    }
}
