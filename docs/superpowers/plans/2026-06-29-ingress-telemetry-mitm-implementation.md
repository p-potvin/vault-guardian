# Ingress Telemetry MITM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add local privacy telemetry detection, bounded full-trace triggers, and a browser-profile mitmproxy workflow to VaultGuardian ingress monitoring.

**Architecture:** Keep WinDivert passive capture as the base signal, then normalize passive packets and decrypted MITM flow fixtures into a shared ingress content event pipeline. Store privacy selectors locally with DPAPI protection, emit redacted telemetry hits, and let hits activate bounded full-trace scopes that temporarily relax sampling only for matching sources/flows/profiles.

**Tech Stack:** .NET 10, WinUI 3, WindivertDotnet, `System.Text.Json` source generation, Windows DPAPI via `System.Security.Cryptography.ProtectedData`, external `mitmdump` process invoked through a new non-blocking managed process launcher because the existing `IProcessRunner` waits for process exit.

---

## File Structure

- Create `src/VaultGuardian.Core/Ingress/Telemetry/IngressContentEvent.cs`: normalized content-event models for passive packets, MITM requests/responses, and later key-log traces.
- Create `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyWatchProfile.cs`: selector models, hit models, confidence enum, and redaction helpers.
- Create `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyWatchProfileStore.cs`: local profile load/save with DPAPI-protected selector values.
- Create `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyTelemetryAnalyzer.cs`: selector matching and telemetry heuristics.
- Create `src/VaultGuardian.Core/Ingress/Tracing/FullTraceModels.cs`: trace trigger and active trace scope models.
- Create `src/VaultGuardian.Core/Ingress/Tracing/FullTraceManager.cs`: bounded full trace lifecycle and capture decisions.
- Modify `src/VaultGuardian.Core/Ingress/IngressCaptureLimiter.cs`: accept active full-trace scope overrides while preserving global disk/archive safety.
- Create `src/VaultGuardian.Core/Ingress/Mitm/MitmProxyModels.cs`: mitmproxy status, config, and flow import models.
- Create `src/VaultGuardian.Core/Ingress/Mitm/MitmFlowImporter.cs`: import decrypted mitmproxy JSON fixture/events into content events.
- Create `src/VaultGuardian.Core/Ingress/Mitm/MitmProxyService.cs`: start/stop local `mitmdump`, create browser profile path, and launch Edge/Chromium with proxy/profile arguments.
- Create `src/VaultGuardian.Core/Diagnostics/IManagedProcessLauncher.cs`: non-blocking process launcher abstraction for long-running local proxy/browser processes.
- Create `src/VaultGuardian.Core/Diagnostics/ManagedProcessLauncher.cs`: `System.Diagnostics.Process` implementation with explicit stop/dispose behavior.
- Modify `src/VaultGuardian.Core/Observability/SystemMetrics.cs` and `src/VaultGuardian.Core/Observability/LiveMonitorService.cs`: expose telemetry hits, full-trace status, and MITM status.
- Modify `src/VaultGuardian.UI/MainWindow.xaml`: add telemetry and MITM status controls inside the existing Ingress pivot using current VaultWares theme tokens.
- Modify `src/VaultGuardian.UI/MainWindow.xaml.cs`: render telemetry hits, trace state, and MITM status; wire start/stop/export buttons to services.
- Modify `src/VaultGuardian.UI/App.xaml.cs`: register new services and store paths under `AppDomain.CurrentDomain.BaseDirectory`.
- Create tests under `tests/VaultGuardian.Core.Tests/IngressTelemetry*Tests.cs`, `IngressFullTrace*Tests.cs`, and `IngressMitm*Tests.cs`.
- Create fixtures under `tests/VaultGuardian.Core.Tests/Fixtures/mitmproxy-flow-httpbin.json`.

---

### Task 1: Normalized Content Events

**Files:**
- Create: `src/VaultGuardian.Core/Ingress/Telemetry/IngressContentEvent.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressContentEventTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/VaultGuardian.Core.Tests/IngressContentEventTests.cs`:

```csharp
using System.Text;
using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressContentEventTests
{
    [Fact]
    public void FromPacketObservation_CarriesFlowAndPlaintextSample()
    {
        var flow = new IngressFlowKey(
            "203.0.113.10",
            443,
            "192.168.1.25",
            51000,
            TrafficProtocol.Tcp,
            42,
            "browser",
            @"C:\Apps\browser.exe");
        var payload = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nemail@example.test");
        var sample = IngressPayloadClassifier.ClassifyAndSample(payload, DateTimeOffset.UtcNow);
        var observation = new IngressPacketObservation(flow, DateTimeOffset.UtcNow, payload.Length + 40, payload.Length, sample);

        var contentEvent = IngressContentEvent.FromPacketObservation(observation);

        Assert.Equal(IngressContentSource.PassivePacket, contentEvent.Source);
        Assert.Equal("203.0.113.10", contentEvent.RemoteAddress);
        Assert.Equal("browser", contentEvent.ProcessName);
        Assert.Equal(IngressContentClassification.Plaintext, contentEvent.Classification);
        Assert.Contains("email@example.test", contentEvent.Text ?? string.Empty);
    }

    [Fact]
    public void FromMitmFlow_CarriesHttpMetadataWithoutProcessAttribution()
    {
        var flow = new MitmHttpFlowEvent(
            FlowId: "flow-1",
            CapturedAt: DateTimeOffset.UtcNow,
            Url: "https://telemetry.example.test/collect",
            Method: "POST",
            StatusCode: 204,
            RequestHeaders: new Dictionary<string, string> { ["content-type"] = "application/json" },
            ResponseHeaders: new Dictionary<string, string>(),
            RequestBody: "{\"device\":\"abc\"}",
            ResponseBody: string.Empty);

        var contentEvent = IngressContentEvent.FromMitmFlow(flow);

        Assert.Equal(IngressContentSource.MitmRequest, contentEvent.Source);
        Assert.Equal("telemetry.example.test", contentEvent.Host);
        Assert.Equal("POST", contentEvent.HttpMethod);
        Assert.Equal("/collect", contentEvent.Path);
        Assert.Contains("device", contentEvent.Text ?? string.Empty);
    }
}
```

- [ ] **Step 2: Run the tests to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressContentEventTests -v:minimal
```

Expected: compile failure because `IngressContentEvent`, `IngressContentSource`, and `MitmHttpFlowEvent` do not exist.

- [ ] **Step 3: Implement the models**

Create `src/VaultGuardian.Core/Ingress/Telemetry/IngressContentEvent.cs`:

```csharp
namespace VaultGuardian.Core.Ingress.Telemetry;

public enum IngressContentSource
{
    PassivePacket,
    MitmRequest,
    MitmResponse,
    KeyLogDecryptedTrace
}

public sealed record MitmHttpFlowEvent(
    string FlowId,
    DateTimeOffset CapturedAt,
    string Url,
    string Method,
    int? StatusCode,
    IReadOnlyDictionary<string, string> RequestHeaders,
    IReadOnlyDictionary<string, string> ResponseHeaders,
    string? RequestBody,
    string? ResponseBody);

public sealed record IngressContentEvent(
    IngressContentSource Source,
    DateTimeOffset CapturedAt,
    string? RemoteAddress,
    int? RemotePort,
    string? LocalAddress,
    int? LocalPort,
    TrafficProtocol Protocol,
    int? ProcessId,
    string? ProcessName,
    string? ProcessPath,
    string? Host,
    string? Url,
    string? Path,
    string? HttpMethod,
    int? StatusCode,
    string? ContentType,
    IngressContentClassification Classification,
    string? Text,
    long BodyLength,
    string? FlowId)
{
    public static IngressContentEvent FromPacketObservation(IngressPacketObservation observation)
    {
        var sample = observation.PayloadSample;
        return new IngressContentEvent(
            IngressContentSource.PassivePacket,
            observation.Timestamp,
            observation.Flow.RemoteAddress,
            observation.Flow.RemotePort,
            observation.Flow.LocalAddress,
            observation.Flow.LocalPort,
            observation.Flow.Protocol,
            observation.Flow.ProcessId,
            observation.Flow.ProcessName,
            observation.Flow.ProcessPath,
            Host: null,
            Url: null,
            Path: null,
            HttpMethod: null,
            StatusCode: null,
            ContentType: ExtractHeader(sample?.TextPreview, "content-type"),
            sample?.Classification ?? IngressContentClassification.Unknown,
            sample?.TextPreview,
            observation.PayloadLength,
            FlowId: null);
    }

    public static IngressContentEvent FromMitmFlow(MitmHttpFlowEvent flow)
    {
        var uri = new Uri(flow.Url);
        var contentType = flow.RequestHeaders.TryGetValue("content-type", out var value)
            ? value
            : null;
        return new IngressContentEvent(
            IngressContentSource.MitmRequest,
            flow.CapturedAt,
            RemoteAddress: null,
            RemotePort: null,
            LocalAddress: null,
            LocalPort: null,
            TrafficProtocol.Tcp,
            ProcessId: null,
            ProcessName: "BrowserProfile",
            ProcessPath: null,
            uri.Host,
            flow.Url,
            string.IsNullOrWhiteSpace(uri.Query) ? uri.AbsolutePath : uri.PathAndQuery,
            flow.Method,
            flow.StatusCode,
            contentType,
            IngressContentClassification.Plaintext,
            flow.RequestBody,
            flow.RequestBody?.Length ?? 0,
            flow.FlowId);
    }

    private static string? ExtractHeader(string? text, string headerName)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        foreach (var line in text.Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            if (string.Equals(line[..separator].Trim(), headerName, StringComparison.OrdinalIgnoreCase))
            {
                return line[(separator + 1)..].Trim();
            }
        }

        return null;
    }
}
```

- [ ] **Step 4: Run the tests to verify green**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressContentEventTests -v:minimal
```

Expected: 2 tests pass.

---

### Task 2: Privacy Watch Profile With Redacted Hits

**Files:**
- Create: `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyWatchProfile.cs`
- Create: `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyWatchProfileStore.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressPrivacyWatchProfileTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/VaultGuardian.Core.Tests/IngressPrivacyWatchProfileTests.cs`:

```csharp
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressPrivacyWatchProfileTests
{
    [Fact]
    public void SelectorMatch_ReturnsLabelWithoutRawValue()
    {
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("email.primary", PrivacySelectorKind.Literal, "person@example.test", Enabled: true)
        ]);
        var text = "POST body contains person@example.test";

        var hits = PrivacySelectorMatcher.Match(profile, text, DateTimeOffset.UtcNow);

        var hit = Assert.Single(hits);
        Assert.Equal("email.primary", hit.SelectorLabel);
        Assert.DoesNotContain("person@example.test", hit.Summary);
        Assert.DoesNotContain("person@example.test", hit.EvidencePreview);
    }

    [Fact]
    public async Task Store_RoundTripsProfileWithoutWritingPlainSelectorValue()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-privacy-profile.json");
        var store = new PrivacyWatchProfileStore(path);
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("username.github", PrivacySelectorKind.Literal, "sensitive-user", Enabled: true)
        ]);

        await store.SaveAsync(profile);
        var rawFile = await File.ReadAllTextAsync(path);
        var loaded = await store.LoadAsync();

        Assert.DoesNotContain("sensitive-user", rawFile);
        Assert.Equal("sensitive-user", Assert.Single(loaded.Selectors).Value);
    }
}
```

- [ ] **Step 2: Run the tests to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressPrivacyWatchProfileTests -v:minimal
```

Expected: compile failure because privacy selector types and store do not exist.

- [ ] **Step 3: Add DPAPI package**

Add this to `src/VaultGuardian.Core/VaultGuardian.Core.csproj` so `ProtectedData` is available consistently on the Windows target:

```xml
<PackageReference Include="System.Security.Cryptography.ProtectedData" Version="10.0.8" />
```

- [ ] **Step 4: Implement privacy models and matcher**

Create `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyWatchProfile.cs`:

```csharp
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
            var matched = selector.Kind switch
            {
                PrivacySelectorKind.Literal => text.Contains(selector.Value, StringComparison.OrdinalIgnoreCase),
                PrivacySelectorKind.Regex => Regex.IsMatch(text, selector.Value, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250)),
                _ => false
            };

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

        return Regex.Replace(text, selector.Value, "[redacted]", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250));
    }
}
```

- [ ] **Step 5: Implement DPAPI-backed store**

Create `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyWatchProfileStore.cs`:

```csharp
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress.Telemetry;

public sealed class PrivacyWatchProfileStore
{
    private readonly string _path;

    public PrivacyWatchProfileStore(string path)
    {
        _path = path;
    }

    public async Task<PrivacyWatchProfile> LoadAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_path))
        {
            return PrivacyWatchProfile.Empty;
        }

        var json = await File.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false);
        var stored = JsonSerializer.Deserialize(json, PrivacyWatchProfileJsonContext.Default.StoredPrivacyWatchProfile);
        if (stored == null)
        {
            return PrivacyWatchProfile.Empty;
        }

        return new PrivacyWatchProfile(stored.Selectors
            .Select(selector => new PrivacySelector(
                selector.Label,
                selector.Kind,
                Unprotect(selector.ProtectedValue),
                selector.Enabled))
            .ToArray());
    }

    public async Task SaveAsync(PrivacyWatchProfile profile, CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var stored = new StoredPrivacyWatchProfile(profile.Selectors
            .Select(selector => new StoredPrivacySelector(
                selector.Label,
                selector.Kind,
                Protect(selector.Value),
                selector.Enabled))
            .ToArray());
        var json = JsonSerializer.Serialize(stored, PrivacyWatchProfileJsonContext.Default.StoredPrivacyWatchProfile);
        await File.WriteAllTextAsync(_path, json, cancellationToken).ConfigureAwait(false);
    }

    private static string Protect(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var protectedBytes = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Convert.ToBase64String(protectedBytes);
    }

    private static string Unprotect(string value)
    {
        var protectedBytes = Convert.FromBase64String(value);
        var bytes = ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
        return Encoding.UTF8.GetString(bytes);
    }
}

public sealed record StoredPrivacyWatchProfile(IReadOnlyList<StoredPrivacySelector> Selectors);

public sealed record StoredPrivacySelector(
    string Label,
    PrivacySelectorKind Kind,
    string ProtectedValue,
    bool Enabled);

[JsonSerializable(typeof(StoredPrivacyWatchProfile))]
[JsonSourceGenerationOptions(WriteIndented = true, Converters = [typeof(JsonStringEnumConverter<PrivacySelectorKind>)])]
internal sealed partial class PrivacyWatchProfileJsonContext : JsonSerializerContext;
```

- [ ] **Step 6: Run the tests to verify green**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressPrivacyWatchProfileTests -v:minimal
```

Expected: 2 tests pass and the raw temp JSON file does not contain selector values.

---

### Task 3: Telemetry Analyzer and Hit Archive

**Files:**
- Create: `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyTelemetryAnalyzer.cs`
- Create: `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyTelemetryStore.cs`
- Modify: `src/VaultGuardian.Core/Observability/SystemMetrics.cs`
- Modify: `src/VaultGuardian.Core/Observability/LiveMonitorService.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressTelemetryAnalyzerTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/VaultGuardian.Core.Tests/IngressTelemetryAnalyzerTests.cs`:

```csharp
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressTelemetryAnalyzerTests
{
    [Fact]
    public void Analyze_DetectsPrivacySelectorAndTelemetryEndpoint()
    {
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("email.primary", PrivacySelectorKind.Literal, "person@example.test", Enabled: true)
        ]);
        var analyzer = new PrivacyTelemetryAnalyzer(profile);
        var contentEvent = new IngressContentEvent(
            IngressContentSource.MitmRequest,
            DateTimeOffset.UtcNow,
            RemoteAddress: null,
            RemotePort: null,
            LocalAddress: null,
            LocalPort: null,
            TrafficProtocol.Tcp,
            ProcessId: null,
            ProcessName: "BrowserProfile",
            ProcessPath: null,
            Host: "analytics.example.test",
            Url: "https://analytics.example.test/collect",
            Path: "/collect",
            HttpMethod: "POST",
            StatusCode: 204,
            ContentType: "application/json",
            IngressContentClassification.Plaintext,
            Text: "{\"email\":\"person@example.test\"}",
            BodyLength: 31,
            FlowId: "flow-1");

        var result = analyzer.Analyze(contentEvent);

        Assert.Contains(result.Hits, hit => hit.SelectorLabel == "email.primary");
        Assert.Contains(result.Tags, tag => tag == "telemetry.endpoint");
        Assert.DoesNotContain("person@example.test", string.Join("\n", result.Hits.Select(hit => hit.EvidencePreview)));
    }
}
```

- [ ] **Step 2: Run the test to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressTelemetryAnalyzerTests -v:minimal
```

Expected: compile failure because `PrivacyTelemetryAnalyzer` does not exist.

- [ ] **Step 3: Implement analyzer**

Create `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyTelemetryAnalyzer.cs`:

```csharp
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

        if (contentEvent.Source == IngressContentSource.MitmRequest ||
            contentEvent.Source == IngressContentSource.MitmResponse)
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
```

- [ ] **Step 4: Add append-only hit store**

Create `src/VaultGuardian.Core/Ingress/Telemetry/PrivacyTelemetryStore.cs`:

```csharp
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress.Telemetry;

public sealed class PrivacyTelemetryStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<PrivacyTelemetryHit> _hits;

    public PrivacyTelemetryStore(string path)
    {
        _path = path;
        _hits = Load(path);
    }

    public async Task AppendAsync(IEnumerable<PrivacyTelemetryHit> hits, CancellationToken cancellationToken = default)
    {
        var newHits = hits.ToArray();
        if (newHits.Length == 0)
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            foreach (var hit in newHits)
            {
                _hits.Add(hit);
                var line = JsonSerializer.Serialize(hit, PrivacyTelemetryJsonContext.Default.PrivacyTelemetryHit);
                await File.AppendAllTextAsync(_path, line + Environment.NewLine, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public IReadOnlyList<PrivacyTelemetryHit> ListRecent(int count = 50)
    {
        _gate.Wait();
        try
        {
            return _hits.OrderByDescending(hit => hit.DetectedAt).Take(count).ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    private static List<PrivacyTelemetryHit> Load(string path)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        var hits = new List<PrivacyTelemetryHit>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var hit = JsonSerializer.Deserialize(line, PrivacyTelemetryJsonContext.Default.PrivacyTelemetryHit);
            if (hit != null)
            {
                hits.Add(hit);
            }
        }

        return hits;
    }
}

[JsonSerializable(typeof(PrivacyTelemetryHit))]
[JsonSourceGenerationOptions(WriteIndented = false, Converters = [typeof(JsonStringEnumConverter<PrivacyHitConfidence>)])]
internal sealed partial class PrivacyTelemetryJsonContext : JsonSerializerContext;
```

- [ ] **Step 5: Run focused tests**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressTelemetryAnalyzerTests -v:minimal
```

Expected: analyzer test passes.

---

### Task 4: Full Trace Manager and Limiter Override

**Files:**
- Create: `src/VaultGuardian.Core/Ingress/Tracing/FullTraceModels.cs`
- Create: `src/VaultGuardian.Core/Ingress/Tracing/FullTraceManager.cs`
- Modify: `src/VaultGuardian.Core/Ingress/IngressCaptureLimiter.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressFullTraceManagerTests.cs`

- [ ] **Step 1: Write the failing tests**

Create `tests/VaultGuardian.Core.Tests/IngressFullTraceManagerTests.cs`:

```csharp
using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Tests;

public sealed class IngressFullTraceManagerTests
{
    [Fact]
    public void Trigger_ActivatesTraceForMatchingFlowAndStopsAtByteLimit()
    {
        var manager = new FullTraceManager(new FullTraceOptions(
            MaxDuration: TimeSpan.FromMinutes(5),
            MaxBytes: 100,
            MaxPackets: 10));
        var flow = Flow();
        var now = DateTimeOffset.UtcNow;

        var trigger = manager.Trigger(new FullTraceTrigger(
            FullTraceScopeKind.Flow,
            flow,
            "privacy selector `email.primary` matched",
            now));

        Assert.True(manager.ShouldBypassSampling(flow, now, packetLength: 50));
        Assert.True(manager.ShouldBypassSampling(flow, now.AddSeconds(1), packetLength: 50));
        Assert.False(manager.ShouldBypassSampling(flow, now.AddSeconds(2), packetLength: 1));
        Assert.Equal(FullTraceState.Stopped, manager.GetStatus().State);
        Assert.Equal(trigger.TraceId, manager.GetStatus().LastTraceId);
    }

    private static IngressFlowKey Flow()
    {
        return new IngressFlowKey(
            "203.0.113.55",
            443,
            "192.168.1.25",
            51000,
            TrafficProtocol.Tcp,
            42,
            "browser",
            @"C:\Apps\browser.exe");
    }
}
```

- [ ] **Step 2: Run the test to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressFullTraceManagerTests -v:minimal
```

Expected: compile failure because full trace types do not exist.

- [ ] **Step 3: Implement full trace models**

Create `src/VaultGuardian.Core/Ingress/Tracing/FullTraceModels.cs`:

```csharp
namespace VaultGuardian.Core.Ingress.Tracing;

public enum FullTraceScopeKind
{
    Flow,
    Source,
    BrowserProfile
}

public enum FullTraceState
{
    Idle,
    Active,
    Stopped
}

public sealed record FullTraceOptions(
    TimeSpan MaxDuration,
    long MaxBytes,
    int MaxPackets)
{
    public static FullTraceOptions Default { get; } = new(
        TimeSpan.FromMinutes(2),
        25 * 1024 * 1024,
        10_000);
}

public sealed record FullTraceTrigger(
    FullTraceScopeKind ScopeKind,
    IngressFlowKey? Flow,
    string Reason,
    DateTimeOffset TriggeredAt);

public sealed record ActiveFullTrace(
    string TraceId,
    FullTraceScopeKind ScopeKind,
    IngressFlowKey? Flow,
    string Reason,
    DateTimeOffset StartedAt,
    long CapturedBytes,
    int CapturedPackets);

public sealed record FullTraceStatus(
    FullTraceState State,
    string? ActiveTraceId,
    string? LastTraceId,
    string? Reason,
    long CapturedBytes,
    int CapturedPackets);
```

- [ ] **Step 4: Implement manager**

Create `src/VaultGuardian.Core/Ingress/Tracing/FullTraceManager.cs`:

```csharp
namespace VaultGuardian.Core.Ingress.Tracing;

public sealed class FullTraceManager
{
    private readonly object _lock = new();
    private readonly FullTraceOptions _options;
    private ActiveFullTrace? _active;
    private string? _lastTraceId;

    public FullTraceManager(FullTraceOptions? options = null)
    {
        _options = options ?? FullTraceOptions.Default;
    }

    public ActiveFullTrace Trigger(FullTraceTrigger trigger)
    {
        lock (_lock)
        {
            _active = new ActiveFullTrace(
                TraceId: $"trace-{Guid.NewGuid():N}",
                trigger.ScopeKind,
                trigger.Flow,
                trigger.Reason,
                trigger.TriggeredAt,
                CapturedBytes: 0,
                CapturedPackets: 0);
            return _active;
        }
    }

    public bool ShouldBypassSampling(IngressFlowKey flow, DateTimeOffset now, int packetLength)
    {
        lock (_lock)
        {
            if (_active == null)
            {
                return false;
            }

            if (now - _active.StartedAt > _options.MaxDuration ||
                _active.CapturedBytes + packetLength > _options.MaxBytes ||
                _active.CapturedPackets + 1 > _options.MaxPackets)
            {
                StopActive();
                return false;
            }

            var matches = _active.ScopeKind switch
            {
                FullTraceScopeKind.Flow => _active.Flow == flow,
                FullTraceScopeKind.Source => string.Equals(_active.Flow?.RemoteAddress, flow.RemoteAddress, StringComparison.OrdinalIgnoreCase),
                FullTraceScopeKind.BrowserProfile => string.Equals(flow.ProcessName, "BrowserProfile", StringComparison.OrdinalIgnoreCase),
                _ => false
            };

            if (!matches)
            {
                return false;
            }

            _active = _active with
            {
                CapturedBytes = _active.CapturedBytes + packetLength,
                CapturedPackets = _active.CapturedPackets + 1
            };
            return true;
        }
    }

    public FullTraceStatus GetStatus()
    {
        lock (_lock)
        {
            if (_active == null)
            {
                return new FullTraceStatus(FullTraceState.Stopped, null, _lastTraceId, null, 0, 0);
            }

            return new FullTraceStatus(
                FullTraceState.Active,
                _active.TraceId,
                _lastTraceId,
                _active.Reason,
                _active.CapturedBytes,
                _active.CapturedPackets);
        }
    }

    private void StopActive()
    {
        if (_active != null)
        {
            _lastTraceId = _active.TraceId;
            _active = null;
        }
    }
}
```

- [ ] **Step 5: Wire limiter override**

Modify `src/VaultGuardian.Core/Ingress/IngressCaptureLimiter.cs`:

```csharp
using VaultGuardian.Core.Ingress.Tracing;
```

Add a field and constructor parameter:

```csharp
private readonly FullTraceManager? _fullTraceManager;

public IngressCaptureLimiter(IngressCaptureLimiterOptions? options = null, FullTraceManager? fullTraceManager = null)
{
    _options = options ?? IngressCaptureLimiterOptions.Default;
    _fullTraceManager = fullTraceManager;
}
```

At the start of `Apply`, after `TrimGlobalWindow`, insert:

```csharp
if (_fullTraceManager?.ShouldBypassSampling(observation.Flow, observation.Timestamp, observation.PacketLength) == true)
{
    ArchivedPackets++;
    _globalArchiveWindow.Enqueue(observation.Timestamp);
    return observation;
}
```

- [ ] **Step 6: Run full trace tests**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressFullTraceManagerTests -v:minimal
```

Expected: full trace manager test passes.

---

### Task 5: MITM Flow Fixture Import

**Files:**
- Create: `src/VaultGuardian.Core/Ingress/Mitm/MitmProxyModels.cs`
- Create: `src/VaultGuardian.Core/Ingress/Mitm/MitmFlowImporter.cs`
- Create: `tests/VaultGuardian.Core.Tests/Fixtures/mitmproxy-flow-httpbin.json`
- Test: `tests/VaultGuardian.Core.Tests/IngressMitmFlowImporterTests.cs`

- [ ] **Step 1: Add fixture**

Create `tests/VaultGuardian.Core.Tests/Fixtures/mitmproxy-flow-httpbin.json`:

```json
{
  "id": "fixture-flow-1",
  "request": {
    "method": "POST",
    "url": "https://telemetry.example.test/collect",
    "headers": {
      "content-type": "application/json"
    },
    "text": "{\"email\":\"person@example.test\",\"event\":\"startup\"}"
  },
  "response": {
    "status_code": 204,
    "headers": {
      "content-type": "text/plain"
    },
    "text": ""
  },
  "timestamp_start": "2026-06-29T07:30:00-04:00"
}
```

- [ ] **Step 2: Write the failing test**

Create `tests/VaultGuardian.Core.Tests/IngressMitmFlowImporterTests.cs`:

```csharp
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressMitmFlowImporterTests
{
    [Fact]
    public async Task ImportAsync_ConvertsMitmJsonFixtureToContentEvent()
    {
        var repoRoot = FindRepoRoot();
        var fixturePath = Path.Combine(repoRoot, "tests", "VaultGuardian.Core.Tests", "Fixtures", "mitmproxy-flow-httpbin.json");
        var importer = new MitmFlowImporter();

        var events = await importer.ImportAsync(fixturePath);

        var contentEvent = Assert.Single(events);
        Assert.Equal(IngressContentSource.MitmRequest, contentEvent.Source);
        Assert.Equal("telemetry.example.test", contentEvent.Host);
        Assert.Equal("POST", contentEvent.HttpMethod);
        Assert.Contains("person@example.test", contentEvent.Text);
    }

    private static string FindRepoRoot()
    {
        var current = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (current != null)
        {
            if (File.Exists(Path.Combine(current.FullName, "VaultGuardian.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate VaultGuardian repository root.");
    }
}
```

- [ ] **Step 3: Run the test to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressMitmFlowImporterTests -v:minimal
```

Expected: compile failure because `MitmFlowImporter` does not exist.

- [ ] **Step 4: Implement MITM models and importer**

Create `src/VaultGuardian.Core/Ingress/Mitm/MitmProxyModels.cs`:

```csharp
using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress.Mitm;

public enum MitmProxyState
{
    Stopped,
    Starting,
    Running,
    Faulted
}

public sealed record MitmProxyStatus(
    MitmProxyState State,
    int ListenPort,
    string? BrowserProfilePath,
    string? LastError,
    int ImportedFlows);

public sealed record MitmProxyOptions(
    string MitmDumpPath,
    int ListenPort,
    string BrowserExecutablePath,
    string BrowserProfilePath)
{
    public static MitmProxyOptions Default(string baseDirectory) => new(
        "mitmdump",
        18080,
        "msedge",
        Path.Combine(baseDirectory, "mitm-browser-profile"));
}

internal sealed record MitmFlowJson(
    string Id,
    MitmMessageJson Request,
    MitmResponseJson? Response,
    DateTimeOffset TimestampStart);

internal sealed record MitmMessageJson(
    string Method,
    string Url,
    Dictionary<string, string> Headers,
    string? Text);

internal sealed record MitmResponseJson(
    [property: JsonPropertyName("status_code")] int? StatusCode,
    Dictionary<string, string> Headers,
    string? Text);
```

Create `src/VaultGuardian.Core/Ingress/Mitm/MitmFlowImporter.cs`:

```csharp
using System.Text.Json;
using System.Text.Json.Serialization;
using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Ingress.Mitm;

public sealed class MitmFlowImporter
{
    public async Task<IReadOnlyList<IngressContentEvent>> ImportAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var stream = File.OpenRead(path);
        var flow = await JsonSerializer.DeserializeAsync(stream, MitmJsonContext.Default.MitmFlowJson, cancellationToken)
            .ConfigureAwait(false);
        if (flow == null)
        {
            return [];
        }

        var eventFlow = new MitmHttpFlowEvent(
            flow.Id,
            flow.TimestampStart,
            flow.Request.Url,
            flow.Request.Method,
            flow.Response?.StatusCode,
            flow.Request.Headers,
            flow.Response?.Headers ?? new Dictionary<string, string>(),
            flow.Request.Text,
            flow.Response?.Text);
        return [IngressContentEvent.FromMitmFlow(eventFlow)];
    }
}

[JsonSerializable(typeof(MitmFlowJson))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.SnakeCaseLower)]
internal sealed partial class MitmJsonContext : JsonSerializerContext;
```

- [ ] **Step 5: Run importer tests**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressMitmFlowImporterTests -v:minimal
```

Expected: importer test passes.

---

### Task 6: Browser-Profile MITM Process Service

**Files:**
- Create: `src/VaultGuardian.Core/Ingress/Mitm/MitmProxyService.cs`
- Create: `src/VaultGuardian.Core/Diagnostics/IManagedProcessLauncher.cs`
- Create: `src/VaultGuardian.Core/Diagnostics/ManagedProcessLauncher.cs`
- Modify: `src/VaultGuardian.Core/AppSettings.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressMitmProxyServiceTests.cs`

- [ ] **Step 1: Write failing tests**

Create `tests/VaultGuardian.Core.Tests/IngressMitmProxyServiceTests.cs`:

```csharp
using VaultGuardian.Core.Diagnostics;
using VaultGuardian.Core.Ingress.Mitm;

namespace VaultGuardian.Core.Tests;

public sealed class IngressMitmProxyServiceTests
{
    [Fact]
    public async Task StartAsync_CreatesBrowserProfileAndBuildsMitmCommand()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-mitm-profile");
        var launcher = new RecordingManagedProcessLauncher();
        var options = new MitmProxyOptions(
            "mitmdump",
            18080,
            "msedge",
            tempRoot);
        var service = new MitmProxyService(launcher, options);

        await service.StartAsync(CancellationToken.None);

        Assert.True(Directory.Exists(tempRoot));
        Assert.Contains(launcher.Commands, command => command.FileName == "mitmdump" && command.Arguments.Contains("--listen-port"));
        Assert.Contains(launcher.Commands, command => command.FileName == "mitmdump" && command.Arguments.Contains("18080"));
        Assert.Contains(launcher.Commands, command => command.FileName == "msedge" && command.Arguments.Any(argument => argument.StartsWith("--user-data-dir=", StringComparison.Ordinal)));
        Assert.Equal(MitmProxyState.Running, service.GetStatus().State);
    }

    private sealed class RecordingManagedProcessLauncher : IManagedProcessLauncher
    {
        public List<(string FileName, IReadOnlyList<string> Arguments)> Commands { get; } = [];

        public IManagedProcess Start(string fileName, IReadOnlyList<string> arguments)
        {
            Commands.Add((fileName, arguments));
            return new RecordingManagedProcess();
        }
    }

    private sealed class RecordingManagedProcess : IManagedProcess
    {
        public int ProcessId => 1234;
        public bool HasExited { get; private set; }
        public void Stop() => HasExited = true;
        public void Dispose() => Stop();
    }
}
```

- [ ] **Step 2: Run the test to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressMitmProxyServiceTests -v:minimal
```

Expected: compile failure because `MitmProxyService`, `IManagedProcessLauncher`, and `IManagedProcess` do not exist.

- [ ] **Step 3: Implement settings**

Modify `src/VaultGuardian.Core/AppSettings.cs`:

```csharp
public bool EnableBrowserProfileMitm { get; set; } = false;
public string MitmDumpPath { get; set; } = "mitmdump";
public int MitmProxyPort { get; set; } = 18080;
public string MitmBrowserExecutablePath { get; set; } = "msedge";
```

- [ ] **Step 4: Implement managed process launcher**

Create `src/VaultGuardian.Core/Diagnostics/IManagedProcessLauncher.cs`:

```csharp
namespace VaultGuardian.Core.Diagnostics;

public interface IManagedProcessLauncher
{
    IManagedProcess Start(string fileName, IReadOnlyList<string> arguments);
}

public interface IManagedProcess : IDisposable
{
    int ProcessId { get; }
    bool HasExited { get; }
    void Stop();
}
```

Create `src/VaultGuardian.Core/Diagnostics/ManagedProcessLauncher.cs`:

```csharp
using System.Diagnostics;

namespace VaultGuardian.Core.Diagnostics;

public sealed class ManagedProcessLauncher : IManagedProcessLauncher
{
    public IManagedProcess Start(string fileName, IReadOnlyList<string> arguments)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        };

        foreach (var argument in arguments)
        {
            psi.ArgumentList.Add(argument);
        }

        var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {fileName}");
        return new ManagedProcess(process);
    }

    private sealed class ManagedProcess : IManagedProcess
    {
        private readonly Process _process;

        public ManagedProcess(Process process)
        {
            _process = process;
        }

        public int ProcessId => _process.Id;
        public bool HasExited => _process.HasExited;

        public void Stop()
        {
            if (_process.HasExited)
            {
                return;
            }

            try
            {
                if (!_process.CloseMainWindow())
                {
                    _process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
            }
        }

        public void Dispose()
        {
            Stop();
            _process.Dispose();
        }
    }
}
```

- [ ] **Step 5: Implement MITM service**

Create `src/VaultGuardian.Core/Ingress/Mitm/MitmProxyService.cs`:

```csharp
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
```

- [ ] **Step 6: Run service tests**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressMitmProxyServiceTests -v:minimal
```

Expected: service test passes and verifies that the proxy/browser commands are launched without waiting for process exit.

---

### Task 7: UI Contract and Rendering

**Files:**
- Modify: `src/VaultGuardian.UI/MainWindow.xaml`
- Modify: `src/VaultGuardian.UI/MainWindow.xaml.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressUiContractTests.cs`

- [ ] **Step 1: Extend UI contract test**

Modify `tests/VaultGuardian.Core.Tests/IngressUiContractTests.cs` to assert:

```csharp
Assert.Contains("IngressTelemetryHitsList", xaml);
Assert.Contains("MitmProxyStatusText", xaml);
Assert.Contains("StartBrowserMitmButton", xaml);
Assert.Contains("StopBrowserMitmButton", xaml);
Assert.Contains("FullTraceStatusText", xaml);
Assert.Contains("OnStartBrowserMitmClick", codeBehind);
Assert.Contains("OnStopBrowserMitmClick", codeBehind);
```

- [ ] **Step 2: Run UI contract test to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressUiContractTests -v:minimal
```

Expected: failure because the XAML names and handlers do not exist.

- [ ] **Step 3: Add UI controls under the Ingress pivot**

Inside `src/VaultGuardian.UI/MainWindow.xaml`, add a third status/details area under the existing Ingress layout using existing brushes:

```xml
<TextBlock x:Name="MitmProxyStatusText"
           Text="Browser MITM: stopped"
           Foreground="{StaticResource SecondaryTextBrush}"
           FontFamily="{StaticResource VaultMonoFontFamily}"
           FontSize="12"
           Margin="0,10,0,0"/>
<TextBlock x:Name="FullTraceStatusText"
           Text="Full trace: idle"
           Foreground="{StaticResource SecondaryTextBrush}"
           FontFamily="{StaticResource VaultMonoFontFamily}"
           FontSize="12"
           Margin="0,6,0,0"/>
<StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
    <Button x:Name="StartBrowserMitmButton"
            Content="Start Browser MITM"
            Click="OnStartBrowserMitmClick"
            Padding="14,8"
            Margin="0,0,10,0"
            Background="Transparent"
            BorderBrush="{StaticResource ConsoleBorderBrush}"
            BorderThickness="1"
            Foreground="{StaticResource SecondaryTextBrush}"/>
    <Button x:Name="StopBrowserMitmButton"
            Content="Stop Browser MITM"
            Click="OnStopBrowserMitmClick"
            Padding="14,8"
            Background="Transparent"
            BorderBrush="{StaticResource ConsoleBorderBrush}"
            BorderThickness="1"
            Foreground="{StaticResource SecondaryTextBrush}"/>
</StackPanel>
<ListView x:Name="IngressTelemetryHitsList"
          Background="{StaticResource ConsoleSurfaceBrush}"
          Foreground="{StaticResource PrimaryTextBrush}"
          BorderBrush="{StaticResource ConsoleBorderBrush}"
          BorderThickness="1"
          Margin="0,10,0,0"/>
```

Place the controls in the existing Ingress details column or below it without nesting cards inside cards.

- [ ] **Step 4: Add handlers**

Modify `src/VaultGuardian.UI/MainWindow.xaml.cs` constructor to accept `MitmProxyService mitmProxyService` after registering it in Task 8. Add:

```csharp
private readonly MitmProxyService _mitmProxyService;

private async void OnStartBrowserMitmClick(object sender, RoutedEventArgs e)
{
    try
    {
        await _mitmProxyService.StartAsync(CancellationToken.None);
        MitmProxyStatusText.Text = FormatMitmStatus(_mitmProxyService.GetStatus());
    }
    catch (Exception ex)
    {
        MitmProxyStatusText.Text = $"Browser MITM: failed - {ex.Message}";
    }
}

private async void OnStopBrowserMitmClick(object sender, RoutedEventArgs e)
{
    await _mitmProxyService.StopAsync(CancellationToken.None);
    MitmProxyStatusText.Text = FormatMitmStatus(_mitmProxyService.GetStatus());
}

private static string FormatMitmStatus(MitmProxyStatus status)
{
    return status.State == MitmProxyState.Running
        ? $"Browser MITM: running on 127.0.0.1:{status.ListenPort}"
        : $"Browser MITM: {status.State}";
}
```

- [ ] **Step 5: Run UI contract test**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressUiContractTests -v:minimal
```

Expected: UI contract test passes.

---

### Task 8: Dependency Injection and Metrics Wiring

**Files:**
- Modify: `src/VaultGuardian.UI/App.xaml.cs`
- Modify: `src/VaultGuardian.Core/Observability/SystemMetrics.cs`
- Modify: `src/VaultGuardian.Core/Observability/LiveMonitorService.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressMetricsContractTests.cs`

- [ ] **Step 1: Write/extend failing metrics contract test**

Modify `tests/VaultGuardian.Core.Tests/IngressMetricsContractTests.cs`:

```csharp
Assert.NotNull(metrics.IngressTelemetryHits);
Assert.NotNull(metrics.FullTrace);
Assert.NotNull(metrics.MitmProxy);
```

Instantiate `AggregateMetrics` with:

```csharp
Array.Empty<PrivacyTelemetryHit>(),
new FullTraceStatus(FullTraceState.Stopped, null, null, null, 0, 0),
new MitmProxyStatus(MitmProxyState.Stopped, 18080, null, null, 0)
```

- [ ] **Step 2: Run metrics test to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressMetricsContractTests -v:minimal
```

Expected: compile failure because `AggregateMetrics` lacks new properties.

- [ ] **Step 3: Extend metrics models**

Modify `src/VaultGuardian.Core/Observability/SystemMetrics.cs`:

```csharp
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;
```

Extend `AggregateMetrics`:

```csharp
public sealed record AggregateMetrics(
    SystemResourceMetrics Resources,
    TrafficStatsSnapshot Traffic,
    IngressTrafficSnapshot Ingress,
    IngressWatcherStatus IngressWatcher,
    IReadOnlyList<PrivacyTelemetryHit> IngressTelemetryHits,
    FullTraceStatus FullTrace,
    MitmProxyStatus MitmProxy);
```

- [ ] **Step 4: Extend live monitor**

Modify `src/VaultGuardian.Core/Observability/LiveMonitorService.cs` constructor to accept nullable stores/services:

```csharp
PrivacyTelemetryStore? privacyTelemetryStore = null,
FullTraceManager? fullTraceManager = null,
MitmProxyService? mitmProxyService = null
```

Return:

```csharp
_privacyTelemetryStore?.ListRecent() ?? [],
_fullTraceManager?.GetStatus() ?? new FullTraceStatus(FullTraceState.Stopped, null, null, null, 0, 0),
_mitmProxyService?.GetStatus() ?? new MitmProxyStatus(MitmProxyState.Stopped, 18080, null, null, 0)
```

- [ ] **Step 5: Register services**

Modify `src/VaultGuardian.UI/App.xaml.cs`:

```csharp
using VaultGuardian.Core.Diagnostics;

services.AddSingleton<PrivacyWatchProfileStore>(_ =>
    new PrivacyWatchProfileStore(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "privacy-watch-profile.json")));
services.AddSingleton<PrivacyTelemetryStore>(_ =>
    new PrivacyTelemetryStore(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "privacy-telemetry-hits.jsonl")));
services.AddSingleton<FullTraceManager>();
services.AddSingleton<MitmFlowImporter>();
services.AddSingleton<IManagedProcessLauncher, ManagedProcessLauncher>();
services.AddSingleton(sp =>
{
    var settings = sp.GetRequiredService<AppSettings>();
    return new MitmProxyOptions(
        settings.MitmDumpPath,
        settings.MitmProxyPort,
        settings.MitmBrowserExecutablePath,
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "mitm-browser-profile"));
});
services.AddSingleton<MitmProxyService>();
```

- [ ] **Step 6: Run metrics test**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressMetricsContractTests -v:minimal
```

Expected: metrics contract passes.

---

### Task 9: End-to-End Fixture Pipeline

**Files:**
- Create: `src/VaultGuardian.Core/Ingress/Telemetry/IngressTelemetryPipeline.cs`
- Test: `tests/VaultGuardian.Core.Tests/IngressTelemetryPipelineTests.cs`

- [ ] **Step 1: Write failing pipeline test**

Create `tests/VaultGuardian.Core.Tests/IngressTelemetryPipelineTests.cs`:

```csharp
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;

namespace VaultGuardian.Core.Tests;

public sealed class IngressTelemetryPipelineTests
{
    [Fact]
    public async Task ProcessMitmFixture_AppendsHitAndTriggersFullTrace()
    {
        var repoRoot = FindRepoRoot();
        var fixturePath = Path.Combine(repoRoot, "tests", "VaultGuardian.Core.Tests", "Fixtures", "mitmproxy-flow-httpbin.json");
        var hitPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-hits.jsonl");
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("email.primary", PrivacySelectorKind.Literal, "person@example.test", Enabled: true)
        ]);
        var pipeline = new IngressTelemetryPipeline(
            new MitmFlowImporter(),
            new PrivacyTelemetryAnalyzer(profile),
            new PrivacyTelemetryStore(hitPath),
            new FullTraceManager(new FullTraceOptions(TimeSpan.FromMinutes(1), 1024 * 1024, 100)));

        var result = await pipeline.ProcessMitmFileAsync(fixturePath);

        Assert.Equal(1, result.EventsProcessed);
        Assert.Equal(1, result.HitsDetected);
        Assert.Equal(FullTraceState.Active, result.FullTrace.State);
    }

    private static string FindRepoRoot()
    {
        var current = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (current != null)
        {
            if (File.Exists(Path.Combine(current.FullName, "VaultGuardian.slnx"))) return current.FullName;
            current = current.Parent;
        }
        throw new InvalidOperationException("Could not locate VaultGuardian repository root.");
    }
}
```

- [ ] **Step 2: Run pipeline test to verify red**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressTelemetryPipelineTests -v:minimal
```

Expected: compile failure because `IngressTelemetryPipeline` does not exist.

- [ ] **Step 3: Implement pipeline**

Create `src/VaultGuardian.Core/Ingress/Telemetry/IngressTelemetryPipeline.cs`:

```csharp
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

    public async Task<IngressTelemetryPipelineResult> ProcessMitmFileAsync(string path, CancellationToken cancellationToken = default)
    {
        var events = await _mitmFlowImporter.ImportAsync(path, cancellationToken).ConfigureAwait(false);
        var allHits = new List<PrivacyTelemetryHit>();

        foreach (var contentEvent in events)
        {
            var analysis = _analyzer.Analyze(contentEvent);
            allHits.AddRange(analysis.Hits);

            foreach (var hit in analysis.Hits)
            {
                _fullTraceManager.Trigger(new FullTraceTrigger(
                    FullTraceScopeKind.BrowserProfile,
                    Flow: null,
                    $"privacy selector `{hit.SelectorLabel}` matched",
                    hit.DetectedAt));
            }
        }

        await _telemetryStore.AppendAsync(allHits, cancellationToken).ConfigureAwait(false);
        return new IngressTelemetryPipelineResult(events.Count, allHits.Count, _fullTraceManager.GetStatus());
    }
}
```

- [ ] **Step 4: Run pipeline test**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 --filter IngressTelemetryPipelineTests -v:minimal
```

Expected: pipeline test passes.

---

### Task 10: Full Verification and Manual UI Check

**Files:**
- No new files unless preceding tasks reveal compile gaps.

- [ ] **Step 1: Run full test suite**

Run:

```powershell
dotnet test tests\VaultGuardian.Core.Tests\VaultGuardian.Core.Tests.csproj -p:Platform=x64 -v:minimal
```

Expected: all tests pass. Any failures are fixed before continuing.

- [ ] **Step 2: Build solution**

Run:

```powershell
dotnet build VaultGuardian.slnx -v:minimal
```

Expected: build succeeds. Existing Windows-only CA1416 warnings are acceptable only if the build exits 0; new compile warnings should be reviewed.

- [ ] **Step 3: Launch UI without live MITM**

Run:

```powershell
$base = Join-Path (Get-Location) 'src\VaultGuardian.UI\bin\x64\Debug\net10.0-windows10.0.19041.0\win-x64'
Remove-Item -LiteralPath (Join-Path $base 'settings.json') -ErrorAction SilentlyContinue
$exe = Join-Path $base 'VaultGuardian.UI.exe'
$p = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 5
$p.Refresh()
[pscustomobject]@{ Id=$p.Id; HasExited=$p.HasExited; MainWindowTitle=$p.MainWindowTitle; Responding=if ($p.HasExited) { $null } else { $p.Responding } }
```

Expected: process remains alive and responding.

- [ ] **Step 4: UI Automation check**

Use the existing UI Automation pattern from prior verification to select `Ingress` and verify these names exist:

```powershell
Ingress
IngressTelemetryHitsList
MitmProxyStatusText
FullTraceStatusText
Start Browser MITM
Stop Browser MITM
```

Expected: all names are present and the process remains responding.

- [ ] **Step 5: Do not run live network/proxy verification without explicit approval**

Before launching mitmproxy against a real browser profile, pause and ask:

```text
I can run one live local MITM browser-profile check. Target: local mitmproxy listener on 127.0.0.1:18080 and one browser profile launch. Request count: no scripted HTTP requests; manual browser launch only. Stop condition: app crash, mitmproxy failure, or after status renders. Approve?
```

Expected: no live MITM/browser check is run without user approval.

---

## Self-Review Notes

- Spec coverage: passive metadata, browser-profile MITM, key-log support as later mode, privacy selectors, full trace triggers, local storage, UI, and tests are represented.
- Scope split: this first implementation does not add key-log decryption beyond the normalized event model. That is intentional because browser-profile MITM is the approved first active decryption path.
- Safety: no system-wide transparent MITM, no certificate pinning bypass, no automated request loops, no raw selector values in logs or summaries.
- Type consistency: model names introduced in early tasks are reused by later tasks: `IngressContentEvent`, `PrivacyTelemetryHit`, `FullTraceStatus`, `MitmProxyStatus`.
