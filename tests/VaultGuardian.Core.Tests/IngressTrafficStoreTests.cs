using System.Text;
using VaultGuardian.Core;
using VaultGuardian.Core.Ingress;

namespace VaultGuardian.Core.Tests;

public sealed class IngressTrafficStoreTests
{
    [Fact]
    public async Task AppendAsync_GroupsPacketsByRemoteSourceAndFlow()
    {
        var archivePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-ingress.json");
        await using var store = new IngressTrafficStore(archivePath);
        var firstFlow = new IngressFlowKey(
            RemoteAddress: "203.0.113.10",
            RemotePort: 443,
            LocalAddress: "192.168.1.25",
            LocalPort: 51000,
            Protocol: TrafficProtocol.Tcp,
            ProcessId: 42,
            ProcessName: "browser",
            ProcessPath: @"C:\Apps\browser.exe");
        var secondFlow = firstFlow with { LocalPort = 51001 };

        await store.AppendAsync(Packet(firstFlow, payloadLength: 128));
        await store.AppendAsync(Packet(firstFlow, payloadLength: 256));
        await store.AppendAsync(Packet(secondFlow, payloadLength: 64));

        var snapshot = store.GetSnapshot();

        var source = Assert.Single(snapshot.Sources);
        Assert.Equal("203.0.113.10", source.RemoteAddress);
        Assert.Equal(3, source.PacketCount);
        Assert.Equal(448, source.TotalPayloadBytes);
        Assert.Equal(2, source.Flows.Count);
        Assert.Contains(source.Flows, flow => flow.Key.LocalPort == 51000 && flow.PacketCount == 2);
        Assert.Contains(source.Flows, flow => flow.Key.LocalPort == 51001 && flow.PacketCount == 1);
    }

    [Fact]
    public void PayloadClassifier_StoresPlaintextButSuppressesKnownLargeMediaBody()
    {
        var textPayload = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello vault");
        var mediaPayload = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\n\r\n" + new string('x', 4096));

        var textSample = IngressPayloadClassifier.ClassifyAndSample(textPayload, DateTimeOffset.UtcNow);
        var mediaSample = IngressPayloadClassifier.ClassifyAndSample(mediaPayload, DateTimeOffset.UtcNow, fileName: "clip.mp4");

        Assert.Equal(IngressContentClassification.Plaintext, textSample.Classification);
        Assert.False(textSample.BodyCaptureSuppressed);
        Assert.Equal(textPayload.Length, textSample.StoredBytes.Length);
        Assert.Contains("hello vault", textSample.TextPreview);

        Assert.Equal(IngressContentClassification.LargeMedia, mediaSample.Classification);
        Assert.True(mediaSample.BodyCaptureSuppressed);
        Assert.True(mediaSample.StoredBytes.Length <= IngressPayloadClassifier.SignatureBytesToKeep);
        Assert.Contains("large media", mediaSample.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PayloadClassifier_KeepsBoundedEncryptedSample()
    {
        var tlsPayload = new byte[8192];
        tlsPayload[0] = 0x16;
        tlsPayload[1] = 0x03;
        tlsPayload[2] = 0x03;

        var sample = IngressPayloadClassifier.ClassifyAndSample(tlsPayload, DateTimeOffset.UtcNow);

        Assert.Equal(IngressContentClassification.Encrypted, sample.Classification);
        Assert.False(sample.BodyCaptureSuppressed);
        Assert.Equal(IngressPayloadClassifier.DefaultMaxStoredBytes, sample.StoredBytes.Length);
        Assert.Null(sample.TextPreview);
    }

    [Fact]
    public async Task ArchivePersistsUntilExplicitClear()
    {
        var archivePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-ingress.json");
        var flow = new IngressFlowKey(
            RemoteAddress: "198.51.100.8",
            RemotePort: 80,
            LocalAddress: "192.168.1.25",
            LocalPort: 52000,
            Protocol: TrafficProtocol.Tcp,
            ProcessId: 77,
            ProcessName: "downloader",
            ProcessPath: @"C:\Apps\downloader.exe");

        await using (var store = new IngressTrafficStore(archivePath))
        {
            await store.AppendAsync(Packet(flow, payloadLength: 512));
        }

        await using (var reloaded = new IngressTrafficStore(archivePath))
        {
            Assert.Equal(1, reloaded.GetSnapshot().TotalPackets);
            await reloaded.ClearAsync();
            Assert.Equal(0, reloaded.GetSnapshot().TotalPackets);
        }

        await using (var cleared = new IngressTrafficStore(archivePath))
        {
            Assert.Equal(0, cleared.GetSnapshot().TotalPackets);
        }
    }

    [Fact]
    public async Task AppendAsync_WritesAppendOnlyJsonLines()
    {
        var archivePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-ingress.jsonl");
        var flow = new IngressFlowKey(
            RemoteAddress: "203.0.113.80",
            RemotePort: 443,
            LocalAddress: "192.168.1.25",
            LocalPort: 54000,
            Protocol: TrafficProtocol.Tcp,
            ProcessId: 88,
            ProcessName: "browser",
            ProcessPath: @"C:\Apps\browser.exe");

        await using var store = new IngressTrafficStore(archivePath);
        await store.AppendAsync(Packet(flow, payloadLength: 16));
        await store.AppendAsync(Packet(flow, payloadLength: 32));

        var lines = await File.ReadAllLinesAsync(archivePath);

        Assert.Equal(2, lines.Length);
        Assert.All(lines, line => Assert.StartsWith("{", line.TrimStart()));
    }

    [Fact]
    public async Task ExportFlowAsync_WritesSelectedFlowPackets()
    {
        var archivePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-ingress.jsonl");
        var exportDirectory = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-ingress-export");
        var flow = new IngressFlowKey(
            RemoteAddress: "203.0.113.90",
            RemotePort: 443,
            LocalAddress: "192.168.1.25",
            LocalPort: 55000,
            Protocol: TrafficProtocol.Tcp,
            ProcessId: 99,
            ProcessName: "browser",
            ProcessPath: @"C:\Apps\browser.exe");

        await using var store = new IngressTrafficStore(archivePath);
        await store.AppendAsync(Packet(flow, payloadLength: 64));

        var exportPath = await store.ExportFlowAsync(flow, exportDirectory);
        var exportedJson = await File.ReadAllTextAsync(exportPath);

        Assert.True(new FileInfo(exportPath).Length > 0);
        Assert.Contains("203.0.113.90", exportedJson);
        Assert.Contains("browser", exportedJson);
    }

    [Fact]
    public async Task AppendAsync_RejectsArchiveWhenMaximumSizeWouldBeExceeded()
    {
        var archivePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-ingress.jsonl");
        var flow = new IngressFlowKey(
            RemoteAddress: "203.0.113.100",
            RemotePort: 443,
            LocalAddress: "192.168.1.25",
            LocalPort: 56000,
            Protocol: TrafficProtocol.Tcp,
            ProcessId: 100,
            ProcessName: "browser",
            ProcessPath: @"C:\Apps\browser.exe");

        await using var store = new IngressTrafficStore(
            archivePath,
            new IngressTrafficStoreOptions(MaxArchiveBytes: 1, MinimumFreeDiskBytes: 0));

        var error = await Assert.ThrowsAsync<IngressArchiveSafetyException>(
            () => store.AppendAsync(Packet(flow, payloadLength: 64)));

        Assert.Contains("archive", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(archivePath));
    }

    private static IngressPacketObservation Packet(IngressFlowKey flow, int payloadLength)
    {
        var payload = Encoding.ASCII.GetBytes("payload");
        var sample = IngressPayloadClassifier.ClassifyAndSample(payload, DateTimeOffset.UtcNow);
        return new IngressPacketObservation(
            Flow: flow,
            Timestamp: DateTimeOffset.UtcNow,
            PacketLength: payloadLength + 40,
            PayloadLength: payloadLength,
            PayloadSample: sample);
    }
}
