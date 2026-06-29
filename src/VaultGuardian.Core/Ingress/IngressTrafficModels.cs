using System.Text.Json.Serialization;

namespace VaultGuardian.Core.Ingress;

public enum IngressContentClassification
{
    Unknown,
    Plaintext,
    Encrypted,
    Binary,
    LargeMedia
}

public enum IngressWatcherState
{
    Stopped,
    Starting,
    Running,
    Stopping,
    Faulted
}

public sealed record IngressWatcherStatus(
    IngressWatcherState State,
    DateTimeOffset? StartedAt,
    DateTimeOffset? StoppedAt,
    string? LastError,
    string? Warning,
    long ArchivedPackets = 0,
    long SkippedPackets = 0,
    long SuppressedPayloadSamples = 0)
{
    public static IngressWatcherStatus Stopped { get; } =
        new(IngressWatcherState.Stopped, null, null, null, null);

    public bool IsRunning => State == IngressWatcherState.Running;
}

public sealed record IngressFlowKey(
    string RemoteAddress,
    int RemotePort,
    string LocalAddress,
    int LocalPort,
    TrafficProtocol Protocol,
    int ProcessId,
    string ProcessName,
    string ProcessPath);

public sealed record PayloadSample(
    DateTimeOffset CapturedAt,
    int OriginalLength,
    byte[] StoredBytes,
    IngressContentClassification Classification,
    bool BodyCaptureSuppressed,
    string Reason,
    string? TextPreview);

public sealed record IngressPacketObservation(
    IngressFlowKey Flow,
    DateTimeOffset Timestamp,
    int PacketLength,
    int PayloadLength,
    PayloadSample? PayloadSample);

public sealed record IngressFlowSummary(
    IngressFlowKey Key,
    int PacketCount,
    long TotalBytes,
    long TotalPayloadBytes,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    IReadOnlyList<PayloadSample> RecentSamples);

public sealed record IngressSourceSummary(
    string RemoteAddress,
    int PacketCount,
    int FlowCount,
    long TotalBytes,
    long TotalPayloadBytes,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    IReadOnlyList<IngressFlowSummary> Flows);

public sealed record IngressTrafficSnapshot(
    long TotalPackets,
    long TotalBytes,
    long TotalPayloadBytes,
    IReadOnlyList<IngressSourceSummary> Sources)
{
    public static IngressTrafficSnapshot Empty { get; } = new(0, 0, 0, []);
}

[JsonSerializable(typeof(IngressPacketObservation))]
[JsonSerializable(typeof(List<IngressPacketObservation>))]
[JsonSourceGenerationOptions(WriteIndented = true, Converters = [typeof(JsonStringEnumConverter<TrafficProtocol>), typeof(JsonStringEnumConverter<IngressContentClassification>)])]
internal sealed partial class IngressTrafficJsonContext : JsonSerializerContext;
