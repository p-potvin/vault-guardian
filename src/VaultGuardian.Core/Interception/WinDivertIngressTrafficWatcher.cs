using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Hostname;
using VaultGuardian.Core.Observability;
using WindivertDotnet;

namespace VaultGuardian.Core.Interception;

[SupportedOSPlatform("windows")]
public sealed class WinDivertIngressTrafficWatcher : IIngressTrafficWatcher
{
    private const int DnsPort = 53;

    private readonly IIngressTrafficStore _store;
    private readonly ILogger<WinDivertIngressTrafficWatcher> _logger;
    private readonly TrafficStats? _trafficStats;
    private readonly HostnameResolutionStore? _hostnameStore;
    private readonly IngressFlowCorrelator _correlator = new();
    private readonly IngressCaptureLimiter _captureLimiter;
    private WinDivert? _flowDivert;
    private WinDivert? _networkDivert;
    private CancellationTokenSource? _cts;
    private Task? _flowTask;
    private Task? _networkTask;
    private readonly object _statusLock = new();
    private IngressWatcherStatus _status = IngressWatcherStatus.Stopped;

    public WinDivertIngressTrafficWatcher(
        IIngressTrafficStore store,
        ILogger<WinDivertIngressTrafficWatcher> logger,
        TrafficStats? trafficStats = null,
        IngressCaptureLimiter? captureLimiter = null,
        HostnameResolutionStore? hostnameStore = null)
    {
        _store = store;
        _logger = logger;
        _trafficStats = trafficStats;
        _captureLimiter = captureLimiter ?? new IngressCaptureLimiter();
        _hostnameStore = hostnameStore;
    }

    public event EventHandler<IngressPacketObservation>? ObservationReceived;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_cts != null)
        {
            return Task.CompletedTask;
        }

        SetStatus(new IngressWatcherStatus(IngressWatcherState.Starting, null, null, null, null));
        try
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _flowDivert = new WinDivert("true", WinDivertLayer.Flow, 0, WinDivertFlag.Sniff | WinDivertFlag.RecvOnly);
            _networkDivert = new WinDivert("inbound and (tcp or udp)", WinDivertLayer.Network, 0, WinDivertFlag.Sniff | WinDivertFlag.RecvOnly);
            _flowTask = Task.Run(() => RunFlowLoopAsync(_cts.Token), _cts.Token);
            _networkTask = Task.Run(() => RunNetworkLoopAsync(_cts.Token), _cts.Token);
            SetStatus(new IngressWatcherStatus(IngressWatcherState.Running, DateTimeOffset.UtcNow, null, null, null));
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            SetStatus(new IngressWatcherStatus(IngressWatcherState.Faulted, null, DateTimeOffset.UtcNow, ex.Message, null));
            _flowDivert?.Dispose();
            _networkDivert?.Dispose();
            _cts?.Dispose();
            _flowDivert = null;
            _networkDivert = null;
            _cts = null;
            throw;
        }
    }

    public async Task StopAsync()
    {
        if (_cts == null)
        {
            return;
        }

        var previousStatus = GetStatus();
        SetStatus(previousStatus with { State = IngressWatcherState.Stopping });
        await _cts.CancelAsync().ConfigureAwait(false);
        await AwaitLoopAsync(_flowTask).ConfigureAwait(false);
        await AwaitLoopAsync(_networkTask).ConfigureAwait(false);
        _flowDivert?.Dispose();
        _networkDivert?.Dispose();
        _cts.Dispose();
        _flowDivert = null;
        _networkDivert = null;
        _flowTask = null;
        _networkTask = null;
        _cts = null;
        SetStatus(previousStatus with
        {
            State = IngressWatcherState.Stopped,
            StoppedAt = DateTimeOffset.UtcNow
        });
    }

    public IngressTrafficSnapshot GetSnapshot() => _store.GetSnapshot();

    public IngressWatcherStatus GetStatus()
    {
        lock (_statusLock)
        {
            return _status;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
    }

    private unsafe Task RunFlowLoopAsync(CancellationToken cancellationToken)
    {
        var packet = new WinDivertPacket(0);
        var address = new WinDivertAddress();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                _flowDivert?.Recv(packet, address, cancellationToken);
                var flow = address.Flow;
                if (flow == null)
                {
                    continue;
                }

                var protocol = flow->Protocol switch
                {
                    System.Net.Sockets.ProtocolType.Tcp => TrafficProtocol.Tcp,
                    System.Net.Sockets.ProtocolType.Udp => TrafficProtocol.Udp,
                    _ => TrafficProtocol.Any
                };

                var process = ResolveProcess(flow->ProcessId);
                _correlator.ObserveFlow(new IngressFlowKey(
                    RemoteAddress: flow->RemoteAddr.ToString(),
                    RemotePort: flow->RemotePort,
                    LocalAddress: flow->LocalAddr.ToString(),
                    LocalPort: flow->LocalPort,
                    Protocol: protocol,
                    ProcessId: flow->ProcessId,
                    ProcessName: process.Name,
                    ProcessPath: process.Path));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Ingress flow correlation loop skipped an event");
            }
        }

        return Task.CompletedTask;
    }

    private async Task RunNetworkLoopAsync(CancellationToken cancellationToken)
    {
        var packet = new WinDivertPacket(65535);
        var address = new WinDivertAddress();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var bytesRecv = _networkDivert?.Recv(packet, address, cancellationToken) ?? 0;
                if (bytesRecv <= 0)
                {
                    continue;
                }

                var parseResult = packet.GetParseResult();
                if (!IsSupportedInboundPacket(parseResult))
                {
                    continue;
                }

                var packetInfo = ReadInboundPacketInfo(parseResult);

                var flow = _correlator.Resolve(
                               packetInfo.RemoteAddress,
                               packetInfo.RemotePort,
                               packetInfo.LocalAddress,
                               packetInfo.LocalPort,
                               packetInfo.Protocol) ??
                           new IngressFlowKey(
                               packetInfo.RemoteAddress,
                               packetInfo.RemotePort,
                               packetInfo.LocalAddress,
                               packetInfo.LocalPort,
                               packetInfo.Protocol,
                               ProcessId: 0,
                               ProcessName: "Unknown",
                               ProcessPath: "Unknown");

                var payload = parseResult.DataLength > 0 ? parseResult.DataSpan.ToArray() : [];

                // Passive hostname learning: inbound UDP from port 53 is a DNS
                // response. Feed it to the resolver so egress rules can match host.
                if (_hostnameStore != null &&
                    packetInfo.Protocol == TrafficProtocol.Udp &&
                    packetInfo.RemotePort == DnsPort &&
                    payload.Length > 0)
                {
                    try
                    {
                        _hostnameStore.IngestDnsResponse(payload);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to ingest a DNS response for hostname correlation");
                    }
                }

                var sample = payload.Length > 0
                    ? IngressPayloadClassifier.ClassifyAndSample(payload, DateTimeOffset.UtcNow)
                    : null;

                var observation = new IngressPacketObservation(
                    flow,
                    DateTimeOffset.UtcNow,
                    bytesRecv,
                    parseResult.DataLength,
                    sample);

                _trafficStats?.IncrementAllowed(bytesRecv, isOutbound: false);

                var limitedObservation = _captureLimiter.Apply(observation);
                UpdateCaptureCounters();
                if (limitedObservation == null)
                {
                    continue;
                }

                await _store.AppendAsync(limitedObservation, cancellationToken).ConfigureAwait(false);
                ObservationReceived?.Invoke(this, limitedObservation);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (IngressArchiveSafetyException ex)
            {
                SetStatus(GetStatus() with
                {
                    State = IngressWatcherState.Faulted,
                    StoppedAt = DateTimeOffset.UtcNow,
                    LastError = ex.Message,
                    Warning = "Ingress capture stopped before the archive could make disk usage unsafe."
                });
                _logger.LogWarning(ex, "Ingress packet watcher stopped because archive safety limits were reached");
                await (_cts?.CancelAsync() ?? Task.CompletedTask).ConfigureAwait(false);
                break;
            }
            catch (Exception ex)
            {
                SetStatus(GetStatus() with { LastError = ex.Message });
                _logger.LogError(ex, "Ingress packet watcher skipped an inbound packet");
            }
        }
    }

    private void SetStatus(IngressWatcherStatus status)
    {
        lock (_statusLock)
        {
            _status = status;
        }
    }

    private void UpdateCaptureCounters()
    {
        lock (_statusLock)
        {
            var warning = _captureLimiter.SkippedPackets > 0 || _captureLimiter.SuppressedPayloadSamples > 0
                ? "Ingress archive sampling is active to keep packet capture bounded."
                : _status.Warning;

            _status = _status with
            {
                Warning = warning,
                ArchivedPackets = _captureLimiter.ArchivedPackets,
                SkippedPackets = _captureLimiter.SkippedPackets,
                SuppressedPayloadSamples = _captureLimiter.SuppressedPayloadSamples
            };
        }
    }

    private static async Task AwaitLoopAsync(Task? task)
    {
        if (task == null)
        {
            return;
        }

        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static unsafe InboundPacketInfo ReadInboundPacketInfo(WinDivertParseResult parseResult)
    {
        var protocol = parseResult.TcpHeader != null ? TrafficProtocol.Tcp : TrafficProtocol.Udp;
        return new InboundPacketInfo(
            RemoteAddress: parseResult.IPV4Header->SrcAddr.ToString(),
            RemotePort: parseResult.TcpHeader != null
                ? (int)parseResult.TcpHeader->SrcPort
                : (int)parseResult.UdpHeader->SrcPort,
            LocalAddress: parseResult.IPV4Header->DstAddr.ToString(),
            LocalPort: parseResult.TcpHeader != null
                ? (int)parseResult.TcpHeader->DstPort
                : (int)parseResult.UdpHeader->DstPort,
            Protocol: protocol);
    }

    private static unsafe bool IsSupportedInboundPacket(WinDivertParseResult parseResult)
    {
        return parseResult.IPV4Header != null &&
               (parseResult.TcpHeader != null || parseResult.UdpHeader != null);
    }

    private static (string Name, string Path) ResolveProcess(int processId)
    {
        if (processId <= 0)
        {
            return ("Unknown", "Unknown");
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            return (process.ProcessName, process.MainModule?.FileName ?? "Unknown");
        }
        catch
        {
            return ("Unknown", "Unknown");
        }
    }

    private sealed record InboundPacketInfo(
        string RemoteAddress,
        int RemotePort,
        string LocalAddress,
        int LocalPort,
        TrafficProtocol Protocol);
}
