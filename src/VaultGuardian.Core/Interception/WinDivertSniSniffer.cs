using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using VaultGuardian.Core.Ingress.Hostname;
using WindivertDotnet;

namespace VaultGuardian.Core.Interception;

/// <summary>
/// Sniffs outbound TLS ClientHello packets (destination port 443) in passive
/// RecvOnly mode and feeds their SNI into the <see cref="HostnameResolutionStore"/>.
/// It never blocks or modifies traffic — it only reads, so egress policy stays
/// the interceptor's job. Combined with inbound DNS learning, this gives the
/// resolver live hostname coverage without terminating TLS.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WinDivertSniSniffer : IHostnameSniffer
{
    // TLS record content type 0x16 = handshake; the SNI parser validates the rest.
    private const byte TlsHandshakeContentType = 0x16;

    private readonly HostnameResolutionStore _hostnameStore;
    private readonly ILogger<WinDivertSniSniffer> _logger;
    private WinDivert? _divert;
    private CancellationTokenSource? _cts;
    private Task? _runTask;

    public WinDivertSniSniffer(
        HostnameResolutionStore hostnameStore,
        ILogger<WinDivertSniSniffer> logger)
    {
        _hostnameStore = hostnameStore;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_cts != null)
        {
            return Task.CompletedTask;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        // Only the ClientHello matters, and it rides in the first outbound
        // segment of a TLS connection, so scope the filter tightly to HTTPS.
        _divert = new WinDivert(
            "outbound and tcp and tcp.DstPort == 443",
            WinDivertLayer.Network,
            0,
            WinDivertFlag.Sniff | WinDivertFlag.RecvOnly);
        _runTask = Task.Run(() => RunLoopAsync(_cts.Token), _cts.Token);
        return Task.CompletedTask;
    }

    private async Task RunLoopAsync(CancellationToken cancellationToken)
    {
        var packet = new WinDivertPacket(65535);
        var address = new WinDivertAddress();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var bytesRecv = _divert?.Recv(packet, address, cancellationToken) ?? 0;
                if (bytesRecv <= 0)
                {
                    continue;
                }

                Inspect(packet);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "SNI sniffer skipped an outbound packet");
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private unsafe void Inspect(WinDivertPacket packet)
    {
        var parseResult = packet.GetParseResult();
        if (parseResult.IPV4Header == null ||
            parseResult.TcpHeader == null ||
            parseResult.DataLength <= 0)
        {
            return;
        }

        var data = parseResult.DataSpan;
        if (data.Length == 0 || data[0] != TlsHandshakeContentType)
        {
            return;
        }

        var destinationAddress = parseResult.IPV4Header->DstAddr.ToString();
        _hostnameStore.IngestTlsClientHello(destinationAddress, data);
    }

    public async Task StopAsync()
    {
        if (_cts == null)
        {
            return;
        }

        _logger.LogInformation("SNI sniffer stopping");
        await _cts.CancelAsync().ConfigureAwait(false);
        if (_runTask != null)
        {
            try
            {
                await _runTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        _divert?.Dispose();
        _cts.Dispose();
        _divert = null;
        _cts = null;
        _runTask = null;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
    }
}
