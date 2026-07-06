namespace VaultGuardian.Core.Interception;

/// <summary>
/// Passive capture that observes outbound TLS ClientHello traffic and feeds the
/// Server Name Indication into the hostname resolver, completing the live
/// non-MITM hostname path alongside inbound DNS learning.
/// </summary>
public interface IHostnameSniffer : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync();
}
