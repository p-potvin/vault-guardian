namespace VaultGuardian.Core.Ingress;

public interface IIngressTrafficWatcher : IAsyncDisposable
{
    event EventHandler<IngressPacketObservation>? ObservationReceived;

    Task StartAsync(CancellationToken cancellationToken);

    Task StopAsync();

    IngressTrafficSnapshot GetSnapshot();

    IngressWatcherStatus GetStatus();
}
