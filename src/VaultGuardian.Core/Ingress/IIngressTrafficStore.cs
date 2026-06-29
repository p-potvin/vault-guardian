namespace VaultGuardian.Core.Ingress;

public interface IIngressTrafficStore
{
    Task AppendAsync(IngressPacketObservation observation, CancellationToken cancellationToken = default);

    IngressTrafficSnapshot GetSnapshot();

    IReadOnlyList<IngressPacketObservation> ListFlowPackets(IngressFlowKey flowKey);

    Task ClearAsync(CancellationToken cancellationToken = default);

    Task<string> ExportFlowAsync(
        IngressFlowKey flowKey,
        string exportDirectory,
        CancellationToken cancellationToken = default);
}
