namespace VaultGuardian.Core.Ingress;

public sealed class IngressFlowCorrelator
{
    private readonly object _lock = new();
    private readonly Dictionary<EndpointTuple, IngressFlowKey> _flows = new();

    public void ObserveFlow(IngressFlowKey flow)
    {
        var key = new EndpointTuple(
            flow.RemoteAddress,
            flow.RemotePort,
            flow.LocalAddress,
            flow.LocalPort,
            flow.Protocol);

        lock (_lock)
        {
            _flows[key] = flow;
        }
    }

    public IngressFlowKey? Resolve(
        string RemoteAddress,
        int RemotePort,
        string LocalAddress,
        int LocalPort,
        TrafficProtocol Protocol)
    {
        var key = new EndpointTuple(RemoteAddress, RemotePort, LocalAddress, LocalPort, Protocol);
        lock (_lock)
        {
            return _flows.TryGetValue(key, out var flow) ? flow : null;
        }
    }

    private sealed record EndpointTuple(
        string RemoteAddress,
        int RemotePort,
        string LocalAddress,
        int LocalPort,
        TrafficProtocol Protocol);
}
