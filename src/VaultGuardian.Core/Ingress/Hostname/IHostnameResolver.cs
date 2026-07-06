namespace VaultGuardian.Core.Ingress.Hostname;

/// <summary>
/// Read side of the passive hostname map. The interceptor consults this to
/// annotate a <see cref="TrafficObservation"/> with a hostname so rules can be
/// evaluated on host without terminating TLS (the non-MITM policy path).
/// </summary>
public interface IHostnameResolver
{
    /// <summary>
    /// Returns the most recently observed, non-expired hostname for a remote
    /// address, or <c>false</c> when nothing is known.
    /// </summary>
    bool TryResolve(string address, out string hostname);
}
