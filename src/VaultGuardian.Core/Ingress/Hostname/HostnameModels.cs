namespace VaultGuardian.Core.Ingress.Hostname;

/// <summary>How a hostname was observed for a remote address, without decrypting payloads.</summary>
public enum HostnameSource
{
    /// <summary>Learned from a DNS answer record (A/AAAA) seen on the wire.</summary>
    Dns,

    /// <summary>Learned from the Server Name Indication in a TLS ClientHello.</summary>
    Sni
}

/// <summary>A resolved remote address → hostname mapping with provenance and expiry.</summary>
public sealed record HostnameResolution(
    string Address,
    string Hostname,
    HostnameSource Source,
    DateTimeOffset ResolvedAt,
    DateTimeOffset ExpiresAt,
    string? Ja4 = null);

/// <summary>A single address record parsed out of a DNS answer section.</summary>
public sealed record DnsAddressRecord(
    string Hostname,
    string Address,
    int TtlSeconds);
