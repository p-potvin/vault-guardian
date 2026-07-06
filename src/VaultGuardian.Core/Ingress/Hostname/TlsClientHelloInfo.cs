namespace VaultGuardian.Core.Ingress.Hostname;

/// <summary>
/// Structured view of a parsed TLS ClientHello, carrying everything needed to
/// compute a JA4 client fingerprint plus the SNI. Lists preserve wire order and
/// keep GREASE values in place — the JA4 calculator strips GREASE itself.
/// </summary>
public sealed record TlsClientHelloInfo(
    string TlsVersion,
    bool HasServerName,
    string ServerName,
    IReadOnlyList<ushort> CipherSuites,
    IReadOnlyList<ushort> Extensions,
    string? FirstAlpn,
    IReadOnlyList<ushort> SignatureAlgorithms);
