using System.Security.Cryptography;
using System.Text;
using VaultGuardian.Core.Ingress.Hostname;

namespace VaultGuardian.Core.Tests;

public sealed class Ja4Tests
{
    [Fact]
    public void TryParse_ExtractsVersionSniAlpnAndSignatureAlgorithms()
    {
        Assert.True(TlsClientHelloParser.TryParse(BuildRichClientHello(), out var info));

        Assert.Equal("13", info.TlsVersion); // negotiated via supported_versions, overriding legacy 1.2
        Assert.True(info.HasServerName);
        Assert.Equal("example.com", info.ServerName);
        Assert.Equal("h2", info.FirstAlpn);
        Assert.Equal(new ushort[] { 0x0403, 0x0804 }, info.SignatureAlgorithms);
    }

    [Fact]
    public void Compute_ProducesExpectedFingerprint_WithGreaseStripped()
    {
        Assert.True(TlsClientHelloParser.TryParse(BuildRichClientHello(), out var info));

        var ja4 = Ja4Calculator.Compute(info);

        // a = t (tcp) + 13 (TLS 1.3) + d (SNI present) + 02 ciphers + 04 extensions + h2 (ALPN)
        var expectedB = Hash12("1301,1302");                 // sorted non-GREASE ciphers
        var expectedC = Hash12("000d,002b_0403,0804");       // sorted exts (minus SNI/ALPN) _ sig algs
        Assert.Equal($"t13d0204h2_{expectedB}_{expectedC}", ja4);
    }

    [Fact]
    public void Store_RecordsJa4AlongsideSni()
    {
        var store = new HostnameResolutionStore();

        Assert.True(store.IngestTlsClientHello("203.0.113.50", BuildRichClientHello()));

        var entry = Assert.Single(store.Snapshot());
        Assert.Equal("example.com", entry.Hostname);
        Assert.StartsWith("t13d0204h2_", entry.Ja4);
    }

    [Fact]
    public void Resolver_ReturnsJa4AlongsideHostname()
    {
        var store = new HostnameResolutionStore();
        store.IngestTlsClientHello("203.0.113.50", BuildRichClientHello());

        Assert.True(store.TryResolve("203.0.113.50", out var host, out var ja4));
        Assert.Equal("example.com", host);
        Assert.StartsWith("t13d0204h2_", ja4);
    }

    private static byte[] BuildRichClientHello()
    {
        var extensions = new List<byte>();

        var sni = Encoding.ASCII.GetBytes("example.com");
        var sniEntry = new List<byte> { 0x00 };
        sniEntry.AddRange(Be16((ushort)sni.Length));
        sniEntry.AddRange(sni);
        var sniList = new List<byte>();
        sniList.AddRange(Be16((ushort)sniEntry.Count));
        sniList.AddRange(sniEntry);
        extensions.AddRange(Extension(0x0000, sniList));

        // supported_versions: GREASE 0x0a0a, TLS 1.3, TLS 1.2
        var versions = new List<byte> { 6, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03 };
        extensions.AddRange(Extension(0x002b, versions));

        // ALPN: h2
        var alpn = new List<byte>();
        alpn.AddRange(Be16(3));
        alpn.Add(0x02);
        alpn.AddRange(Encoding.ASCII.GetBytes("h2"));
        extensions.AddRange(Extension(0x0010, alpn));

        // signature_algorithms: 0x0403, 0x0804
        var sigAlgs = new List<byte>();
        sigAlgs.AddRange(Be16(4));
        sigAlgs.AddRange(new byte[] { 0x04, 0x03, 0x08, 0x04 });
        extensions.AddRange(Extension(0x000d, sigAlgs));

        // GREASE extension (must be stripped)
        extensions.AddRange(Extension(0x1a1a, []));

        var body = new List<byte> { 0x03, 0x03 }; // legacy version 1.2
        body.AddRange(new byte[32]);              // random
        body.Add(0x00);                           // session_id length

        // cipher suites: GREASE 0x0a0a, 0x1301, 0x1302
        var ciphers = new byte[] { 0x0a, 0x0a, 0x13, 0x01, 0x13, 0x02 };
        body.AddRange(Be16((ushort)ciphers.Length));
        body.AddRange(ciphers);

        body.Add(0x01);
        body.Add(0x00);                           // one compression method (null)
        body.AddRange(Be16((ushort)extensions.Count));
        body.AddRange(extensions);

        var handshake = new List<byte> { 0x01 };
        handshake.AddRange(Be24(body.Count));
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01 };
        record.AddRange(Be16((ushort)handshake.Count));
        record.AddRange(handshake);
        return record.ToArray();
    }

    private static byte[] Extension(ushort type, List<byte> data)
    {
        var extension = new List<byte>();
        extension.AddRange(Be16(type));
        extension.AddRange(Be16((ushort)data.Count));
        extension.AddRange(data);
        return extension.ToArray();
    }

    private static string Hash12(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(hash)[..12];
    }

    private static byte[] Be16(ushort value) => [(byte)(value >> 8), (byte)value];

    private static byte[] Be24(int value) => [(byte)(value >> 16), (byte)(value >> 8), (byte)value];
}
