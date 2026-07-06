using System.Security.Cryptography;
using System.Text;

namespace VaultGuardian.Core.Ingress.Hostname;

/// <summary>
/// Computes the JA4 TLS client fingerprint (FoxIO spec) from a parsed
/// ClientHello. Format: <c>a_b_c</c> where
/// <list type="bullet">
/// <item>a = transport + TLS version + SNI flag + cipher count + extension count + first ALPN,</item>
/// <item>b = sha256(sorted cipher suites)[:12],</item>
/// <item>c = sha256(sorted extensions (minus SNI/ALPN) + "_" + signature algorithms)[:12].</item>
/// </list>
/// GREASE values are excluded everywhere. The fingerprint identifies the client
/// stack (browser/library/malware) independent of hostname or destination.
/// </summary>
public static class Ja4Calculator
{
    private const string Zeros = "000000000000";
    private const ushort ServerNameExtension = 0x0000;
    private const ushort AlpnExtension = 0x0010;

    public static string Compute(TlsClientHelloInfo hello, char transport = 't')
    {
        var ciphers = WithoutGrease(hello.CipherSuites);
        var extensions = WithoutGrease(hello.Extensions);
        var signatureAlgorithms = WithoutGrease(hello.SignatureAlgorithms);

        var partA = string.Concat(
            transport,
            hello.TlsVersion,
            hello.HasServerName ? "d" : "i",
            Count2(ciphers.Count),
            Count2(extensions.Count),
            Alpn2(hello.FirstAlpn));

        var sortedCiphers = ciphers.OrderBy(static c => c).Select(Hex);
        var partB = ciphers.Count == 0 ? Zeros : Hash12(string.Join(',', sortedCiphers));

        // Part c hashes the sorted extensions with SNI and ALPN removed, joined
        // to the signature algorithms (kept in wire order) by an underscore.
        var hashedExtensions = extensions
            .Where(static e => e != ServerNameExtension && e != AlpnExtension)
            .OrderBy(static e => e)
            .Select(Hex)
            .ToList();

        string partC;
        if (hashedExtensions.Count == 0)
        {
            partC = Zeros;
        }
        else
        {
            var signaturePart = string.Join(',', signatureAlgorithms.Select(Hex));
            partC = Hash12($"{string.Join(',', hashedExtensions)}_{signaturePart}");
        }

        return $"{partA}_{partB}_{partC}";
    }

    private static List<ushort> WithoutGrease(IReadOnlyList<ushort> values)
    {
        var result = new List<ushort>(values.Count);
        foreach (var value in values)
        {
            if (!IsGrease(value))
            {
                result.Add(value);
            }
        }

        return result;
    }

    // GREASE values (RFC 8701) are 0x0a0a, 0x1a1a, ... 0xfafa: both bytes equal
    // and low nibble 0xa.
    private static bool IsGrease(ushort value) =>
        (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0x00ff);

    private static string Count2(int count) => Math.Min(count, 99).ToString("D2");

    private static string Hex(ushort value) => value.ToString("x4");

    private static string Alpn2(string? alpn)
    {
        if (string.IsNullOrEmpty(alpn))
        {
            return "00";
        }

        return $"{alpn[0]}{alpn[^1]}";
    }

    private static string Hash12(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexStringLower(hash)[..12];
    }
}
