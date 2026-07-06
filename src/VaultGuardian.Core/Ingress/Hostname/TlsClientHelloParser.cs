using System.Buffers.Binary;
using System.Text;

namespace VaultGuardian.Core.Ingress.Hostname;

/// <summary>
/// Extracts the Server Name Indication (SNI) host from a TLS ClientHello. The
/// input is expected to start at the TLS record header (content type 0x16).
/// Only the host_name entry of the server_name extension is read; malformed or
/// non-ClientHello input returns <c>false</c> (fail closed).
/// </summary>
public static class TlsClientHelloParser
{
    private const byte HandshakeContentType = 0x16;
    private const byte ClientHelloType = 0x01;
    private const ushort ServerNameExtension = 0x0000;
    private const ushort SignatureAlgorithmsExtension = 0x000d;
    private const ushort AlpnExtension = 0x0010;
    private const ushort SupportedVersionsExtension = 0x002b;
    private const byte HostNameType = 0x00;

    private static readonly TlsClientHelloInfo EmptyInfo =
        new("00", false, string.Empty, [], [], null, []);

    /// <summary>
    /// Fully parses a ClientHello into a <see cref="TlsClientHelloInfo"/> (SNI,
    /// cipher suites, extensions, ALPN, signature algorithms, negotiated version)
    /// for JA4 fingerprinting. Returns <c>false</c> on malformed input.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> record, out TlsClientHelloInfo info)
    {
        info = EmptyInfo;

        if (record.Length < 5 || record[0] != HandshakeContentType)
        {
            return false;
        }

        int recordLength = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(3, 2));
        var body = record.Slice(5);
        if (recordLength < body.Length)
        {
            body = body.Slice(0, recordLength);
        }

        if (body.Length < 4 || body[0] != ClientHelloType)
        {
            return false;
        }

        int pos = 4;
        if (pos + 34 > body.Length) // client version(2) + random(32)
        {
            return false;
        }

        ushort legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos, 2));
        pos += 34;

        if (!TryReadVector8(body, ref pos, out _) ||                 // session_id
            !TryReadVector16(body, ref pos, out var cipherBytes) ||  // cipher_suites
            !TryReadVector8(body, ref pos, out _))                   // compression_methods
        {
            return false;
        }

        var ciphers = ReadUInt16List(cipherBytes);
        var extensions = new List<ushort>();
        var signatureAlgorithms = new List<ushort>();
        bool hasServerName = false;
        string serverName = string.Empty;
        string? firstAlpn = null;
        ushort? negotiatedVersion = null;

        if (pos + 2 <= body.Length)
        {
            int extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos, 2));
            pos += 2;
            int extensionsEnd = pos + extensionsLength;
            if (extensionsEnd > body.Length)
            {
                return false;
            }

            while (pos + 4 <= extensionsEnd)
            {
                ushort extType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos, 2));
                int extLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos + 2, 2));
                int extDataStart = pos + 4;
                if (extDataStart + extLength > extensionsEnd)
                {
                    return false;
                }

                var extData = body.Slice(extDataStart, extLength);
                extensions.Add(extType);

                switch (extType)
                {
                    case ServerNameExtension:
                        hasServerName = true;
                        if (TryReadServerNameExtension(extData, out var parsedName))
                        {
                            serverName = parsedName;
                        }

                        break;
                    case AlpnExtension:
                        firstAlpn = ReadFirstAlpn(extData);
                        break;
                    case SignatureAlgorithmsExtension:
                        signatureAlgorithms = ReadUInt16Vector16(extData);
                        break;
                    case SupportedVersionsExtension:
                        negotiatedVersion = ReadMaxSupportedVersion(extData);
                        break;
                }

                pos = extDataStart + extLength;
            }
        }

        info = new TlsClientHelloInfo(
            MapTlsVersion(negotiatedVersion ?? legacyVersion),
            hasServerName,
            serverName,
            ciphers,
            extensions,
            firstAlpn,
            signatureAlgorithms);
        return true;
    }

    private static bool TryReadVector8(ReadOnlySpan<byte> span, ref int pos, out ReadOnlySpan<byte> data)
    {
        data = default;
        if (pos + 1 > span.Length)
        {
            return false;
        }

        int length = span[pos];
        int start = pos + 1;
        if (start + length > span.Length)
        {
            return false;
        }

        data = span.Slice(start, length);
        pos = start + length;
        return true;
    }

    private static bool TryReadVector16(ReadOnlySpan<byte> span, ref int pos, out ReadOnlySpan<byte> data)
    {
        data = default;
        if (pos + 2 > span.Length)
        {
            return false;
        }

        int length = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos, 2));
        int start = pos + 2;
        if (start + length > span.Length)
        {
            return false;
        }

        data = span.Slice(start, length);
        pos = start + length;
        return true;
    }

    private static List<ushort> ReadUInt16List(ReadOnlySpan<byte> span)
    {
        var list = new List<ushort>(span.Length / 2);
        for (int i = 0; i + 2 <= span.Length; i += 2)
        {
            list.Add(BinaryPrimitives.ReadUInt16BigEndian(span.Slice(i, 2)));
        }

        return list;
    }

    // signature_algorithms: 2-byte list length then 2-byte entries.
    private static List<ushort> ReadUInt16Vector16(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return [];
        }

        int length = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(0, 2));
        int end = Math.Min(2 + length, data.Length);
        var list = new List<ushort>();
        for (int i = 2; i + 2 <= end; i += 2)
        {
            list.Add(BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2)));
        }

        return list;
    }

    // supported_versions (client): 1-byte list length then 2-byte versions.
    private static ushort? ReadMaxSupportedVersion(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1)
        {
            return null;
        }

        int length = data[0];
        int end = Math.Min(1 + length, data.Length);
        ushort? max = null;
        for (int i = 1; i + 2 <= end; i += 2)
        {
            ushort version = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(i, 2));
            if ((version & 0x0f0f) == 0x0a0a && (version >> 8) == (version & 0x00ff))
            {
                continue; // GREASE version placeholder
            }

            if (max is null || version > max)
            {
                max = version;
            }
        }

        return max;
    }

    private static string? ReadFirstAlpn(ReadOnlySpan<byte> data)
    {
        if (data.Length < 3)
        {
            return null;
        }

        int listLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(0, 2));
        int end = Math.Min(2 + listLength, data.Length);
        int pos = 2;
        if (pos + 1 > end)
        {
            return null;
        }

        int nameLength = data[pos];
        int start = pos + 1;
        if (nameLength == 0 || start + nameLength > end)
        {
            return null;
        }

        return Encoding.ASCII.GetString(data.Slice(start, nameLength));
    }

    private static string MapTlsVersion(ushort version) => version switch
    {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00"
    };

    public static bool TryParseServerName(ReadOnlySpan<byte> record, out string serverName)
    {
        serverName = string.Empty;

        // TLS record header: type(1) + version(2) + length(2)
        if (record.Length < 5 || record[0] != HandshakeContentType)
        {
            return false;
        }

        int recordLength = BinaryPrimitives.ReadUInt16BigEndian(record.Slice(3, 2));
        var body = record.Slice(5);
        if (recordLength > body.Length)
        {
            recordLength = body.Length; // tolerate a ClientHello split across packets
        }

        body = body.Slice(0, recordLength);

        // Handshake header: msg_type(1) + length(3)
        if (body.Length < 4 || body[0] != ClientHelloType)
        {
            return false;
        }

        int pos = 4;

        // ClientHello: version(2) + random(32)
        pos += 2 + 32;

        // session_id: len(1) + data
        if (!SkipVector8(body, ref pos))
        {
            return false;
        }

        // cipher_suites: len(2) + data
        if (!SkipVector16(body, ref pos))
        {
            return false;
        }

        // compression_methods: len(1) + data
        if (!SkipVector8(body, ref pos))
        {
            return false;
        }

        // extensions: len(2) + data
        if (pos + 2 > body.Length)
        {
            return false;
        }

        int extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos, 2));
        pos += 2;
        int extensionsEnd = pos + extensionsLength;
        if (extensionsEnd > body.Length)
        {
            return false;
        }

        while (pos + 4 <= extensionsEnd)
        {
            ushort extType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos, 2));
            int extLength = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos + 2, 2));
            int extData = pos + 4;
            if (extData + extLength > extensionsEnd)
            {
                return false;
            }

            if (extType == ServerNameExtension)
            {
                return TryReadServerNameExtension(body.Slice(extData, extLength), out serverName);
            }

            pos = extData + extLength;
        }

        return false;
    }

    private static bool TryReadServerNameExtension(ReadOnlySpan<byte> data, out string serverName)
    {
        serverName = string.Empty;

        // server_name_list: len(2) then entries of name_type(1) + name(len(2)+bytes)
        if (data.Length < 2)
        {
            return false;
        }

        int listLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(0, 2));
        int pos = 2;
        int listEnd = pos + listLength;
        if (listEnd > data.Length)
        {
            return false;
        }

        while (pos + 3 <= listEnd)
        {
            byte nameType = data[pos];
            int nameLength = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(pos + 1, 2));
            int nameStart = pos + 3;
            if (nameStart + nameLength > listEnd)
            {
                return false;
            }

            if (nameType == HostNameType && nameLength > 0)
            {
                serverName = Encoding.ASCII.GetString(data.Slice(nameStart, nameLength));
                return serverName.Length > 0;
            }

            pos = nameStart + nameLength;
        }

        return false;
    }

    private static bool SkipVector8(ReadOnlySpan<byte> span, ref int pos)
    {
        if (pos + 1 > span.Length)
        {
            return false;
        }

        int length = span[pos];
        pos += 1 + length;
        return pos <= span.Length;
    }

    private static bool SkipVector16(ReadOnlySpan<byte> span, ref int pos)
    {
        if (pos + 2 > span.Length)
        {
            return false;
        }

        int length = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(pos, 2));
        pos += 2 + length;
        return pos <= span.Length;
    }
}
