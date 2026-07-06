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
    private const byte HostNameType = 0x00;

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
