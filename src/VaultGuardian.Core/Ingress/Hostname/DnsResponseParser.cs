using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace VaultGuardian.Core.Ingress.Hostname;

/// <summary>
/// Minimal, allocation-light parser for DNS response messages (RFC 1035).
/// It extracts A/AAAA answer records and attributes every resolved IP to the
/// name in the question section — i.e. "this address belongs to the hostname
/// the client looked up." Malformed input yields an empty result (fail closed).
/// </summary>
public static class DnsResponseParser
{
    private const int HeaderLength = 12;
    private const ushort TypeA = 1;
    private const ushort TypeAaaa = 28;
    private const int MaxNameLength = 255;

    public static IReadOnlyList<DnsAddressRecord> ParseAnswers(ReadOnlySpan<byte> message)
    {
        if (message.Length < HeaderLength)
        {
            return [];
        }

        // Byte 2, high bit is QR: 1 = response. Only trust responses.
        var isResponse = (message[2] & 0x80) != 0;
        if (!isResponse)
        {
            return [];
        }

        int questionCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        int answerCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6, 2));
        if (questionCount == 0 || answerCount == 0)
        {
            return [];
        }

        int pos = HeaderLength;

        // Read the queried name from the first question; skip any others.
        if (!TryReadName(message, ref pos, out var queriedName))
        {
            return [];
        }

        pos += 4; // QTYPE + QCLASS
        for (int q = 1; q < questionCount; q++)
        {
            if (!TryReadName(message, ref pos, out _))
            {
                return [];
            }

            pos += 4;
        }

        var records = new List<DnsAddressRecord>(answerCount);
        for (int a = 0; a < answerCount; a++)
        {
            if (!TryReadName(message, ref pos, out _))
            {
                break;
            }

            if (pos + 10 > message.Length)
            {
                break;
            }

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(pos, 2));
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(pos + 4, 4));
            int rdLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(pos + 8, 2));
            int rdStart = pos + 10;
            if (rdStart + rdLength > message.Length)
            {
                break;
            }

            if (type == TypeA && rdLength == 4)
            {
                var ip = new IPAddress(message.Slice(rdStart, 4).ToArray());
                records.Add(new DnsAddressRecord(queriedName, ip.ToString(), ClampTtl(ttl)));
            }
            else if (type == TypeAaaa && rdLength == 16)
            {
                var ip = new IPAddress(message.Slice(rdStart, 16).ToArray());
                records.Add(new DnsAddressRecord(queriedName, ip.ToString(), ClampTtl(ttl)));
            }

            pos = rdStart + rdLength;
        }

        return records;
    }

    private static int ClampTtl(uint ttl) => ttl > int.MaxValue ? int.MaxValue : (int)ttl;

    /// <summary>
    /// Reads a DNS name starting at <paramref name="pos"/>, following compression
    /// pointers to build the dotted string, and advances <paramref name="pos"/> to
    /// the first byte after the name as it appears in the record stream (pointers
    /// are not followed for the purpose of advancing).
    /// </summary>
    private static bool TryReadName(ReadOnlySpan<byte> message, ref int pos, out string name)
    {
        name = string.Empty;
        var builder = new StringBuilder();
        int cursor = pos;
        int? streamPos = null; // where to resume once we jump via a pointer
        int safety = 0;

        while (true)
        {
            if (cursor >= message.Length || ++safety > MaxNameLength)
            {
                return false;
            }

            byte length = message[cursor];

            if ((length & 0xC0) == 0xC0)
            {
                // Compression pointer: two bytes, low 14 bits are the offset.
                if (cursor + 1 >= message.Length)
                {
                    return false;
                }

                streamPos ??= cursor + 2;
                int pointer = ((length & 0x3F) << 8) | message[cursor + 1];
                if (pointer >= message.Length)
                {
                    return false;
                }

                cursor = pointer;
                continue;
            }

            if (length == 0)
            {
                cursor++;
                break;
            }

            // Regular label.
            cursor++;
            if (cursor + length > message.Length)
            {
                return false;
            }

            if (builder.Length > 0)
            {
                builder.Append('.');
            }

            builder.Append(Encoding.ASCII.GetString(message.Slice(cursor, length)));
            cursor += length;
        }

        pos = streamPos ?? cursor;
        name = builder.ToString();
        return name.Length > 0;
    }
}
