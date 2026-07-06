using System.Text;
using VaultGuardian.Core.Ingress.Hostname;

namespace VaultGuardian.Core.Tests;

public sealed class HostnameResolutionTests
{
    [Fact]
    public void DnsResponseParser_ParsesARecord_AttributedToQueriedName()
    {
        var message = BuildDnsResponse("example.com", [93, 184, 216, 34], ttlSeconds: 3600);

        var records = DnsResponseParser.ParseAnswers(message);

        var record = Assert.Single(records);
        Assert.Equal("example.com", record.Hostname);
        Assert.Equal("93.184.216.34", record.Address);
        Assert.Equal(3600, record.TtlSeconds);
    }

    [Fact]
    public void DnsResponseParser_IgnoresQueryMessages()
    {
        var query = BuildDnsResponse("example.com", [1, 2, 3, 4], ttlSeconds: 60);
        query[2] &= 0x7F; // clear the QR bit → looks like a request

        Assert.Empty(DnsResponseParser.ParseAnswers(query));
    }

    [Fact]
    public void DnsResponseParser_ReturnsEmptyForTruncatedMessage()
    {
        var message = BuildDnsResponse("example.com", [93, 184, 216, 34], ttlSeconds: 3600);
        var truncated = message.AsSpan(0, message.Length - 3).ToArray();

        Assert.Empty(DnsResponseParser.ParseAnswers(truncated));
    }

    [Fact]
    public void TlsClientHelloParser_ExtractsServerName()
    {
        var hello = BuildClientHello("secure.example.test");

        Assert.True(TlsClientHelloParser.TryParseServerName(hello, out var name));
        Assert.Equal("secure.example.test", name);
    }

    [Fact]
    public void TlsClientHelloParser_RejectsNonHandshakeRecord()
    {
        var hello = BuildClientHello("example.com");
        hello[0] = 0x17; // application_data, not handshake

        Assert.False(TlsClientHelloParser.TryParseServerName(hello, out _));
    }

    [Fact]
    public void Store_ResolvesHostnameLearnedFromDns()
    {
        var store = new HostnameResolutionStore();
        var message = BuildDnsResponse("cdn.example.net", [203, 0, 113, 7], ttlSeconds: 120);

        var count = store.IngestDnsResponse(message);

        Assert.Equal(1, count);
        Assert.True(store.TryResolve("203.0.113.7", out var host));
        Assert.Equal("cdn.example.net", host);
    }

    [Fact]
    public void Store_ResolvesHostnameLearnedFromSni()
    {
        var store = new HostnameResolutionStore();
        var hello = BuildClientHello("api.example.org");

        Assert.True(store.IngestTlsClientHello("198.51.100.9", hello));
        Assert.True(store.TryResolve("198.51.100.9", out var host));
        Assert.Equal("api.example.org", host);
    }

    [Fact]
    public void Store_ExpiresEntriesAfterTtl()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.Parse("2026-07-06T00:00:00Z"));
        var store = new HostnameResolutionStore(clock);
        var message = BuildDnsResponse("short.example.com", [192, 0, 2, 5], ttlSeconds: 3600);

        store.IngestDnsResponse(message);
        Assert.True(store.TryResolve("192.0.2.5", out _));

        clock.Advance(TimeSpan.FromHours(2));

        Assert.False(store.TryResolve("192.0.2.5", out _));
    }

    [Fact]
    public void Store_SnapshotExcludesExpiredEntries()
    {
        var clock = new MutableTimeProvider(DateTimeOffset.Parse("2026-07-06T00:00:00Z"));
        var store = new HostnameResolutionStore(clock);
        store.IngestDnsResponse(BuildDnsResponse("a.example.com", [192, 0, 2, 1], ttlSeconds: 60));

        clock.Advance(TimeSpan.FromMinutes(5));
        store.IngestDnsResponse(BuildDnsResponse("b.example.com", [192, 0, 2, 2], ttlSeconds: 3600));

        var snapshot = store.Snapshot();

        var entry = Assert.Single(snapshot);
        Assert.Equal("b.example.com", entry.Hostname);
    }

    private static byte[] BuildDnsResponse(string name, byte[] address, uint ttlSeconds)
    {
        var message = new List<byte>
        {
            0x12, 0x34,       // ID
            0x81, 0x80,       // flags: response, recursion available
            0x00, 0x01,       // QDCOUNT = 1
            0x00, 0x01,       // ANCOUNT = 1
            0x00, 0x00,       // NSCOUNT
            0x00, 0x00,       // ARCOUNT
        };

        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            message.Add((byte)bytes.Length);
            message.AddRange(bytes);
        }

        message.Add(0x00);          // root label
        message.AddRange(Be16(1));  // QTYPE A
        message.AddRange(Be16(1));  // QCLASS IN

        message.AddRange(new byte[] { 0xC0, 0x0C }); // NAME → pointer to the question name
        message.AddRange(Be16((ushort)(address.Length == 16 ? 28 : 1))); // TYPE A/AAAA
        message.AddRange(Be16(1));  // CLASS IN
        message.AddRange(Be32(ttlSeconds));
        message.AddRange(Be16((ushort)address.Length)); // RDLENGTH
        message.AddRange(address);

        return message.ToArray();
    }

    private static byte[] BuildClientHello(string sni)
    {
        var name = Encoding.ASCII.GetBytes(sni);

        var entry = new List<byte> { 0x00 };  // host_name
        entry.AddRange(Be16((ushort)name.Length));
        entry.AddRange(name);

        var list = new List<byte>();
        list.AddRange(Be16((ushort)entry.Count));
        list.AddRange(entry);

        var extension = new List<byte>();
        extension.AddRange(Be16(0x0000)); // server_name extension
        extension.AddRange(Be16((ushort)list.Count));
        extension.AddRange(list);

        var body = new List<byte> { 0x03, 0x03 }; // client version
        body.AddRange(new byte[32]);              // random
        body.Add(0x00);                           // session_id length
        body.AddRange(Be16(2));
        body.AddRange(new byte[] { 0x13, 0x01 }); // one cipher suite
        body.Add(0x01);
        body.Add(0x00);                           // one compression method (null)
        body.AddRange(Be16((ushort)extension.Count));
        body.AddRange(extension);

        var handshake = new List<byte> { 0x01 };  // ClientHello
        handshake.AddRange(Be24(body.Count));
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01 }; // handshake, TLS 1.0 record
        record.AddRange(Be16((ushort)handshake.Count));
        record.AddRange(handshake);

        return record.ToArray();
    }

    private static byte[] Be16(ushort value) => [(byte)(value >> 8), (byte)value];

    private static byte[] Be24(int value) => [(byte)(value >> 16), (byte)(value >> 8), (byte)value];

    private static byte[] Be32(uint value) =>
        [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];

    private sealed class MutableTimeProvider(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan delta) => _now += delta;
    }
}
