using System.Collections.Concurrent;

namespace VaultGuardian.Core.Ingress.Hostname;

/// <summary>
/// Thread-safe, bounded cache of remote address → hostname learned passively
/// from DNS answers and TLS SNI. It is both the write side (ingest) for the
/// capture loops and the read side (<see cref="IHostnameResolver"/>) for the
/// interceptor. Entries expire on their TTL so the map reflects current DNS.
/// </summary>
public sealed class HostnameResolutionStore : IHostnameResolver
{
    private static readonly TimeSpan MinTtl = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxTtl = TimeSpan.FromHours(6);
    private static readonly TimeSpan SniTtl = TimeSpan.FromMinutes(30);

    private readonly ConcurrentDictionary<string, HostnameResolution> _map = new();
    private readonly TimeProvider _clock;
    private readonly int _capacity;

    public HostnameResolutionStore(TimeProvider? clock = null, int capacity = 4096)
    {
        _clock = clock ?? TimeProvider.System;
        _capacity = Math.Max(64, capacity);
    }

    /// <summary>Feeds a DNS response payload (UDP source port 53) into the map.</summary>
    public int IngestDnsResponse(ReadOnlySpan<byte> dnsPayload)
    {
        var records = DnsResponseParser.ParseAnswers(dnsPayload);
        foreach (var record in records)
        {
            var ttl = ClampTtl(TimeSpan.FromSeconds(record.TtlSeconds));
            Set(record.Address, record.Hostname, HostnameSource.Dns, ttl);
        }

        return records.Count;
    }

    /// <summary>
    /// Feeds an outbound TLS ClientHello, associating its SNI with the destination
    /// address and recording the JA4 client fingerprint alongside it.
    /// </summary>
    public bool IngestTlsClientHello(string destinationAddress, ReadOnlySpan<byte> tlsRecord)
    {
        if (string.IsNullOrWhiteSpace(destinationAddress))
        {
            return false;
        }

        if (!TlsClientHelloParser.TryParse(tlsRecord, out var hello) ||
            !hello.HasServerName ||
            string.IsNullOrWhiteSpace(hello.ServerName))
        {
            return false;
        }

        var ja4 = Ja4Calculator.Compute(hello);
        Set(destinationAddress, hello.ServerName, HostnameSource.Sni, SniTtl, ja4);
        return true;
    }

    public bool TryResolve(string address, out string hostname)
    {
        hostname = string.Empty;
        if (string.IsNullOrWhiteSpace(address))
        {
            return false;
        }

        if (_map.TryGetValue(address, out var resolution))
        {
            if (resolution.ExpiresAt > _clock.GetUtcNow())
            {
                hostname = resolution.Hostname;
                return true;
            }

            _map.TryRemove(address, out _);
        }

        return false;
    }

    /// <summary>Current, non-expired mappings, most recently resolved first (for UI/diagnostics).</summary>
    public IReadOnlyList<HostnameResolution> Snapshot()
    {
        var now = _clock.GetUtcNow();
        var live = new List<HostnameResolution>(_map.Count);
        foreach (var pair in _map)
        {
            if (pair.Value.ExpiresAt > now)
            {
                live.Add(pair.Value);
            }
            else
            {
                _map.TryRemove(pair.Key, out _);
            }
        }

        live.Sort((a, b) => b.ResolvedAt.CompareTo(a.ResolvedAt));
        return live;
    }

    private void Set(string address, string hostname, HostnameSource source, TimeSpan ttl, string? ja4 = null)
    {
        if (string.IsNullOrWhiteSpace(address) || string.IsNullOrWhiteSpace(hostname))
        {
            return;
        }

        var now = _clock.GetUtcNow();
        _map[address] = new HostnameResolution(address, hostname, source, now, now + ttl, ja4);

        if (_map.Count > _capacity)
        {
            EvictExpiredThenOldest(now);
        }
    }

    private void EvictExpiredThenOldest(DateTimeOffset now)
    {
        foreach (var pair in _map)
        {
            if (pair.Value.ExpiresAt <= now)
            {
                _map.TryRemove(pair.Key, out _);
            }
        }

        // If still over budget, drop the oldest resolutions until we are back under.
        while (_map.Count > _capacity)
        {
            KeyValuePair<string, HostnameResolution>? oldest = null;
            foreach (var pair in _map)
            {
                if (oldest is null || pair.Value.ResolvedAt < oldest.Value.Value.ResolvedAt)
                {
                    oldest = pair;
                }
            }

            if (oldest is null)
            {
                break;
            }

            _map.TryRemove(oldest.Value.Key, out _);
        }
    }

    private static TimeSpan ClampTtl(TimeSpan ttl)
    {
        if (ttl < MinTtl)
        {
            return MinTtl;
        }

        return ttl > MaxTtl ? MaxTtl : ttl;
    }
}
