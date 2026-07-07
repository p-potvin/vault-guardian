using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using VaultGuardian.Core.Ingress.Hostname;

namespace VaultGuardian.Core.Processes;

/// <summary>
/// Windows implementation of <see cref="IProcessInspector"/>. It fuses per-process
/// CPU sampling (System.Diagnostics), image path / parent / hosted services (WMI),
/// Authenticode trust (cached), and the kernel critical-process bit into
/// <see cref="ProcessFacts"/>, then classifies each with
/// <see cref="ProcessTriageClassifier"/>. All probes are best-effort: a process
/// we cannot open still appears with whatever facts were readable.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsProcessInspector : IProcessInspector
{
    private const int ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessBreakOnTermination = 29;
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int MaxEndpointsPerProcess = 6;

    private static readonly ConcurrentDictionary<string, (SignatureStatus Status, string? Publisher)> SignatureCache = new();

    private readonly IHostnameResolver _hostnameResolver;
    private readonly object _sampleLock = new();
    private Dictionary<int, (TimeSpan Cpu, DateTimeOffset At)> _previousCpu = new();

    public WindowsProcessInspector(IHostnameResolver hostnameResolver)
    {
        _hostnameResolver = hostnameResolver;
    }

    public IReadOnlyList<ProcessTriageEntry> Snapshot(int maxEntries = 150)
    {
        var processMetadata = QueryProcessMetadata();
        var servicesByPid = QueryServicesByPid();
        var remoteAddressesByPid = QueryTcpRemoteAddressesByPid();
        var processorCount = Math.Max(1, Environment.ProcessorCount);

        var nextCpu = new Dictionary<int, (TimeSpan, DateTimeOffset)>();
        var entries = new List<ProcessTriageEntry>();

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var pid = process.Id;
                var name = process.ProcessName;
                var cpuPercent = SampleCpuPercent(process, processorCount, nextCpu);
                long workingSet = SafeWorkingSet(process);

                processMetadata.TryGetValue(pid, out var meta);
                var imagePath = meta.Path;
                var parentPid = meta.ParentPid;

                var (signature, publisher) = ResolveSignature(imagePath);
                servicesByPid.TryGetValue(pid, out var services);
                var hostnames = ResolveHostnames(pid, remoteAddressesByPid);

                var facts = new ProcessFacts(
                    ProcessId: pid,
                    Name: name,
                    ImagePath: imagePath,
                    ParentProcessId: parentPid,
                    CpuPercent: cpuPercent,
                    WorkingSetBytes: workingSet,
                    Signature: signature,
                    Publisher: publisher,
                    IsCriticalProcess: ProbeCriticalBit(pid),
                    IsServiceHost: name.Equals("svchost", StringComparison.OrdinalIgnoreCase),
                    HostedServices: services ?? [],
                    RunsInUtilityVm: IsUtilityVm(name),
                    Hostnames: hostnames);

                entries.Add(new ProcessTriageEntry(facts, ProcessTriageClassifier.Classify(facts)));
            }
            catch
            {
                // Skip processes that vanished or cannot be read at all.
            }
            finally
            {
                process.Dispose();
            }
        }

        lock (_sampleLock)
        {
            _previousCpu = nextCpu;
        }

        return entries
            .OrderByDescending(e => e.Facts.CpuPercent)
            .ThenByDescending(e => e.Facts.WorkingSetBytes)
            .Take(maxEntries)
            .ToList();
    }

    private double SampleCpuPercent(Process process, int processorCount, Dictionary<int, (TimeSpan, DateTimeOffset)> nextCpu)
    {
        TimeSpan cpuTime;
        try
        {
            cpuTime = process.TotalProcessorTime;
        }
        catch
        {
            return 0;
        }

        var now = DateTimeOffset.UtcNow;
        nextCpu[process.Id] = (cpuTime, now);

        Dictionary<int, (TimeSpan Cpu, DateTimeOffset At)> previous;
        lock (_sampleLock)
        {
            previous = _previousCpu;
        }

        if (!previous.TryGetValue(process.Id, out var last))
        {
            return 0;
        }

        var wallDelta = (now - last.At).TotalMilliseconds;
        if (wallDelta <= 0)
        {
            return 0;
        }

        var cpuDelta = (cpuTime - last.Cpu).TotalMilliseconds;
        var percent = cpuDelta / (wallDelta * processorCount) * 100.0;
        return percent < 0 ? 0 : Math.Round(percent, 1);
    }

    private static long SafeWorkingSet(Process process)
    {
        try
        {
            return process.WorkingSet64;
        }
        catch
        {
            return 0;
        }
    }

    private static Dictionary<int, (string? Path, int ParentPid)> QueryProcessMetadata()
    {
        var map = new Dictionary<int, (string?, int)>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ExecutablePath, ParentProcessId FROM Win32_Process");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    var pid = ToInt(obj["ProcessId"]);
                    if (pid <= 0)
                    {
                        continue;
                    }

                    map[pid] = (obj["ExecutablePath"] as string, ToInt(obj["ParentProcessId"]));
                }
            }
        }
        catch
        {
            // WMI unavailable — facts fall back to path-less classification.
        }

        return map;
    }

    private static Dictionary<int, List<string>> QueryServicesByPid()
    {
        var map = new Dictionary<int, List<string>>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, ProcessId FROM Win32_Service WHERE State = 'Running'");
            foreach (var obj in searcher.Get())
            {
                using (obj)
                {
                    var pid = ToInt(obj["ProcessId"]);
                    if (pid <= 0)
                    {
                        continue;
                    }

                    var serviceName = obj["Name"] as string;
                    if (string.IsNullOrEmpty(serviceName))
                    {
                        continue;
                    }

                    if (!map.TryGetValue(pid, out var list))
                    {
                        list = [];
                        map[pid] = list;
                    }

                    list.Add(serviceName);
                }
            }
        }
        catch
        {
            // Best-effort; svchost still classifies by name.
        }

        return map;
    }

    private IReadOnlyList<string> ResolveHostnames(int pid, Dictionary<int, HashSet<string>> remoteAddressesByPid)
    {
        if (!remoteAddressesByPid.TryGetValue(pid, out var addresses) || addresses.Count == 0)
        {
            return [];
        }

        var endpoints = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var address in addresses)
        {
            if (!_hostnameResolver.TryResolve(address, out var hostname, out var ja4))
            {
                continue;
            }

            var label = string.IsNullOrEmpty(ja4) ? hostname : $"{hostname} [{ja4}]";
            if (seen.Add(label))
            {
                endpoints.Add(label);
                if (endpoints.Count >= MaxEndpointsPerProcess)
                {
                    break;
                }
            }
        }

        return endpoints;
    }

    // Maps owning PID -> distinct remote addresses from the active TCP tables (IPv4 + IPv6).
    private static Dictionary<int, HashSet<string>> QueryTcpRemoteAddressesByPid()
    {
        var map = new Dictionary<int, HashSet<string>>();

        // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (24 bytes).
        ReadTcpTable(AfInet, rowSize: 24, remoteAddrOffset: 12, remoteAddrLength: 4, pidOffset: 20, map);

        // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16],
        // remoteScope, remotePort, state, pid (56 bytes).
        ReadTcpTable(AfInet6, rowSize: 56, remoteAddrOffset: 24, remoteAddrLength: 16, pidOffset: 52, map);

        return map;
    }

    private static void ReadTcpTable(
        int ipVersion,
        int rowSize,
        int remoteAddrOffset,
        int remoteAddrLength,
        int pidOffset,
        Dictionary<int, HashSet<string>> map)
    {
        int bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, ipVersion, TcpTableOwnerPidAll, 0);
        if (bufferSize <= 0)
        {
            return;
        }

        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (GetExtendedTcpTable(buffer, ref bufferSize, false, ipVersion, TcpTableOwnerPidAll, 0) != 0)
            {
                return;
            }

            int entryCount = Marshal.ReadInt32(buffer);
            const int rowsStart = 4; // past dwNumEntries
            var addressBytes = new byte[remoteAddrLength];
            for (int i = 0; i < entryCount; i++)
            {
                int baseOffset = rowsStart + (i * rowSize);
                int pid = Marshal.ReadInt32(buffer, baseOffset + pidOffset);
                if (pid <= 0)
                {
                    continue;
                }

                Marshal.Copy(IntPtr.Add(buffer, baseOffset + remoteAddrOffset), addressBytes, 0, remoteAddrLength);
                var ip = new IPAddress(addressBytes);
                if (IsUnspecified(ip))
                {
                    continue; // listening / unconnected socket
                }

                var address = ip.ToString();
                if (!map.TryGetValue(pid, out var set))
                {
                    set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    map[pid] = set;
                }

                set.Add(address);
            }
        }
        catch
        {
            // Best-effort: no network attribution when the table can't be read.
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool IsUnspecified(IPAddress ip) =>
        ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any);

    private static (SignatureStatus, string?) ResolveSignature(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath) || !File.Exists(imagePath))
        {
            return (SignatureStatus.Unknown, null);
        }

        return SignatureCache.GetOrAdd(imagePath, static path =>
        {
            try
            {
                // CreateFromSignedFile is the documented way to read an Authenticode
                // signer cert from a PE file; X509CertificateLoader has no equivalent.
#pragma warning disable SYSLIB0057
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
                using var chain = new X509Chain();
                var trusted = chain.Build(cert);
                var publisher = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                return (trusted ? SignatureStatus.SignedTrusted : SignatureStatus.SignedUntrusted, publisher);
            }
            catch
            {
                return (SignatureStatus.Unsigned, null);
            }
        });
    }

    private static bool ProbeCriticalBit(int pid)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            int value = 0;
            var status = NtQueryInformationProcess(handle, ProcessBreakOnTermination, ref value, sizeof(int), out _);
            return status == 0 && value != 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static bool IsUtilityVm(string name) =>
        name.Equals("vmmem", StringComparison.OrdinalIgnoreCase) ||
        name.StartsWith("vmmemwsl", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("vmmemCmZygote", StringComparison.OrdinalIgnoreCase);

    private static int ToInt(object? value)
    {
        try
        {
            return value is null ? 0 : Convert.ToInt32(value);
        }
        catch
        {
            return 0;
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int tableSize,
        bool sort,
        int ipVersion,
        int tableClass,
        int reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref int processInformation,
        int processInformationLength,
        out int returnLength);
}
