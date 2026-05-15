using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;

namespace VaultGuardian.Core.Observability;

public sealed partial class ResourceMonitor : IDisposable
{
    private readonly PerformanceCounter _cpuCounter;
    private readonly PerformanceCounter _ramAvailableCounter;
    private bool _disposed;
    private bool _nvmlInitialized;
    private IntPtr _gpuHandle;

    public ResourceMonitor()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            _ramAvailableCounter = new PerformanceCounter("Memory", "Available MBytes");
            // Initial read to avoid first value being 0
            _cpuCounter.NextValue();
            
            InitializeNvml();
        }
        else
        {
            throw new PlatformNotSupportedException("ResourceMonitor is currently only supported on Windows.");
        }
    }

    private void InitializeNvml()
    {
        try
        {
            if (nvmlInit() == 0)
            {
                _nvmlInitialized = true;
                // Get handle for the first GPU (index 0)
                if (nvmlDeviceGetHandleByIndex(0, out _gpuHandle) != 0)
                {
                    _gpuHandle = IntPtr.Zero;
                }
            }
        }
        catch { /* NVML not found or failed to init */ }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct nvmlUtilization_t
    {
        public uint gpu;
        public uint memory;
    }

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlInit();

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlShutdown();

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetHandleByIndex(uint index, out IntPtr device);

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetUtilizationRates(IntPtr device, out nvmlUtilization_t utilization);

    public SystemResourceMetrics GetCurrentMetrics()
    {
        var cpuUsage = _cpuCounter.NextValue();
        var availableUnits = _ramAvailableCounter.NextValue();

        // Approximate Total RAM using computer info
        var totalRamBytes = GetTotalPhysicalMemory();
        var availableBytes = availableUnits * 1024 * 1024;
        var usedBytes = totalRamBytes - availableBytes;

        return new SystemResourceMetrics(
            CpuUsagePercentage: cpuUsage,
            RamUsageBytes: usedBytes,
            RamAvailableBytes: availableBytes,
            GpuUsagePercentage: GetGpuUsage()
        );
    }

    private double GetGpuUsage()
    {
        if (_nvmlInitialized && _gpuHandle != IntPtr.Zero)
        {
            if (nvmlDeviceGetUtilizationRates(_gpuHandle, out var utilization) == 0)
            {
                return utilization.gpu;
            }
        }

        // Fallback to WMI if NVML fails
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController");
            foreach (var obj in searcher.Get())
            {
                // GPU usage through WMI is notoriously tricky and often requires vendor drivers.
                // This is a placeholder. For actual usage, Nvml or DirectX probes are better.
                return 0.0; 
            }
        }
        catch { }
        return 0.0;
    }

    private double GetTotalPhysicalMemory()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            foreach (var obj in searcher.Get())
            {
                return Convert.ToDouble(obj["TotalPhysicalMemory"]);
            }
        }
        catch { }
        return 16.0 * 1024 * 1024 * 1024; // Fallback
    }

    public void Dispose()
    {
        if (_disposed) return;
        _cpuCounter?.Dispose();
        _ramAvailableCounter?.Dispose();
        
        if (_nvmlInitialized)
        {
            try { nvmlShutdown(); } catch { }
        }
        
        _disposed = true;
    }
}
