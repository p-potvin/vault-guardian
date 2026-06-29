using System.Runtime.InteropServices;
using static VaultGuardian.Core.Observability.CuptiInterop;

namespace VaultGuardian.Core.Observability;

/// <summary>
/// CUDA profiler for monitoring GPU kernel execution and utilization.
/// Dynamically loads NVIDIA CUDA libraries from vendored paths or system installations.
/// Gracefully degrades if CUDA is unavailable.
/// </summary>
public sealed class CudaProfiler : IDisposable
{
    private const int BufferSizeBytes = 4 * 1024 * 1024; // 4 MB activity buffer
    private static bool _loaderInitialized;

    /// <summary>
    /// Static initializer - attempts to set up native library resolution but never crashes.
    /// </summary>
    static CudaProfiler()
    {
        // Don't do anything in the static constructor to avoid fail-fast exceptions.
        // Initialization happens lazily in the instance constructor.
    }

    /// <summary>
    /// Ensures the library loader is initialized once.
    /// </summary>
    private static void EnsureLoaderInitialized()
    {
        if (_loaderInitialized) return;

        try
        {
            CudaLibraryLoader.Initialize();
            _loaderInitialized = true;
        }
        catch (Exception ex)
        {
            // Log but don't crash - CUDA is optional
            System.Diagnostics.Debug.WriteLine($"CUDA library loader initialization failed: {ex}");
            _loaderInitialized = true; // Mark as attempted to avoid repeated tries
        }
    }

    // NVML subset for GPU utilization (same driver as CUPTI)
    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlInit();

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlShutdown();

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetHandleByIndex(uint index, out IntPtr device);

    [StructLayout(LayoutKind.Sequential)]
    private struct NvmlUtilization { public uint gpu; public uint memory; }

    [DllImport("nvml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int nvmlDeviceGetUtilizationRates(IntPtr device, out NvmlUtilization utilization);

    private readonly bool _nvmlInitialized;
    private readonly IntPtr _gpuHandle;
    private readonly bool _cuptiActive;
    private readonly byte[]? _activityBuffer;
    private GCHandle _bufferPin;
    private GCHandle _allocCallbackPin;
    private GCHandle _processCallbackPin;

    // Kernel count accumulated by CUPTI buffer callback (written from native thread)
    private int _pendingKernelCount;

    public CudaProfiler()
    {
        // Check if CUDA is explicitly enabled via environment variable
        bool cudaEnabled = Environment.GetEnvironmentVariable("VAULTGUARDIAN_CUDA_ENABLED") == "1";
        if (!cudaEnabled)
        {
            CudaDiagnostics.LogInfo("CUDA profiler disabled (set VAULTGUARDIAN_CUDA_ENABLED=1 to enable)");
            return;
        }

        // Lazy initialization of library loader - this is safer than static constructor
        EnsureLoaderInitialized();

        try
        {
            if (nvmlInit() == 0)
            {
                _nvmlInitialized = true;
                if (nvmlDeviceGetHandleByIndex(0, out _gpuHandle) != 0)
                    _gpuHandle = IntPtr.Zero;
            }
        }
        catch (DllNotFoundException ex)
        {
            CudaDiagnostics.LogWarning($"NVML initialization failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            CudaDiagnostics.LogError("Unexpected error during NVML initialization", ex);
        }

        // CUPTI is only useful on NVIDIA hardware
        if (!_nvmlInitialized)
        {
            CudaDiagnostics.LogInfo("NVML not initialized; GPU profiling unavailable.");
            return;
        }

        try
        {
            _activityBuffer = new byte[BufferSizeBytes];
            _bufferPin = GCHandle.Alloc(_activityBuffer, GCHandleType.Pinned);

            // Pin delegates so the GC never moves them (they're held by native CUPTI)
            CuptiBufferAllocCallback allocCb = AllocBuffer;
            CuptiBufferRequestCallback processCb = ProcessBuffer;
            _allocCallbackPin = GCHandle.Alloc(allocCb);
            _processCallbackPin = GCHandle.Alloc(processCb);

            if (cuptiActivityRegisterCallbacks(allocCb, processCb) != CuptiResult.CUPTI_SUCCESS ||
                cuptiActivityEnable(CuptiActivityKind.CUPTI_ACTIVITY_KIND_KERNEL) != CuptiResult.CUPTI_SUCCESS)
            {
                FreeCuptiHandles();
                CudaDiagnostics.LogWarning("CUPTI activity registration failed");
                return;
            }

            _cuptiActive = true;
            CudaDiagnostics.LogInfo("CUPTI GPU profiler initialized successfully");
        }
        catch (DllNotFoundException ex)
        {
            var missing = CudaLibraryLoader.CheckAvailableLibraries();
            CudaDiagnostics.LogError(
                $"CUPTI initialization failed. Missing DLLs: {string.Join(", ", missing)}",
                ex);
            FreeCuptiHandles();
        }
        catch (Exception ex)
        {
            CudaDiagnostics.LogError("Unexpected error during CUPTI initialization", ex);
            FreeCuptiHandles();
        }
    }

    private void AllocBuffer(out IntPtr buffer, out uint size, out uint maxNumRecords)
    {
        buffer = _bufferPin.IsAllocated ? _bufferPin.AddrOfPinnedObject() : IntPtr.Zero;
        size = BufferSizeBytes;
        maxNumRecords = 0; // no limit
    }

    private void ProcessBuffer(IntPtr buffer, uint size, uint validSize)
    {
        if (validSize == 0) return;
        var count = 0;
        while (cuptiActivityGetNextRecord(buffer, validSize, out var record) == CuptiResult.CUPTI_SUCCESS)
        {
            // All CUPTI activity records start with a CuptiActivityKind field (uint32 at offset 0)
            if ((CuptiActivityKind)Marshal.ReadInt32(record) == CuptiActivityKind.CUPTI_ACTIVITY_KIND_KERNEL)
                count++;
        }
        if (count > 0)
            Interlocked.Add(ref _pendingKernelCount, count);
    }

    public uint GetActiveKernelCount()
    {
        if (!_cuptiActive) return 0;
        try { cuptiActivityFlushAll(0); } catch { }
        return (uint)Interlocked.Exchange(ref _pendingKernelCount, 0);
    }

    public double GetCoreUtilization()
    {
        if (!_nvmlInitialized || _gpuHandle == IntPtr.Zero) return 0;
        try
        {
            if (nvmlDeviceGetUtilizationRates(_gpuHandle, out var util) == 0)
                return util.gpu;
        }
        catch { }
        return 0;
    }

    public void Dispose()
    {
        if (_cuptiActive)
        {
            try { cuptiActivityDisable(CuptiActivityKind.CUPTI_ACTIVITY_KIND_KERNEL); } catch { }
            try { cuptiActivityFlushAll(0); } catch { }
        }
        FreeCuptiHandles();
        if (_nvmlInitialized)
            try { nvmlShutdown(); } catch { }
    }

    private void FreeCuptiHandles()
    {
        if (_bufferPin.IsAllocated) _bufferPin.Free();
        if (_allocCallbackPin.IsAllocated) _allocCallbackPin.Free();
        if (_processCallbackPin.IsAllocated) _processCallbackPin.Free();
    }
}
