using System.Runtime.InteropServices;
using static VaultGuardian.Core.Observability.CuptiInterop;

namespace VaultGuardian.Core.Observability;

public sealed class CudaProfiler : IDisposable
{
    private const int BufferSizeBytes = 4 * 1024 * 1024; // 4 MB activity buffer

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
        try
        {
            if (nvmlInit() == 0)
            {
                _nvmlInitialized = true;
                if (nvmlDeviceGetHandleByIndex(0, out _gpuHandle) != 0)
                    _gpuHandle = IntPtr.Zero;
            }
        }
        catch { /* nvml.dll absent or driver not present */ }

        // CUPTI is only useful on NVIDIA hardware
        if (!_nvmlInitialized) return;

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
                return;
            }

            _cuptiActive = true;
        }
        catch
        {
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
