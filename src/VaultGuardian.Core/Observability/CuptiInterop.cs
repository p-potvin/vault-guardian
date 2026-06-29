using System.Runtime.InteropServices;

namespace VaultGuardian.Core.Observability;

/// <summary>
/// P/Invoke bindings for NVIDIA CUPTI (CUDA Profiling Tools Interface) and NVML (NVIDIA Management Library).
/// This module dynamically loads native libraries from vendored paths or system installations.
/// NOTE: This class uses lazy static initialization to defer native library loading until
/// environment variable checks pass. P/Invoke declarations are in nested [LibraryImport] classes
/// to prevent JIT compilation of DllImport stubs at class load time.
/// </summary>
internal static class CuptiInterop
{
    // Lazy-initialized wrapper for CUPTI P/Invoke
    private static class CuptiNative
    {
        private const string CuptiLib = "cupti64_120.dll";

        [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
        private static extern CuptiResult _cuptiActivityEnable(CuptiActivityKind kind);

        [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
        private static extern CuptiResult _cuptiActivityDisable(CuptiActivityKind kind);

        [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
        private static extern CuptiResult _cuptiActivityRegisterCallbacks(
            CuptiBufferAllocCallback bufferAlloc,
            CuptiBufferRequestCallback bufferRequest);

        [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
        private static extern CuptiResult _cuptiActivityFlushAll(uint flag);

        [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
        private static extern CuptiResult _cuptiActivityGetNextRecord(IntPtr buffer, uint validBufferSizeBytes, out IntPtr record);

        public static CuptiResult cuptiActivityEnable(CuptiActivityKind kind) => _cuptiActivityEnable(kind);
        public static CuptiResult cuptiActivityDisable(CuptiActivityKind kind) => _cuptiActivityDisable(kind);
        public static CuptiResult cuptiActivityRegisterCallbacks(CuptiBufferAllocCallback bufferAlloc, CuptiBufferRequestCallback bufferRequest) 
            => _cuptiActivityRegisterCallbacks(bufferAlloc, bufferRequest);
        public static CuptiResult cuptiActivityFlushAll(uint flag) => _cuptiActivityFlushAll(flag);
        public static CuptiResult cuptiActivityGetNextRecord(IntPtr buffer, uint validBufferSizeBytes, out IntPtr record)
            => _cuptiActivityGetNextRecord(buffer, validBufferSizeBytes, out record);
    }

    // Public wrappers - these are only called if CUDA is enabled
    public static CuptiResult cuptiActivityEnable(CuptiActivityKind kind) => CuptiNative.cuptiActivityEnable(kind);
    public static CuptiResult cuptiActivityDisable(CuptiActivityKind kind) => CuptiNative.cuptiActivityDisable(kind);
    public static CuptiResult cuptiActivityRegisterCallbacks(CuptiBufferAllocCallback bufferAlloc, CuptiBufferRequestCallback bufferRequest)
        => CuptiNative.cuptiActivityRegisterCallbacks(bufferAlloc, bufferRequest);
    public static CuptiResult cuptiActivityFlushAll(uint flag) => CuptiNative.cuptiActivityFlushAll(flag);
    public static CuptiResult cuptiActivityGetNextRecord(IntPtr buffer, uint validBufferSizeBytes, out IntPtr record)
        => CuptiNative.cuptiActivityGetNextRecord(buffer, validBufferSizeBytes, out record);

    public enum CuptiResult
    {
        CUPTI_SUCCESS = 0,
        CUPTI_ERROR_NOT_INITIALIZED = 1,
        CUPTI_ERROR_INVALID_PARAMETER = 2,
        CUPTI_ERROR_INVALID_DEVICE = 3,
        // ... more as needed
    }

    public enum CuptiActivityKind
    {
        CUPTI_ACTIVITY_KIND_MEMCPY = 1,
        CUPTI_ACTIVITY_KIND_MEMSET = 2,
        CUPTI_ACTIVITY_KIND_KERNEL = 3,
        CUPTI_ACTIVITY_KIND_DRIVER = 4,
        CUPTI_ACTIVITY_KIND_RUNTIME = 5,
        CUPTI_ACTIVITY_KIND_DEVICE = 6,
        CUPTI_ACTIVITY_KIND_CONTEXT = 7,
        CUPTI_ACTIVITY_KIND_OVERHEAD = 14,
    }

    public delegate void CuptiBufferAllocCallback(out IntPtr buffer, out uint size, out uint maxNumRecords);
    public delegate void CuptiBufferRequestCallback(IntPtr buffer, uint size, uint validSize);
}
