using System.Runtime.InteropServices;

namespace VaultGuardian.Core.Observability;

internal static partial class CuptiInterop
{
    private const string CuptiLib = "cupti64_2024.1.0.dll"; // Note: Specific version might vary, usually path has it. 
    // In production, we'd search for the DLL or use a generic name if possible.

    [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern CuptiResult cuptiActivityEnable(CuptiActivityKind kind);

    [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern CuptiResult cuptiActivityDisable(CuptiActivityKind kind);

    [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern CuptiResult cuptiActivityRegisterCallbacks(
        CuptiBufferAllocCallback bufferAlloc,
        CuptiBufferRequestCallback bufferRequest);

    [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern CuptiResult cuptiActivityFlushAll(uint flag);

    [DllImport(CuptiLib, CallingConvention = CallingConvention.Cdecl)]
    public static extern CuptiResult cuptiActivityGetNextRecord(IntPtr buffer, uint validBufferSizeBytes, out IntPtr record);

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
