using System.Runtime.InteropServices;

namespace VaultGuardian.Core.Firewall.Wfp;

/// <summary>
/// Raw P/Invoke surface for the user-mode Windows Filtering Platform management
/// API (<c>fwpuclnt.dll</c>).
///
/// Scope note: everything here operates at the ALE authorization layers, which
/// permit/block whole <em>connections</em>. Per-packet inspection or modification
/// requires a kernel-mode callout driver and is deliberately out of scope.
///
/// Struct layouts intentionally omit manual padding: <see cref="LayoutKind.Sequential"/>
/// with default packing applies natural alignment, which produces the correct
/// layout on both 32-bit and 64-bit without arch-specific branches.
/// </summary>
internal static class WfpInterop
{
    private const string Fwpuclnt = "fwpuclnt.dll";

    // ---- Status codes -----------------------------------------------------

    public const uint ERROR_SUCCESS = 0;

    // FwpmGetAppIdFromFileName0 reports a missing executable with plain Win32
    // codes rather than an FWP_E_* value.
    public const uint ERROR_FILE_NOT_FOUND = 2;
    public const uint ERROR_PATH_NOT_FOUND = 3;

    public const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    public const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
    public const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    public const uint FWP_E_NOT_FOUND = 0x80320008;
    public const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    public const uint FWP_E_IN_USE = 0x8032000A;

    // ---- Flags ------------------------------------------------------------

    public const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;
    public const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;
    public const uint FWPM_FILTER_FLAG_NONE = 0x00000000;
    public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;

    public const uint RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF;
    public const uint RPC_C_AUTHN_WINNT = 10;

    public const byte IPPROTO_TCP = 6;
    public const byte IPPROTO_UDP = 17;

    // ---- Enums ------------------------------------------------------------

    public enum FWP_DATA_TYPE : uint
    {
        FWP_EMPTY = 0,
        FWP_UINT8 = 1,
        FWP_UINT16 = 2,
        FWP_UINT32 = 3,
        FWP_UINT64 = 4,
        FWP_BYTE_ARRAY16_TYPE = 11,
        FWP_BYTE_BLOB_TYPE = 12,
        FWP_V4_ADDR_MASK = 0x100,
        FWP_V6_ADDR_MASK = 0x101,
    }

    public enum FWP_MATCH_TYPE : uint
    {
        FWP_MATCH_EQUAL = 0,
    }

    public enum FWP_ACTION_TYPE : uint
    {
        FWP_ACTION_BLOCK = 0x00001001,  // 0x1 | FWP_ACTION_FLAG_TERMINATING
        FWP_ACTION_PERMIT = 0x00001002, // 0x2 | FWP_ACTION_FLAG_TERMINATING
    }

    // ---- Well-known GUIDs -------------------------------------------------

    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
        new("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    public static readonly Guid FWPM_LAYER_ALE_AUTH_CONNECT_V6 =
        new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    public static readonly Guid FWPM_CONDITION_ALE_APP_ID =
        new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    public static readonly Guid FWPM_CONDITION_IP_REMOTE_ADDRESS =
        new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

    public static readonly Guid FWPM_CONDITION_IP_REMOTE_PORT =
        new("c35a604d-d22b-4e1a-91b4-68f674ee674b");

    public static readonly Guid FWPM_CONDITION_IP_PROTOCOL =
        new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");

    // ---- VaultGuardian identity -------------------------------------------
    // Every object we register carries this provider key, so cleanup never has
    // to guess which filters are ours.

    public static readonly Guid VaultGuardianProviderKey =
        new("8f4a5e21-3c7d-4b96-a1e8-5d2f9c6b7a03");

    public static readonly Guid VaultGuardianSubLayerKey =
        new("2b6d9c14-7e58-4a3f-b0c9-6e1d8f4a2537");

    // ---- Structs ----------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_DISPLAY_DATA0
    {
        public nint name;        // wchar_t*
        public nint description; // wchar_t*
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_BYTE_BLOB
    {
        public uint size;
        public nint data; // UINT8*
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_SESSION0
    {
        public Guid sessionKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint txnWaitTimeoutInMSec;
        public uint processId;
        public nint sid;         // SID*
        public nint username;    // wchar_t*
        public int kernelMode;   // BOOL
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_PROVIDER0
    {
        public Guid providerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public FWP_BYTE_BLOB providerData;
        public nint serviceName; // wchar_t*
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public nint providerKey; // GUID*
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    /// <summary>
    /// Union-bearing value. The union's widest member is pointer-sized, so a
    /// single <c>nint</c> covers it: small integral values sit in the low bytes
    /// (little-endian), wider values are stored as a pointer.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_VALUE0
    {
        public FWP_DATA_TYPE type;
        public nint value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_CONDITION_VALUE0
    {
        public FWP_DATA_TYPE type;
        public nint value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_FILTER_CONDITION0
    {
        public Guid fieldKey;
        public FWP_MATCH_TYPE matchType;
        public FWP_CONDITION_VALUE0 conditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_ACTION0
    {
        public FWP_ACTION_TYPE type;
        public Guid filterOrCalloutKey; // union { GUID filterType; GUID calloutKey; }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public nint providerKey; // GUID*
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public nint filterCondition; // FWPM_FILTER_CONDITION0*
        public FWPM_ACTION0 action;
        // union { UINT64 rawContext; GUID providerContextKey; } — GUID is widest.
        public Guid providerContextKey;
        public nint reserved;    // GUID*
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWP_V4_ADDR_AND_MASK
    {
        public uint addr; // host byte order
        public uint mask; // host byte order
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct FWP_V6_ADDR_AND_MASK
    {
        public fixed byte addr[16];
        public byte prefixLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FWPM_FILTER_ENUM_TEMPLATE0
    {
        public nint providerKey; // GUID*
        public Guid layerKey;
        public uint enumType;    // FWP_FILTER_ENUM_FULLY_CONTAINED = 0
        public uint flags;
        public nint providerContextTemplate;
        public uint numFilterConditions;
        public nint filterCondition;
        public uint actionMask;
        public nint calloutKey;  // GUID*
    }

    // ---- Engine -----------------------------------------------------------

    [DllImport(Fwpuclnt, ExactSpelling = true, CharSet = CharSet.Unicode)]
    public static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        uint authnService,
        nint authIdentity,
        nint session,
        out nint engineHandle);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmEngineClose0(nint engineHandle);

    // ---- Transactions -----------------------------------------------------

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmTransactionBegin0(nint engineHandle, uint flags);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmTransactionCommit0(nint engineHandle);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmTransactionAbort0(nint engineHandle);

    // ---- Provider / sublayer ----------------------------------------------

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmProviderAdd0(nint engineHandle, nint provider, nint sd);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmProviderDeleteByKey0(nint engineHandle, in Guid key);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmSubLayerAdd0(nint engineHandle, nint subLayer, nint sd);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmSubLayerDeleteByKey0(nint engineHandle, in Guid key);

    // ---- Filters ----------------------------------------------------------

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmFilterAdd0(nint engineHandle, nint filter, nint sd, out ulong id);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmFilterDeleteById0(nint engineHandle, ulong id);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmFilterCreateEnumHandle0(
        nint engineHandle, nint enumTemplate, out nint enumHandle);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmFilterEnum0(
        nint engineHandle,
        nint enumHandle,
        uint numEntriesRequested,
        out nint entries,
        out uint numEntriesReturned);

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern uint FwpmFilterDestroyEnumHandle0(nint engineHandle, nint enumHandle);

    // ---- Helpers ----------------------------------------------------------

    [DllImport(Fwpuclnt, ExactSpelling = true, CharSet = CharSet.Unicode)]
    public static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName,
        out nint appId); // FWP_BYTE_BLOB**

    [DllImport(Fwpuclnt, ExactSpelling = true)]
    public static extern void FwpmFreeMemory0(ref nint p);
}

/// <summary>
/// Raised when one filter cannot be expressed on this machine right now — most
/// often because the rule names an executable that is not installed. This is a
/// per-filter condition, not a batch failure: the applier logs it and carries on
/// with the remaining rules.
/// </summary>
public sealed class WfpFilterNotApplicableException : Exception
{
    public string RuleName { get; }

    public WfpFilterNotApplicableException(string ruleName, string message)
        : base(message)
    {
        RuleName = ruleName;
    }
}

/// <summary>Thrown when a WFP management call returns a non-success code.</summary>
public sealed class WfpException : Exception
{
    public uint ErrorCode { get; }

    public WfpException(string operation, uint errorCode)
        : base($"WFP call '{operation}' failed with 0x{errorCode:X8}{Describe(errorCode)}")
    {
        ErrorCode = errorCode;
    }

    private static string Describe(uint code) => code switch
    {
        0x80320009 => " (FWP_E_ALREADY_EXISTS)",
        0x80320008 => " (FWP_E_NOT_FOUND)",
        0x80320007 => " (FWP_E_SUBLAYER_NOT_FOUND)",
        0x80320005 => " (FWP_E_PROVIDER_NOT_FOUND)",
        0x80320003 => " (FWP_E_FILTER_NOT_FOUND)",
        0x8032000A => " (FWP_E_IN_USE)",
        5 => " (ERROR_ACCESS_DENIED — VaultGuardian must run as Administrator)",
        _ => string.Empty,
    };
}
