using System.Runtime.InteropServices;
using VaultGuardian.Core.Firewall.Wfp;

namespace VaultGuardian.Core.Tests;

/// <summary>
/// Pins the memory layout of the WFP interop structs against the Windows SDK
/// headers (<c>shared/fwptypes.h</c>, <c>shared/fwpmtypes.h</c>).
///
/// A wrong field offset here does not fail to compile and does not throw — it
/// silently reads garbage, which for <c>FWPM_FILTER0.filterId</c> means deleting
/// arbitrary filters or failing to reclaim our own. These assertions are the only
/// automated guard on that, since exercising the real API needs an elevated host.
/// </summary>
public class WfpInteropLayoutTests
{
    private static bool Is64Bit => nint.Size == 8;

    // FWPM_FILTER0 as declared in fwpmtypes.h, laid out for a 64-bit process:
    //
    //   filterKey            GUID          0   .. 16
    //   displayData          2 pointers    16  .. 32
    //   flags                UINT32        32  .. 36   (+4 pad)
    //   providerKey          GUID*         40  .. 48
    //   providerData         FWP_BYTE_BLOB 48  .. 64
    //   layerKey             GUID          64  .. 80
    //   subLayerKey          GUID          80  .. 96
    //   weight               FWP_VALUE0    96  .. 112
    //   numFilterConditions  UINT32        112 .. 116  (+4 pad)
    //   filterCondition      ptr           120 .. 128
    //   action               FWPM_ACTION0  128 .. 148
    //   union{UINT64;GUID}                 152 .. 168  (8-aligned by UINT64 arm)
    //   reserved             GUID*         168 .. 176
    //   filterId             UINT64        176 .. 184
    //   effectiveWeight      FWP_VALUE0    184 .. 200
    private const int ExpectedFilterSize = 200;
    private const int ExpectedFilterIdOffset = 176;

    [Fact]
    public void FwpmFilter0_MatchesSdkLayout()
    {
        if (!Is64Bit) return;

        Assert.Equal(ExpectedFilterSize, Marshal.SizeOf<WfpInterop.FWPM_FILTER0>());
        Assert.Equal(64, (int)Marshal.OffsetOf<WfpInterop.FWPM_FILTER0>(nameof(WfpInterop.FWPM_FILTER0.layerKey)));
        Assert.Equal(96, (int)Marshal.OffsetOf<WfpInterop.FWPM_FILTER0>(nameof(WfpInterop.FWPM_FILTER0.weight)));
        Assert.Equal(128, (int)Marshal.OffsetOf<WfpInterop.FWPM_FILTER0>(nameof(WfpInterop.FWPM_FILTER0.action)));
    }

    [Fact]
    public void FwpmFilter0_FilterIdSitsWhereTheSdkPutsIt()
    {
        if (!Is64Bit) return;

        // The union arm is `GUID providerContextKey` by value (fwpmtypes.h line 502),
        // not `GUID*`. Modelling it as a pointer-sized field would shift filterId
        // 8 bytes low and silently corrupt enumeration and deletion.
        Assert.Equal(
            ExpectedFilterIdOffset,
            (int)Marshal.OffsetOf<WfpInterop.FWPM_FILTER0>(nameof(WfpInterop.FWPM_FILTER0.filterId)));
    }

    [Fact]
    public void FwpValue0_UnionIsPointerSizedAndFollowsTypeTag()
    {
        // Widest arm is UINT64* so the union is pointer-sized; small values live
        // inline in its low bytes on little-endian.
        Assert.Equal(nint.Size == 8 ? 16 : 8, Marshal.SizeOf<WfpInterop.FWP_VALUE0>());
        Assert.Equal(nint.Size, (int)Marshal.OffsetOf<WfpInterop.FWP_VALUE0>(nameof(WfpInterop.FWP_VALUE0.value)));

        Assert.Equal(
            Marshal.SizeOf<WfpInterop.FWP_VALUE0>(),
            Marshal.SizeOf<WfpInterop.FWP_CONDITION_VALUE0>());
    }

    [Fact]
    public void FwpmFilterCondition0_MatchesSdkLayout()
    {
        if (!Is64Bit) return;

        // GUID(16) + FWP_MATCH_TYPE(4) + pad(4) + FWP_CONDITION_VALUE0(16)
        Assert.Equal(40, Marshal.SizeOf<WfpInterop.FWPM_FILTER_CONDITION0>());
        Assert.Equal(
            24,
            (int)Marshal.OffsetOf<WfpInterop.FWPM_FILTER_CONDITION0>(
                nameof(WfpInterop.FWPM_FILTER_CONDITION0.conditionValue)));
    }

    [Fact]
    public void FwpByteBlob_MatchesSdkLayout()
    {
        if (!Is64Bit) return;

        Assert.Equal(16, Marshal.SizeOf<WfpInterop.FWP_BYTE_BLOB>());
        Assert.Equal(8, (int)Marshal.OffsetOf<WfpInterop.FWP_BYTE_BLOB>(nameof(WfpInterop.FWP_BYTE_BLOB.data)));
    }

    [Fact]
    public void FwpmAction0_CarriesGuidByValue()
    {
        // FWP_ACTION_TYPE(4) + GUID(16), GUID aligns to 4 so no padding.
        Assert.Equal(20, Marshal.SizeOf<WfpInterop.FWPM_ACTION0>());
    }

    [Fact]
    public void AddressMaskStructs_MatchSdkSizes()
    {
        Assert.Equal(8, Marshal.SizeOf<WfpInterop.FWP_V4_ADDR_AND_MASK>());

        // 16 address bytes plus a prefix byte, no tail padding — this is why the
        // engine allocates exactly 17 bytes for the IPv6 mask condition.
        Assert.Equal(17, Marshal.SizeOf<WfpInterop.FWP_V6_ADDR_AND_MASK>());
    }

    [Fact]
    public void FwpmSubLayer0_WeightIsTheFinalField()
    {
        if (!Is64Bit) return;

        // subLayerKey(16) displayData(16) flags(4)+pad(4) providerKey(8)
        // providerData(16) weight(2)
        Assert.Equal(
            64,
            (int)Marshal.OffsetOf<WfpInterop.FWPM_SUBLAYER0>(nameof(WfpInterop.FWPM_SUBLAYER0.weight)));
    }

    [Fact]
    public void FwpmSession0_PointerFieldsAreAligned()
    {
        if (!Is64Bit) return;

        // sessionKey(16) displayData(16) flags(4) txnWaitTimeout(4) processId(4)+pad(4) sid
        Assert.Equal(48, (int)Marshal.OffsetOf<WfpInterop.FWPM_SESSION0>(nameof(WfpInterop.FWPM_SESSION0.sid)));
    }
}
