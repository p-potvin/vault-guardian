using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using static VaultGuardian.Core.Firewall.Wfp.WfpInterop;

namespace VaultGuardian.Core.Firewall.Wfp;

/// <summary>
/// Live implementation over <c>fwpuclnt.dll</c>.
///
/// Two engine handles are held deliberately:
/// <list type="bullet">
/// <item><b>Dynamic</b> — opened with FWPM_SESSION_FLAG_DYNAMIC. Filters added here
/// are destroyed by the OS the moment the handle closes, including on a hard
/// process crash. This is what makes session rules genuinely self-cleaning.</item>
/// <item><b>Persistent</b> — a normal session. Filters added here carry
/// FWPM_FILTER_FLAG_PERSISTENT and survive reboot, so they need explicit cleanup.</item>
/// </list>
/// </summary>
public sealed class WfpEngine : IWfpEngine
{
    private const string ProviderName = "VaultGuardian";
    private const string ProviderDescription = "VaultGuardian egress policy provider";
    private const string SubLayerName = "VaultGuardian egress sublayer";

    // Sits above the default sublayer weight so our decisions are evaluated early,
    // while still leaving room for higher-priority system sublayers.
    private const ushort SubLayerWeight = 0x8000;

    private readonly ILogger<WfpEngine> _logger;
    private nint _dynamicHandle;
    private nint _persistentHandle;

    public WfpEngine(ILogger<WfpEngine> logger) => _logger = logger;

    public bool IsOpen => _dynamicHandle != nint.Zero && _persistentHandle != nint.Zero;

    public void Open()
    {
        if (IsOpen) return;

        try
        {
            _persistentHandle = OpenEngine(dynamicSession: false);
            _dynamicHandle = OpenEngine(dynamicSession: true);
            EnsureProviderAndSubLayer();
            _logger.LogInformation("WFP filter engine opened (provider {Provider})", VaultGuardianProviderKey);
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    private static nint OpenEngine(bool dynamicSession)
    {
        nint sessionPtr = nint.Zero;
        try
        {
            if (dynamicSession)
            {
                var session = new FWPM_SESSION0 { flags = FWPM_SESSION_FLAG_DYNAMIC };
                sessionPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FWPM_SESSION0>());
                Marshal.StructureToPtr(session, sessionPtr, fDeleteOld: false);
            }

            var status = FwpmEngineOpen0(
                serverName: null,
                authnService: RPC_C_AUTHN_WINNT,
                authIdentity: nint.Zero,
                session: sessionPtr,
                out var handle);

            if (status != ERROR_SUCCESS) throw new WfpException(nameof(FwpmEngineOpen0), status);
            return handle;
        }
        finally
        {
            if (sessionPtr != nint.Zero) Marshal.FreeHGlobal(sessionPtr);
        }
    }

    /// <summary>
    /// Registers the provider and sublayer as persistent objects, inside a
    /// transaction so a partial registration can never be observed. Both are
    /// idempotent: FWP_E_ALREADY_EXISTS is the expected result on every run
    /// after the first.
    /// </summary>
    private void EnsureProviderAndSubLayer()
    {
        var status = FwpmTransactionBegin0(_persistentHandle, 0);
        if (status != ERROR_SUCCESS) throw new WfpException(nameof(FwpmTransactionBegin0), status);

        using var scope = new NativeScope();
        try
        {
            var provider = new FWPM_PROVIDER0
            {
                providerKey = VaultGuardianProviderKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = scope.AllocString(ProviderName),
                    description = scope.AllocString(ProviderDescription),
                },
                flags = FWPM_PROVIDER_FLAG_PERSISTENT,
            };

            var addProvider = FwpmProviderAdd0(_persistentHandle, scope.AllocStruct(provider), nint.Zero);
            if (addProvider != ERROR_SUCCESS && addProvider != FWP_E_ALREADY_EXISTS)
                throw new WfpException(nameof(FwpmProviderAdd0), addProvider);

            var subLayer = new FWPM_SUBLAYER0
            {
                subLayerKey = VaultGuardianSubLayerKey,
                displayData = new FWPM_DISPLAY_DATA0
                {
                    name = scope.AllocString(SubLayerName),
                    description = scope.AllocString(ProviderDescription),
                },
                flags = FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey = scope.AllocStruct(VaultGuardianProviderKey),
                weight = SubLayerWeight,
            };

            var addSubLayer = FwpmSubLayerAdd0(_persistentHandle, scope.AllocStruct(subLayer), nint.Zero);
            if (addSubLayer != ERROR_SUCCESS && addSubLayer != FWP_E_ALREADY_EXISTS)
                throw new WfpException(nameof(FwpmSubLayerAdd0), addSubLayer);

            var commit = FwpmTransactionCommit0(_persistentHandle);
            if (commit != ERROR_SUCCESS) throw new WfpException(nameof(FwpmTransactionCommit0), commit);
        }
        catch
        {
            FwpmTransactionAbort0(_persistentHandle);
            throw;
        }
    }

    public ulong AddFilter(WfpFilterPlan plan)
    {
        EnsureOpen();

        if (plan.IsUnconditional)
        {
            // Defence in depth: the planner already refuses these, but an
            // unconditional terminating filter would take the whole machine
            // offline, so never let one reach the engine.
            throw new InvalidOperationException(
                $"Refusing to install unconditional WFP filter for rule '{plan.RuleName}'.");
        }

        var handle = plan.Persistent ? _persistentHandle : _dynamicHandle;

        using var scope = new NativeScope();
        var conditions = BuildConditions(plan, scope);

        var conditionsPtr = nint.Zero;
        if (conditions.Count > 0)
        {
            var stride = Marshal.SizeOf<FWPM_FILTER_CONDITION0>();
            conditionsPtr = scope.Alloc(stride * conditions.Count);
            for (var i = 0; i < conditions.Count; i++)
            {
                Marshal.StructureToPtr(conditions[i], conditionsPtr + (i * stride), fDeleteOld: false);
            }
        }

        var filter = new FWPM_FILTER0
        {
            filterKey = Guid.NewGuid(),
            displayData = new FWPM_DISPLAY_DATA0
            {
                name = scope.AllocString(plan.DisplayName),
                description = scope.AllocString($"VaultGuardian rule '{plan.RuleName}'"),
            },
            flags = plan.Persistent ? FWPM_FILTER_FLAG_PERSISTENT : FWPM_FILTER_FLAG_NONE,
            providerKey = scope.AllocStruct(VaultGuardianProviderKey),
            layerKey = plan.Family == WfpAddressFamily.IPv4
                ? FWPM_LAYER_ALE_AUTH_CONNECT_V4
                : FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            subLayerKey = VaultGuardianSubLayerKey,
            weight = new FWP_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_UINT64,
                value = scope.AllocStruct(plan.Weight),
            },
            numFilterConditions = (uint)conditions.Count,
            filterCondition = conditionsPtr,
            action = new FWPM_ACTION0
            {
                type = plan.Action == WfpFilterAction.Block
                    ? FWP_ACTION_TYPE.FWP_ACTION_BLOCK
                    : FWP_ACTION_TYPE.FWP_ACTION_PERMIT,
            },
        };

        var status = FwpmFilterAdd0(handle, scope.AllocStruct(filter), nint.Zero, out var id);
        if (status != ERROR_SUCCESS) throw new WfpException(nameof(FwpmFilterAdd0), status);

        return id;
    }

    private static List<FWPM_FILTER_CONDITION0> BuildConditions(WfpFilterPlan plan, NativeScope scope)
    {
        var conditions = new List<FWPM_FILTER_CONDITION0>(4);

        if (plan.AppPath is { } appPath)
        {
            var status = FwpmGetAppIdFromFileName0(appPath, out var appIdPtr);

            // Resolving an app id requires the file to exist on disk. A rule that
            // names an uninstalled program must not abort the whole batch — it is
            // simply not expressible right now, and an absent program cannot
            // originate traffic anyway.
            if (status is ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND)
            {
                throw new WfpFilterNotApplicableException(
                    plan.RuleName,
                    $"Executable '{appPath}' was not found, so no application filter could be installed for rule '{plan.RuleName}'.");
            }

            if (status != ERROR_SUCCESS) throw new WfpException($"{nameof(FwpmGetAppIdFromFileName0)}('{appPath}')", status);
            scope.TrackFwpmMemory(appIdPtr);

            conditions.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_ALE_APP_ID,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_BYTE_BLOB_TYPE,
                    value = appIdPtr,
                },
            });
        }

        if (plan.RemoteAddress is { } address)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = BuildAddressValue(address, scope),
            });
        }

        if (plan.RemotePort is { } port)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_IP_REMOTE_PORT,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT16,
                    value = port, // small values live inline in the union
                },
            });
        }

        if (plan.IpProtocol is { } protocol)
        {
            conditions.Add(new FWPM_FILTER_CONDITION0
            {
                fieldKey = FWPM_CONDITION_IP_PROTOCOL,
                matchType = FWP_MATCH_TYPE.FWP_MATCH_EQUAL,
                conditionValue = new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT8,
                    value = protocol,
                },
            });
        }

        return conditions;
    }

    private static FWP_CONDITION_VALUE0 BuildAddressValue(WfpAddressMatch address, NativeScope scope)
    {
        if (address.Family == WfpAddressFamily.IPv4)
        {
            // WFP takes IPv4 as a host-order UINT32; GetAddressBytes is network order.
            var value = BinaryPrimitives.ReadUInt32BigEndian(address.Address);

            if (address.PrefixLength is not { } prefix)
            {
                return new FWP_CONDITION_VALUE0
                {
                    type = FWP_DATA_TYPE.FWP_UINT32,
                    value = (nint)value,
                };
            }

            var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
            var addrAndMask = new FWP_V4_ADDR_AND_MASK { addr = value & mask, mask = mask };
            return new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_V4_ADDR_MASK,
                value = scope.AllocStruct(addrAndMask),
            };
        }

        if (address.PrefixLength is not { } prefix6)
        {
            var raw = scope.Alloc(16);
            Marshal.Copy(address.Address, 0, raw, 16);
            return new FWP_CONDITION_VALUE0
            {
                type = FWP_DATA_TYPE.FWP_BYTE_ARRAY16_TYPE,
                value = raw,
            };
        }

        // FWP_V6_ADDR_AND_MASK: 16 address bytes (network order) then a prefix byte.
        var v6 = scope.Alloc(17);
        Marshal.Copy(address.Address, 0, v6, 16);
        Marshal.WriteByte(v6, 16, (byte)prefix6);
        return new FWP_CONDITION_VALUE0
        {
            type = FWP_DATA_TYPE.FWP_V6_ADDR_MASK,
            value = v6,
        };
    }

    public void DeleteFilter(ulong filterId, bool persistent)
    {
        EnsureOpen();
        var handle = persistent ? _persistentHandle : _dynamicHandle;
        var status = FwpmFilterDeleteById0(handle, filterId);

        // Already gone is a success for our purposes.
        if (status is ERROR_SUCCESS or FWP_E_FILTER_NOT_FOUND or FWP_E_NOT_FOUND) return;
        throw new WfpException(nameof(FwpmFilterDeleteById0), status);
    }

    public int DeleteAllPersistentFilters()
    {
        EnsureOpen();

        var ids = new List<ulong>();
        foreach (var layer in new[] { FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6 })
        {
            ids.AddRange(EnumerateFilterIds(layer));
        }

        var removed = 0;
        foreach (var id in ids)
        {
            try
            {
                DeleteFilter(id, persistent: true);
                removed++;
            }
            catch (WfpException ex)
            {
                _logger.LogWarning(ex, "Could not delete stale WFP filter {FilterId}", id);
            }
        }

        return removed;
    }

    private List<ulong> EnumerateFilterIds(Guid layer)
    {
        var ids = new List<ulong>();
        using var scope = new NativeScope();

        var template = new FWPM_FILTER_ENUM_TEMPLATE0
        {
            providerKey = scope.AllocStruct(VaultGuardianProviderKey),
            layerKey = layer,
            enumType = 0, // FWP_FILTER_ENUM_FULLY_CONTAINED
            actionMask = 0xFFFFFFFF,
        };

        var status = FwpmFilterCreateEnumHandle0(
            _persistentHandle, scope.AllocStruct(template), out var enumHandle);
        if (status != ERROR_SUCCESS) throw new WfpException(nameof(FwpmFilterCreateEnumHandle0), status);

        try
        {
            const uint batch = 256;
            while (true)
            {
                var enumStatus = FwpmFilterEnum0(
                    _persistentHandle, enumHandle, batch, out var entries, out var returned);
                if (enumStatus != ERROR_SUCCESS) throw new WfpException(nameof(FwpmFilterEnum0), enumStatus);
                if (returned == 0)
                {
                    if (entries != nint.Zero) FwpmFreeMemory0(ref entries);
                    break;
                }

                try
                {
                    // entries is FWPM_FILTER0** — an array of pointers.
                    for (var i = 0; i < returned; i++)
                    {
                        var filterPtr = Marshal.ReadIntPtr(entries, i * nint.Size);
                        if (filterPtr == nint.Zero) continue;
                        ids.Add(Marshal.PtrToStructure<FWPM_FILTER0>(filterPtr).filterId);
                    }
                }
                finally
                {
                    FwpmFreeMemory0(ref entries);
                }

                if (returned < batch) break;
            }
        }
        finally
        {
            FwpmFilterDestroyEnumHandle0(_persistentHandle, enumHandle);
        }

        return ids;
    }

    private void EnsureOpen()
    {
        if (!IsOpen) throw new InvalidOperationException("WFP engine is not open. Call Open() first.");
    }

    public void Dispose()
    {
        // Closing the dynamic handle is what removes every session filter, so it
        // must happen even if the persistent close throws.
        if (_dynamicHandle != nint.Zero)
        {
            FwpmEngineClose0(_dynamicHandle);
            _dynamicHandle = nint.Zero;
        }

        if (_persistentHandle != nint.Zero)
        {
            FwpmEngineClose0(_persistentHandle);
            _persistentHandle = nint.Zero;
        }
    }

    /// <summary>
    /// Tracks native allocations for the duration of one call so every path —
    /// including the throwing ones — releases them exactly once.
    /// </summary>
    private sealed class NativeScope : IDisposable
    {
        private readonly List<nint> _hglobal = [];
        private readonly List<nint> _fwpmOwned = [];

        public nint Alloc(int byteCount)
        {
            var ptr = Marshal.AllocHGlobal(byteCount);
            _hglobal.Add(ptr);
            return ptr;
        }

        public nint AllocString(string value)
        {
            var ptr = Marshal.StringToHGlobalUni(value);
            _hglobal.Add(ptr);
            return ptr;
        }

        public nint AllocStruct<T>(T value) where T : struct
        {
            var ptr = Alloc(Marshal.SizeOf<T>());
            Marshal.StructureToPtr(value, ptr, fDeleteOld: false);
            return ptr;
        }

        /// <summary>Memory allocated by WFP itself, which must go back via FwpmFreeMemory0.</summary>
        public void TrackFwpmMemory(nint ptr) => _fwpmOwned.Add(ptr);

        public void Dispose()
        {
            foreach (var ptr in _hglobal) Marshal.FreeHGlobal(ptr);
            _hglobal.Clear();

            foreach (var ptr in _fwpmOwned)
            {
                var local = ptr;
                if (local != nint.Zero) FwpmFreeMemory0(ref local);
            }
            _fwpmOwned.Clear();
        }
    }
}
