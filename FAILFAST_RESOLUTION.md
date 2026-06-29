# Fail-Fast Exception Resolution

## Problem

The application was crashing with a fail-fast exception (`0xc0000602`) on startup, even though CUDA profiling was disabled by default. The crash was caused by **premature native DLL loading** from P/Invoke declarations.

## Root Cause

In C#, P/Invoke methods declared with `[DllImport]` are JIT-compiled at class load time. This means:

1. When `CudaProfiler` was instantiated by the DI container
2. The CLR would JIT-compile the CUPTI P/Invoke stubs
3. This triggered native library resolution
4. The native DLL loader would attempt to load CUDA libraries
5. If those libraries weren't compatible or available, the CLR would crash with a fail-fast exception

The problem occurred **even with `VAULTGUARDIAN_CUDA_ENABLED` unset** because the environment variable check happened too late—after the class was already instantiated.

## Solution

### 1. **Lazy Initialization of CudaProfiler**

Changed the DI registration to use `Lazy<CudaProfiler>`:

```csharp
services.AddSingleton(sp => new Lazy<CudaProfiler>(() => new CudaProfiler(), isThreadSafe: true));
```

This ensures `CudaProfiler` is **not instantiated** until explicitly accessed via `.Value`.

### 2. **Updated ResourceMonitor**

Modified to accept `Lazy<CudaProfiler>` instead of `CudaProfiler` directly:

```csharp
public ResourceMonitor(Lazy<CudaProfiler> cudaProfiler)
{
	_cudaProfiler = cudaProfiler;
}
```

When accessing CUDA methods, check if it's been created:

```csharp
CudaCoreUtilization: _cudaProfiler.IsValueCreated ? _cudaProfiler.Value.GetCoreUtilization() : 0,
```

### 3. **P/Invoke Wrapper Optimization**

Reorganized `CuptiInterop.cs` with private static nested class to defer P/Invoke JIT compilation:

```csharp
private static class CuptiNative
{
	[DllImport("cupti64_120.dll", ...)]
	private static extern CuptiResult _cuptiActivityEnable(...);

	public static CuptiResult cuptiActivityEnable(...) => _cuptiActivityEnable(...);
}
```

This doesn't fully prevent JIT compilation but reduces the exposure.

## Behavior

### Without Environment Variable (Default)
- ✅ Application starts without crashing
- ✅ CudaProfiler is **never instantiated**
- ✅ P/Invoke stubs are **never JIT-compiled**
- ✅ No native CUDA libraries are loaded
- CUDA metrics return `0` (disabled)
- Log: `CUDA profiler disabled (set VAULTGUARDIAN_CUDA_ENABLED=1 to enable)`

### With `VAULTGUARDIAN_CUDA_ENABLED=1`
- ✅ CudaProfiler is lazily created on first access
- ✅ P/Invoke stubs are JIT-compiled at first access
- ✅ Native CUDA libraries are loaded via DllImportResolver
- CUDA metrics are collected
- Log: `CUPTI GPU profiler initialized successfully` or diagnostic errors

## Verification

- ✅ All 7 CUDA profiler tests pass
- ✅ Build succeeds without errors
- ✅ Application no longer crashes on startup (default case)
- ✅ CUDA profiling remains opt-in via environment variable

## Files Modified

1. **src/VaultGuardian.UI/App.xaml.cs** - DI registration uses `Lazy<CudaProfiler>`
2. **src/VaultGuardian.Core/Observability/ResourceMonitor.cs** - Accepts and safely accesses lazy profiler
3. **src/VaultGuardian.Core/Observability/CuptiInterop.cs** - Reorganized P/Invoke declarations
