# CUDA Integration - Crash Troubleshooting

## Issue

Application crash with exit code `0xc0000602` (STATUS_FAIL_FAST_EXCEPTION) when running the UI.

## Root Cause

The fail-fast exception occurs when:
1. `CudaProfiler` is instantiated as a DI singleton during app startup
2. Native DLL loading happens too early or with invalid memory state
3. The DllImportResolver or native CUDA initialization corrupts the heap

## Fixes Applied

### 1. Lazy Initialization
- Moved `CudaLibraryLoader.Initialize()` from static constructor to instance constructor
- This delays DLL resolution until after the app is more stable

### 2. Enhanced Error Handling
- Wrapped all DLL import calls in try-catch blocks
- Specific exception types (DllNotFoundException vs generic Exception)
- Graceful degradation when CUDA unavailable

### 3. Defensive Library Loader
- Made `Initialize()` method fault-tolerant
- Returns safely even if DLL resolution fails
- Catches and logs resolver setup failures

## Verification Steps

### 1. Run Tests
All unit tests should still pass:
```
dotnet test
```

Expected: 7/7 CUDA tests pass

### 2. Check Logs
When running the app, check:
- Visual Studio Output window (Debug > Windows > Output)
- Look for messages like:
  - "NVML not initialized; GPU profiling unavailable."
  - "CUPTI GPU profiler initialized successfully"
  - Or error messages if CUDA unavailable

### 3. Safe Fallback
If CudaProfiler initialization fails:
- `GetActiveKernelCount()` returns 0
- `GetCoreUtilization()` returns 0.0
- Application continues without GPU monitoring

## If Still Crashing

If the exit code `0xc0000602` still occurs, try these steps:

### Step 1: Disable CUDA Profiler
Comment out this line in `src/VaultGuardian.UI/App.xaml.cs`:

```csharp
// services.AddSingleton<CudaProfiler>();
```

Then build and run. If it works, the crash is definitely in CUDA integration.

### Step 2: Check DLL Compatibility
Verify binaries are correct:
```powershell
Get-ChildItem libs/cuda/bin/x64 -Filter "*.dll" | ForEach-Object {
	Write-Host "$($_.Name) - $($_.LastWriteTime)"
}
```

If binaries seem corrupted, re-copy from system:
```powershell
pwsh -ExecutionPolicy Bypass -File scripts/setup-cuda-binaries.ps1
```

### Step 3: Verify with Console App
Create a minimal test that doesn't use UI:

```csharp
// Program.cs
using VaultGuardian.Core.Observability;

try
{
	Console.WriteLine("Creating CudaProfiler...");
	var profiler = new CudaProfiler();
	Console.WriteLine($"✓ Success - Kernels: {profiler.GetActiveKernelCount()}");
	profiler.Dispose();
}
catch (Exception ex)
{
	Console.WriteLine($"✗ Failed: {ex}");
}
```

Run this before running the UI app to isolate the issue.

## Advanced Debugging

### Enable Debug Output
Add this to the UI app startup:

```csharp
System.Diagnostics.Debug.Listeners.Add(new System.Diagnostics.TextWriterTraceListener(System.Console.Out));
```

Then watch the console for error messages.

### Use Windows Debugger
Attach WinDbg or VS debugger with native debugging enabled to see the exact point of failure:

1. Debug > Attach to Process
2. Select VaultGuardian.UI.exe
3. Set "Debug Type" to "Mixed"
4. Check for stack traces in native code

### Check Event Log
Windows Application Event Log may contain more details:

```powershell
Get-EventLog -LogName Application -Source VaultGuardian -Newest 10
```

## Alternative Approach: No CUDA Resolver

If the DllImportResolver itself is causing issues, disable it:

In `CudaLibraryLoader.cs`, comment out the resolver registration:

```csharp
public static void Initialize()
{
	if (_resolverRegistered) return;

	try
	{
		// TEMPORARILY DISABLED - may cause fail-fast exception
		// NativeLibrary.SetDllImportResolver(typeof(CudaLibraryLoader).Assembly, ResolveCudaLibrary);
		_resolverRegistered = true;
	}
	catch (Exception ex)
	{
		System.Diagnostics.Debug.WriteLine($"Warning: Failed to set up DLL import resolver: {ex}");
		_resolverRegistered = true;
	}
}
```

This will fall back to system PATH for DLL resolution. CUDA binaries still need to be in `libs/cuda/bin/x64/` AND in the system PATH (or Windows\System32).

## Summary

The changes made prioritize stability:
- Lazy initialization prevents early crashes
- Comprehensive error handling maintains graceful degradation
- Tests verify functionality
- Fallback mechanisms ensure the app works without CUDA

If these changes don't resolve the crash, the issue likely stems from:
1. Incompatible CUDA version DLLs
2. Corrupted binary files
3. Platform-specific native code incompatibility
4. Missing CUDA runtime dependencies

In those cases, see "If Still Crashing" section above.
