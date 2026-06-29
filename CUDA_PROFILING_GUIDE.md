# CUDA Profiling Guide

## Overview

VaultGuardian includes optional GPU profiling via NVIDIA CUPTI and NVML, but it is **disabled by default** to ensure stability and avoid native library loading issues.

## Enabling CUDA Profiling

To enable GPU profiling, set the environment variable before launching the application:

### Windows (PowerShell)
```powershell
$env:VAULTGUARDIAN_CUDA_ENABLED = "1"
.\VaultGuardian.UI.exe
```

### Windows (Command Prompt)
```cmd
set VAULTGUARDIAN_CUDA_ENABLED=1
VaultGuardian.UI.exe
```

### Windows (System Environment Variable - Persistent)
1. Open **System Properties** → **Environment Variables**
2. Click **New** under User variables or System variables
3. Variable name: `VAULTGUARDIAN_CUDA_ENABLED`
4. Variable value: `1`
5. Click **OK** and restart your application

## What Gets Enabled

When `VAULTGUARDIAN_CUDA_ENABLED=1` is set:

- **NVML initialization**: GPU utilization monitoring via NVIDIA Management Library
- **CUPTI profiling**: GPU kernel execution tracking
- **Dynamic library resolution**: Vendored CUDA DLLs are loaded from `libs/cuda/bin/x64/`

## What Gets Disabled (Default)

When the environment variable is NOT set or empty:

- No native CUDA libraries are loaded
- No GPU profiling happens
- The application runs with minimal native interop
- This avoids potential heap corruption or native initialization issues

## Troubleshooting

### "CUDA library loader initialization failed"
- Ensure CUDA binaries exist in `libs/cuda/bin/x64/`
- Check that `VAULTGUARDIAN_CUDA_ENABLED=1` is properly set
- Review debug output for missing DLL names

### "NVML not initialized; GPU profiling unavailable"
- NVIDIA GPU drivers may not be installed or updated
- The system may not have NVIDIA hardware
- This is expected and not an error; the app will function normally without GPU profiling

### "CUPTI activity registration failed"
- Check NVIDIA driver version compatibility
- Verify CUDA toolkit binaries are present in `libs/cuda/bin/x64/`
- Review diagnostic logs via `CudaDiagnostics`

## Debug Output

When CUDA profiling is enabled, you'll see startup messages in the debug output:
- `CUPTI GPU profiler initialized successfully` → Profiling is active
- `NVML not initialized; GPU profiling unavailable` → GPU driver issue
- `CUDA profiler disabled (set VAULTGUARDIAN_CUDA_ENABLED=1 to enable)` → Feature is off (default)

## Vendored CUDA Binaries

The repository includes vendored CUDA DLLs in `libs/cuda/bin/x64/`:
- `cudart64_12.dll` - CUDA Runtime
- `cupti64_120.dll` - CUDA Profiling Tools Interface (NVIDIA driver v12.0)
- `cupti64_118.dll` - CUDA Profiling Tools Interface (NVIDIA driver v11.8)
- `nvml.dll` - NVIDIA Management Library

These are automatically copied to the build output directory and resolved at runtime when profiling is enabled.

## Architecture

```
CudaProfiler (GPU kernel counting, core utilization)
	↓
CudaLibraryLoader (DllImportResolver for dynamic loading)
	↓ (only if VAULTGUARDIAN_CUDA_ENABLED=1)
libs/cuda/bin/x64/ (vendored DLLs)
	↓
NVML / CUPTI (native Windows CUDA libraries)
```

## Performance Notes

- CUDA profiling adds minimal overhead when enabled
- Disabling it (default) has zero performance impact
- GPU utilization queries are fast O(1) operations
- Kernel counting uses a pinned memory buffer (4 MB)
