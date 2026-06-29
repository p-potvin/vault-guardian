# CUDA Toolkit Setup Guide

## Overview

This repository includes a local CUDA toolkit binary cache to ensure consistent GPU profiling capabilities across different environments. The application uses **vendored NVIDIA binaries** stored in `libs/cuda/bin/x64/` instead of relying on system-wide CUDA installation.

## What's Included

### Current Binaries

- **cupti64_120.dll** - CUDA Profiling Tools Interface for CUDA 12.0
- **cupti64_118.dll** - CUDA Profiling Tools Interface for CUDA 11.8 (fallback)
- **cudart64_12.dll** - CUDA Runtime Library
- **nvml.dll** - NVIDIA Management Library (GPU monitoring)

### Directory Structure

```
vault-guardian/
├── libs/
│   └── cuda/
│       └── bin/
│           └── x64/
│               ├── cudart64_12.dll
│               ├── cupti64_120.dll
│               ├── cupti64_118.dll
│               └── nvml.dll
└── src/
	└── VaultGuardian.Core/
		└── Observability/
			├── CudaProfiler.cs          # GPU profiler (uses CUPTI)
			├── CuptiInterop.cs          # P/Invoke definitions
			└── CudaLibraryLoader.cs     # Dynamic DLL resolution
```

## How It Works

### Dynamic Library Resolution

The application uses `CudaLibraryLoader` to resolve native library paths at runtime:

1. **Initialization**: `CudaProfiler` static constructor calls `CudaLibraryLoader.Initialize()`
2. **Registration**: Sets up `NativeLibrary.SetDllImportResolver` for the assembly
3. **Search Order**: Attempts to load DLLs in this priority order:
   - `AppContext.BaseDirectory/bin/x64/` (output directory from build)
   - `libs/cuda/bin/x64/` (repository vendored binaries)
   - Application directory
   - Standard CUDA installation paths (`C:\Program Files\NVIDIA...`)
   - Windows System32/SysWOW64

### Build Integration

The `.csproj` file is configured to automatically copy binaries:

```xml
<ItemGroup>
  <None Include="../../libs/cuda/bin/x64/*.dll" 
		Link="bin/x64/%(Filename)%(Extension)" 
		CopyToOutputDirectory="PreserveNewest" />
</ItemGroup>
```

This ensures binaries are copied to the output directory during each build.

## Setup Instructions

### Option 1: Use Existing System Installation (Recommended)

If you have CUDA toolkit installed on your system:

```powershell
# Navigate to repository root
cd C:\path\to\vault-guardian

# Run the setup script
pwsh -ExecutionPolicy Bypass -File scripts/setup-cuda-binaries.ps1
```

The script will:
1. Detect your CUDA installation
2. Copy required binaries to `libs/cuda/bin/x64/`
3. Verify the binaries are in place

### Option 2: Manual Copy

If you have CUDA installed at a non-standard location:

```powershell
$cudaBin = "C:\Your\CUDA\Installation\bin"
$outputPath = "libs/cuda/bin/x64"

# Copy CUPTI binaries
Copy-Item "$cudaBin\cupti64_*.dll" $outputPath -Force

# Copy CUDA Runtime
Copy-Item "$cudaBin\cudart64_*.dll" $outputPath -Force

# Copy NVIDIA Management Library
Copy-Item "C:\Windows\System32\nvml.dll" $outputPath -Force
```

### Option 3: Download from NVIDIA

If CUDA isn't installed:

1. Visit [NVIDIA CUDA Downloads](https://developer.nvidia.com/cuda-downloads)
2. Select your OS, architecture, and version
3. Download and install CUDA Toolkit
4. Run the setup script (Option 1)

## Troubleshooting

### DllNotFoundException for cupti64_2024.1.0.dll

**Problem**: Application throws `DllNotFoundException` for CUPTI

**Solutions**:
1. Verify binaries are in `libs/cuda/bin/x64/`:
   ```powershell
   Get-ChildItem libs/cuda/bin/x64
   ```

2. Check build output contains binaries:
   ```powershell
   Get-ChildItem src/VaultGuardian.Core/bin/x64/Debug/net10.0/bin/x64 -Filter "*.dll"
   ```

3. Rebuild the project:
   ```powershell
   dotnet clean
   dotnet build -c Debug
   ```

### Missing nvml.dll

**Problem**: GPU monitoring not working (NVML not initialized)

**Solution**: Copy from system:
```powershell
Copy-Item "C:\Windows\System32\nvml.dll" "libs/cuda/bin/x64/" -Force
```

### Version Mismatch

If you have multiple CUDA versions installed, the loader tries compatible versions in order:
- cupti64_120.dll (primary)
- cupti64_118.dll (fallback)
- System PATH (as final fallback)

To add support for another version:
1. Copy the DLL to `libs/cuda/bin/x64/`
2. Add fallback search logic to `CudaLibraryLoader.cs`

## Licensing

NVIDIA CUDA binaries are provided under the NVIDIA CUDA Toolkit End User License Agreement (EULA):
- [NVIDIA CUDA EULA](https://docs.nvidia.com/cuda/eula/index.html)

By using these binaries, you agree to comply with NVIDIA's licensing terms.

## Performance Considerations

- **First load**: DLL resolution adds ~50-100ms on first CudaProfiler instantiation
- **Subsequent loads**: DLL is cached in memory; no additional overhead
- **Profiling overhead**: GPU kernel monitoring adds minimal overhead (~1-2% per-kernel)

## Related Files

- `src/VaultGuardian.Core/Observability/CudaProfiler.cs` - GPU profiler implementation
- `src/VaultGuardian.Core/Observability/CuptiInterop.cs` - CUPTI P/Invoke bindings
- `src/VaultGuardian.Core/Observability/CudaLibraryLoader.cs` - Dynamic library resolution
- `src/VaultGuardian.Core/VaultGuardian.Core.csproj` - Build configuration for binary copy
- `scripts/setup-cuda-binaries.ps1` - Setup helper script
- `libs/cuda/` - Vendored binary cache

## Questions?

For more information:
- NVIDIA CUDA Documentation: https://docs.nvidia.com/cuda/
- CUPTI Guide: https://docs.nvidia.com/cuda/cupti/
- NVML Reference: https://docs.nvidia.com/deploy/nvml-api/
