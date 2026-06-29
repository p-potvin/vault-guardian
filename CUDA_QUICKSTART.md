# Quick Start - CUDA Setup

## TL;DR

If you have CUDA installed:

```powershell
pwsh -ExecutionPolicy Bypass -File scripts/setup-cuda-binaries.ps1
dotnet build
```

If you don't have CUDA installed:

1. Download from: https://developer.nvidia.com/cuda-downloads
2. Install CUDA Toolkit for your OS
3. Run the setup script above
4. Build the project

## What Happens

The application automatically:
- Loads CUDA binaries from `libs/cuda/bin/x64/` (vendored)
- Falls back to system CUDA installation if available
- Gracefully disables GPU profiling if CUDA is not found

## Troubleshooting

**Build fails or GPU profiling disabled?**

Check if DLLs are copied to output:
```powershell
ls src/VaultGuardian.Core/bin/x64/Debug/net10.0/bin/x64 -Filter "*.dll"
```

Should see: `cudart64_12.dll`, `cupti64_*.dll`, `nvml.dll`

**Still not working?**

See full guide: [CUDA_SETUP.md](./CUDA_SETUP.md)

## Files Modified

- `src/VaultGuardian.Core/Observability/CudaProfiler.cs` - Initializes CUDA library loader
- `src/VaultGuardian.Core/Observability/CudaLibraryLoader.cs` - Dynamic DLL resolution
- `src/VaultGuardian.Core/VaultGuardian.Core.csproj` - Copies binaries on build
- `libs/cuda/bin/x64/` - Vendored CUDA binaries

## License

NVIDIA CUDA binaries are under NVIDIA EULA: https://docs.nvidia.com/cuda/eula/index.html
