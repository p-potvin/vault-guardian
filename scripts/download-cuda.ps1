# PowerShell script to download and extract CUDA 2024 binaries
# This script fetches the necessary NVIDIA CUDA and CUPTI binaries

param(
	[string]$CudaVersion = "2024.1.0",
	[string]$OutputDir = "libs/cuda/bin/x64"
)

Write-Host "CUDA Toolkit Setup Script"
Write-Host "========================="
Write-Host ""
Write-Host "This script will help set up the CUDA toolkit binaries locally."
Write-Host ""
Write-Host "IMPORTANT: CUDA Toolkit binaries are covered by NVIDIA's End User License Agreement (EULA)."
Write-Host "By downloading these binaries, you agree to comply with NVIDIA's licensing terms."
Write-Host "Visit: https://docs.nvidia.com/cuda/eula/index.html"
Write-Host ""

# Create output directory if it doesn't exist
if (!(Test-Path $OutputDir)) {
	New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
	Write-Host "Created directory: $OutputDir"
}

Write-Host ""
Write-Host "Required binaries:"
Write-Host "  - cupti64_2024.1.0.dll (CUDA Profiling Tools Interface)"
Write-Host "  - cudart64_12.dll or similar (CUDA Runtime)"
Write-Host "  - nvcuda.dll (NVIDIA GPU driver interface)"
Write-Host ""

Write-Host "OPTIONS TO OBTAIN BINARIES:"
Write-Host ""
Write-Host "Option 1: Download from NVIDIA (RECOMMENDED)"
Write-Host "  1. Visit: https://developer.nvidia.com/cuda-downloads"
Write-Host "  2. Select your OS, architecture, and version"
Write-Host "  3. Download the CUDA Toolkit installer"
Write-Host "  4. Install it or extract binaries from installer"
Write-Host "  5. Copy required DLLs to: $OutputDir"
Write-Host ""
Write-Host "Option 2: Extract from existing CUDA installation"
Write-Host "  1. Find your CUDA installation (usually C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA)"
Write-Host "  2. Copy DLLs from bin\ subfolder to: $OutputDir"
Write-Host ""
Write-Host "Option 3: Copy from NVIDIA Container"
Write-Host "  1. Pull: docker pull nvcr.io/nvidia/cuda:12.4.1-runtime-windows-ltsc2022"
Write-Host "  2. Extract binaries and copy to: $OutputDir"
Write-Host ""

$response = Read-Host "Do you want to open the NVIDIA CUDA Downloads page? (y/n)"
if ($response -eq 'y') {
	Start-Process "https://developer.nvidia.com/cuda-downloads"
}

Write-Host ""
Write-Host "After obtaining the binaries, ensure these DLLs are in: $OutputDir"
Write-Host "  - cupti64_2024.1.0.dll"
Write-Host "  - cudart64_*.dll"
Write-Host "  - nvcuda.dll"
Write-Host ""
Write-Host "Then run: dotnet build"
