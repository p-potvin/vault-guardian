#!/usr/bin/env pwsh
# Download and setup CUDA binaries from NVIDIA

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "CUDA Toolkit Binary Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# CUDA 2024.1.0 downloads
$cudaDownloadUrl = "https://developer.download.nvidia.com/compute/cuda/12.4.1/local_installers/cuda_12.4.1_550.54.15_windows.exe"
$cudaOutputPath = "$PSScriptRoot/../temp/cuda_installer.exe"
$cudaBinPath = "$PSScriptRoot/../libs/cuda/bin/x64"

Write-Host "NVIDIA CUDA License Information:" -ForegroundColor Yellow
Write-Host "=================================="
Write-Host "CUDA Toolkit binaries are provided under the NVIDIA CUDA Toolkit EULA."
Write-Host "By downloading and using these binaries, you agree to comply with the terms at:"
Write-Host "https://docs.nvidia.com/cuda/eula/index.html"
Write-Host ""

# Check if we already have CUDA installed on the system
Write-Host "Checking for existing CUDA installation..." -ForegroundColor Cyan
$cudaInstallPath = $null

if (Test-Path "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA") {
	$cudaInstallPath = Get-ChildItem "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA" | Sort-Object -Descending | Select-Object -First 1 -ExpandProperty FullName
	Write-Host "Found CUDA installation at: $cudaInstallPath" -ForegroundColor Green
}

if ($cudaInstallPath) {
	Write-Host ""
	Write-Host "Option 1: Copy from existing CUDA installation (Recommended - Faster)" -ForegroundColor Cyan
	Write-Host "==========================================================================" -ForegroundColor Cyan

	$response = Read-Host "Copy binaries from $cudaInstallPath ? (y/n)"

	if ($response -eq 'y') {
		Write-Host "Creating output directory..." 
		New-Item -ItemType Directory -Path $cudaBinPath -Force | Out-Null

		$requiredDlls = @(
			"cupti64_2024.1.0.dll",
			"cupti64_12.1.dll",
			"cupti64_12.0.dll",
			"cupti64_11.8.dll",
			"cupti64.dll",
			"cudart64_12.dll",
			"cudart64_11.dll",
			"cudart64.dll",
			"nvml.dll"
		)

		Write-Host ""
		Write-Host "Copying required DLLs..." -ForegroundColor Cyan

		$copiedCount = 0
		foreach ($dll in $requiredDlls) {
			$srcPath = Join-Path $cudaInstallPath "bin" $dll
			if (Test-Path $srcPath) {
				Copy-Item $srcPath $cudaBinPath -Force
				Write-Host "  ✓ Copied $dll" -ForegroundColor Green
				$copiedCount++
			}
		}

		Write-Host ""
		Write-Host "Copied $copiedCount DLLs to $cudaBinPath" -ForegroundColor Green
		Write-Host ""
		Write-Host "Setup complete! You can now build the project with:" -ForegroundColor Green
		Write-Host "  dotnet build"
		exit 0
	}
}

Write-Host ""
Write-Host "Option 2: Download CUDA Toolkit from NVIDIA" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "CUDA 12.4.1 will be downloaded (~4 GB)"
Write-Host "Download URL: $cudaDownloadUrl"
Write-Host ""

$response = Read-Host "Download CUDA 12.4.1? (y/n)"

if ($response -eq 'y') {
	$temp = "$PSScriptRoot/../temp"
	New-Item -ItemType Directory -Path $temp -Force | Out-Null

	Write-Host "Downloading CUDA 12.4.1..." -ForegroundColor Cyan
	$progressPreference = 'SilentlyContinue'
	Invoke-WebRequest -Uri $cudaDownloadUrl -OutFile $cudaOutputPath
	$progressPreference = 'Continue'

	Write-Host "Download complete: $cudaOutputPath" -ForegroundColor Green
	Write-Host ""
	Write-Host "Next steps:" -ForegroundColor Cyan
	Write-Host "  1. Run the installer: $cudaOutputPath"
	Write-Host "  2. Choose 'Custom Installation'"
	Write-Host "  3. Select only 'Development Tools' -> CUPTI"
	Write-Host "  4. Complete the installation"
	Write-Host "  5. Re-run this script to copy the binaries"
	exit 0
}

Write-Host ""
Write-Host "Option 3: Manual Setup" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""
Write-Host "If you prefer to set up manually:"
Write-Host "  1. Download CUDA Toolkit from: https://developer.nvidia.com/cuda-downloads"
Write-Host "  2. Install CUDA locally"
Write-Host "  3. Copy DLLs from your CUDA installation to:"
Write-Host "     $cudaBinPath"
Write-Host ""
Write-Host "Required DLLs:"
Write-Host "  - cupti64_2024.1.0.dll or cupti64_*.dll"
Write-Host "  - nvml.dll"
Write-Host "  - cudart64_*.dll (optional but recommended)"
Write-Host ""
