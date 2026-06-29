using System.Runtime.InteropServices;

namespace VaultGuardian.Core.Observability;

/// <summary>
/// Handles dynamic loading of NVIDIA CUDA native libraries from a local repository path.
/// This allows the application to use vendored CUDA binaries without requiring system-wide installation.
/// </summary>
public static class CudaLibraryLoader
{
    private static bool _resolverRegistered;
    private static readonly string[] LibrarySearchPaths;

    static CudaLibraryLoader()
    {
        // Construct search paths for CUDA binaries
        var appDir = AppContext.BaseDirectory;
        var repoRoot = FindRepositoryRoot(appDir);

        LibrarySearchPaths = new[]
        {
            // Priority 1: Nested bin/x64 in output directory (from project build)
            Path.Combine(appDir, "bin", "x64"),

            // Priority 2: Local vendored binaries in repository
            Path.Combine(repoRoot, "libs", "cuda", "bin", "x64"),

            // Priority 3: Application directory
            appDir,

            // Priority 4: Standard CUDA installation paths
            @"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.4\bin",
            @"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.3\bin",
            @"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.2\bin",
            @"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.1\bin",
            @"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v12.0\bin",

            // Priority 5: System paths (NVIDIA driver may have placed DLLs here)
            @"C:\Windows\System32",
            @"C:\Windows\SysWOW64",
        };
    }

    /// <summary>
    /// Initializes the native library resolver for CUDA libraries.
    /// Call this once during application startup before creating CudaProfiler instances.
    /// This is disabled by default to prevent heap corruption issues.
    /// Only set VAULTGUARDIAN_CUDA_ENABLED=1 to enable.
    /// </summary>
    public static void Initialize()
    {
        if (_resolverRegistered) return;

        // Check if CUDA is explicitly enabled
        bool cudaEnabled = Environment.GetEnvironmentVariable("VAULTGUARDIAN_CUDA_ENABLED") == "1";
        if (!cudaEnabled)
        {
            _resolverRegistered = true; // Mark as attempted to skip retry
            return;
        }

        try
        {
            NativeLibrary.SetDllImportResolver(typeof(CudaLibraryLoader).Assembly, ResolveCudaLibrary);
            _resolverRegistered = true;
        }
        catch (Exception ex)
        {
            // If we can't set up the resolver, that's okay - fall back to system paths
            System.Diagnostics.Debug.WriteLine($"Warning: Failed to set up DLL import resolver: {ex}");
            _resolverRegistered = true; // Mark as attempted
        }
    }

    /// <summary>
    /// Resolves CUDA library imports by searching predefined paths.
    /// </summary>
    private static IntPtr ResolveCudaLibrary(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        // Only handle CUDA-related libraries
        if (!libraryName.Contains("cuda") && !libraryName.Contains("cupti") && !libraryName.Contains("nvml"))
            return IntPtr.Zero;

        foreach (var searchPath_ in LibrarySearchPaths)
        {
            var dllPath = Path.Combine(searchPath_, libraryName);

            if (File.Exists(dllPath))
            {
                try
                {
                    if (NativeLibrary.TryLoad(dllPath, out var handle))
                        return handle;
                }
                catch
                {
                    // Continue to next path
                }
            }
        }

        // Not found in any search path; let the system try its default resolution
        return IntPtr.Zero;
    }

    /// <summary>
    /// Attempts to find the repository root by traversing upward from the given directory.
    /// Looks for .git directory or a known marker file.
    /// </summary>
    private static string FindRepositoryRoot(string startPath)
    {
        var current = new DirectoryInfo(startPath);

        while (current != null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, ".git")))
                return current.FullName;

            if (File.Exists(Path.Combine(current.FullName, "VaultGuardian.slnx")))
                return current.FullName;

            current = current.Parent;
        }

        // Fallback: return the start path
        return startPath;
    }

    /// <summary>
    /// Checks if the required CUDA libraries are available in the expected locations.
    /// Returns a list of missing libraries.
    /// </summary>
    public static IEnumerable<string> CheckAvailableLibraries()
    {
        var requiredLibs = new[] { "cupti64_2024.1.0.dll", "nvml.dll" };
        var missing = new List<string>();

        foreach (var lib in requiredLibs)
        {
            var found = false;
            foreach (var searchPath_ in LibrarySearchPaths)
            {
                if (File.Exists(Path.Combine(searchPath_, lib)))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
                missing.Add(lib);
        }

        return missing;
    }
}
