using VaultGuardian.Core.Observability;
using Xunit;

namespace VaultGuardian.Core.Tests;

/// <summary>
/// Tests for CUDA library loading and GPU profiling functionality.
/// </summary>
public class CudaProfilerTests
{
    [Fact]
    public void CudaLibraryLoader_Initialize_DoesNotThrow()
    {
        // Arrange & Act
        var exception = Record.Exception(() => CudaLibraryLoader.Initialize());

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public void CudaLibraryLoader_CheckAvailableLibraries_ReturnsEnumerable()
    {
        // Arrange & Act
        var libraries = CudaLibraryLoader.CheckAvailableLibraries();

        // Assert
        Assert.NotNull(libraries);
        Assert.IsAssignableFrom<IEnumerable<string>>(libraries);
    }

    [Fact]
    public void CudaProfiler_Constructor_InitializesSuccessfully()
    {
        // Arrange & Act
        CudaLibraryLoader.Initialize();
        var profiler = new CudaProfiler();

        // Assert
        Assert.NotNull(profiler);

        // Cleanup
        profiler.Dispose();
    }

    [Fact]
    public void CudaProfiler_GetActiveKernelCount_ReturnsUint()
    {
        // Arrange
        var profiler = new CudaProfiler();

        // Act
        var count = profiler.GetActiveKernelCount();

        // Assert
        Assert.IsType<uint>(count);
        Assert.True(count >= 0);

        // Cleanup
        profiler.Dispose();
    }

    [Fact]
    public void CudaProfiler_GetCoreUtilization_ReturnsDouble()
    {
        // Arrange
        var profiler = new CudaProfiler();

        // Act
        var utilization = profiler.GetCoreUtilization();

        // Assert
        Assert.IsType<double>(utilization);
        Assert.True(utilization >= 0);

        // Cleanup
        profiler.Dispose();
    }

    [Fact]
    public void CudaProfiler_Dispose_Succeeds()
    {
        // Arrange
        var profiler = new CudaProfiler();

        // Act & Assert - Should not throw
        profiler.Dispose();
    }

    [Fact]
    public void CudaProfiler_MultipleInstances_CanBeCreated()
    {
        // Arrange & Act
        var profiler1 = new CudaProfiler();
        var profiler2 = new CudaProfiler();

        // Assert
        Assert.NotNull(profiler1);
        Assert.NotNull(profiler2);
        Assert.NotSame(profiler1, profiler2);

        // Cleanup
        profiler1.Dispose();
        profiler2.Dispose();
    }
}
