using System.Xml.Linq;

namespace VaultGuardian.Core.Tests;

public class WinUiStartupConfigurationTests
{
    [Fact]
    public void SelfContainedWinUiStartup_DoesNotUseWindowsAppSdkBootstrapper()
    {
        var repoRoot = FindRepoRoot();
        var uiProjectPath = Path.Combine(repoRoot, "src", "VaultGuardian.UI", "VaultGuardian.UI.csproj");
        var programPath = Path.Combine(repoRoot, "src", "VaultGuardian.UI", "Program.cs");

        var project = XDocument.Load(uiProjectPath);
        var isSelfContained = project
            .Descendants("WindowsAppSDKSelfContained")
            .Any(element => string.Equals(element.Value.Trim(), "true", StringComparison.OrdinalIgnoreCase));

        Assert.True(isSelfContained);

        var programSource = File.ReadAllText(programPath);

        Assert.DoesNotContain("Bootstrap.Initialize", programSource);
        Assert.DoesNotContain("Bootstrap.Shutdown", programSource);
    }

    [Fact]
    public void WinUiProject_UsesStableWindowingRuntimePayload()
    {
        var repoRoot = FindRepoRoot();
        var uiProjectPath = Path.Combine(repoRoot, "src", "VaultGuardian.UI", "VaultGuardian.UI.csproj");

        var project = XDocument.Load(uiProjectPath);
        var packageReferences = project
            .Descendants("PackageReference")
            .Select(element => new
            {
                Include = element.Attribute("Include")?.Value,
                Version = element.Attribute("Version")?.Value,
            })
            .ToArray();

        var windowsAppSdk = Assert.Single(
            packageReferences,
            package => package.Include == "Microsoft.WindowsAppSDK");

        Assert.Equal("1.7.250606001", windowsAppSdk.Version);
        Assert.DoesNotContain(
            packageReferences,
            package => package.Include == "Microsoft.Windows.SDK.BuildTools.MSIX");
    }

    [Fact]
    public void IngressCapture_StartsAfterMainWindowActivation()
    {
        var repoRoot = FindRepoRoot();
        var appSource = File.ReadAllText(Path.Combine(repoRoot, "src", "VaultGuardian.UI", "App.xaml.cs"));

        var activateIndex = appSource.IndexOf("MainAppWindow.Activate();", StringComparison.Ordinal);
        var ingressStartIndex = appSource.IndexOf("StartIngressWatcherAsync", StringComparison.Ordinal);

        Assert.True(activateIndex >= 0);
        Assert.True(ingressStartIndex > activateIndex);
    }

    private static string FindRepoRoot()
    {
        var current = new DirectoryInfo(Directory.GetCurrentDirectory());

        while (current != null)
        {
            if (File.Exists(Path.Combine(current.FullName, "VaultGuardian.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate VaultGuardian repository root.");
    }
}
