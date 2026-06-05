using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VaultGuardian.Core;
using VaultGuardian.Core.Firewall;
using VaultGuardian.Core.Interception;
using VaultGuardian.Core.Observability;

namespace VaultGuardian.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    public static IServiceProvider? ServiceProvider { get; private set; }

    protected override async void OnStartup(StartupEventArgs e)
    {
        this.ShutdownMode = ShutdownMode.OnExplicitShutdown;
        var settings = AppSettingsLoader.Load();
        var services = new ServiceCollection();
        ConfigureServices(services, settings);
        ServiceProvider = services.BuildServiceProvider();

        var logger = ServiceProvider.GetRequiredService<ILogger<App>>();

        // Load Rules
        var engine = ServiceProvider.GetRequiredService<RuleDecisionEngine>();
        var loadedRules = await RuleConfigurationLoader.LoadFromFileAsync("rules.json");
        if (loadedRules.Count > 0)
        {
            engine.UpdateRules(loadedRules);
        }

        // Clean up any rules left in the Windows Firewall from the previous session,
        // then re-apply the current rule set (persistent rules will be reinstated).
        var firewall = ServiceProvider.GetRequiredService<IFirewallRuleApplier>();
        try
        {
            await firewall.CleanupPreviousSessionAsync();
            await firewall.ApplyAsync(engine.Rules);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to apply firewall rules at startup");
        }

        // Start Interceptor (lifetime managed by the DI container)
        var interceptor = ServiceProvider.GetRequiredService<IInterceptor>();
        try
        {
            await interceptor.StartAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to start interceptor");
        }

        // Show MainWindow
        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();

        base.OnStartup(e);
    }

    private static void ConfigureServices(IServiceCollection services, AppSettings settings)
    {
        services.AddLogging(builder => builder.AddConsole());

        services.AddSingleton(settings);
        services.AddSingleton(new RuleDecisionEngine([]));

        services.AddSingleton<TrafficStats>();
        services.AddSingleton<CudaProfiler>();
        services.AddSingleton<ResourceMonitor>();
        services.AddSingleton<LiveMonitorService>();
        services.AddSingleton<IInterceptor, WinDivertInterceptor>();
        services.AddSingleton<IProcessRunner, ProcessRunner>();
        services.AddSingleton<IFirewallRuleApplier, WindowsFirewallRuleApplier>();

        services.AddSingleton<MainWindow>();
        services.AddSingleton<OverlayWindow>();
        services.AddTransient<RulesManagerWindow>();
        services.AddTransient<SettingsWindow>();
    }

    private void ShowMainWindow_Click(object sender, RoutedEventArgs e)
    {
        var mainWindow = ServiceProvider?.GetRequiredService<MainWindow>();
        mainWindow?.Show();
        mainWindow?.Activate();
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("VaultGuardian v1.0\nSecure Performance Monitor\nBuilt with .NET 10", "About VaultGuardian", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Help_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("Visit https://github.com/p-potvin/vault-guardian for documentation and support.", "VaultGuardian Help", MessageBoxButton.OK, MessageBoxImage.Question);
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        var window = ServiceProvider?.GetRequiredService<SettingsWindow>();
        if (window == null) return;
        window.Owner = ServiceProvider?.GetService<MainWindow>();
        window.ShowDialog();
    }

    private void ExitApp_Click(object sender, RoutedEventArgs e)
    {
        Current.Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Clear session-only firewall rules before tearing down the container.
        // Wrap in Task.Run to avoid a sync-over-async deadlock on the WPF UI thread.
        try
        {
            if (ServiceProvider?.GetService(typeof(IFirewallRuleApplier)) is IFirewallRuleApplier firewall)
                Task.Run(() => firewall.ClearSessionRulesAsync()).GetAwaiter().GetResult();
        }
        catch
        {
            // best-effort — don't block exit on firewall failures
        }

        // ServiceProvider disposal cascades to singletons (incl. IInterceptor's
        // IAsyncDisposable). Sync Dispose() throws when a singleton is async-only,
        // so prefer DisposeAsync where available.
        try
        {
            if (ServiceProvider is IAsyncDisposable asyncDisposable)
            {
                asyncDisposable.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            else if (ServiceProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
        catch
        {
            // best-effort shutdown — don't block app exit on cleanup failures
        }

        base.OnExit(e);
    }
}
