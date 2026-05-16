using System.Configuration;
using System.Data;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VaultGuardian.Core;
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
        var services = new ServiceCollection();
        ConfigureServices(services);
        ServiceProvider = services.BuildServiceProvider();

        // Load Rules
        var engine = ServiceProvider.GetRequiredService<RuleDecisionEngine>();
        var loadedRules = await RuleConfigurationLoader.LoadFromFileAsync("rules.json");
        if (loadedRules.Count > 0)
        {
            engine.UpdateRules(loadedRules);
        }

        // Start Interceptor
        var interceptor = ServiceProvider.GetRequiredService<IInterceptor>();
        interceptor.StartAsync(CancellationToken.None);

        // Show MainWindow
        var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();

        base.OnStartup(e);
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddLogging(builder => builder.AddConsole());
        
        // Rules - loading an empty list for now or from a default file
        services.AddSingleton(new RuleDecisionEngine([]));
        
        services.AddSingleton<TrafficStats>();
        services.AddSingleton<CudaProfiler>();
        services.AddSingleton<ResourceMonitor>();
        services.AddSingleton<LiveMonitorService>();
        services.AddSingleton<IInterceptor, WinDivertInterceptor>();
        
        services.AddSingleton<MainWindow>();
        services.AddSingleton<OverlayWindow>();
        services.AddTransient<RulesManagerWindow>();
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
        MessageBox.Show("Settings module coming soon.", "Settings", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void ExitApp_Click(object sender, RoutedEventArgs e)
    {
        Current.Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (ServiceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }
        base.OnExit(e);
    }
}

