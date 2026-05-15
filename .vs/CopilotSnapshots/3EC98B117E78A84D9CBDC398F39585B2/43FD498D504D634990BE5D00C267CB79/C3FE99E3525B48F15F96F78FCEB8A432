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

    protected override void OnStartup(StartupEventArgs e)
    {
        var services = new ServiceCollection();
        ConfigureServices(services);
        ServiceProvider = services.BuildServiceProvider();

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
        services.AddSingleton<ResourceMonitor>();
        services.AddSingleton<LiveMonitorService>();
        services.AddSingleton<IInterceptor, WinDivertInterceptor>();
        
        services.AddSingleton<MainWindow>();
        services.AddSingleton<OverlayWindow>();
    }

    private void ShowMainWindow_Click(object sender, RoutedEventArgs e)
    {
        var mainWindow = ServiceProvider?.GetRequiredService<MainWindow>();
        mainWindow?.Show();
        mainWindow?.Activate();
    }

    private void ExitApp_Click(object sender, RoutedEventArgs e)
    {
        Shutdown();
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

