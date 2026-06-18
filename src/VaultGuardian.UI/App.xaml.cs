using System;
using System.Threading;
using System.Threading.Tasks;
using H.NotifyIcon;
using H.NotifyIcon.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using VaultGuardian.Core;
using VaultGuardian.Core.Interception;
using VaultGuardian.Core.Observability;

namespace VaultGuardian.UI;

public partial class App : Application
{
    public static IServiceProvider? ServiceProvider { get; private set; }
    public static TaskbarIcon? TrayIcon { get; private set; }
    public static MainWindow? MainAppWindow { get; private set; }

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        var services = new ServiceCollection();
        ConfigureServices(services);
        ServiceProvider = services.BuildServiceProvider();

        var engine = ServiceProvider.GetRequiredService<RuleDecisionEngine>();
        var loadedRules = await RuleConfigurationLoader.LoadFromFileAsync("rules.json");
        if (loadedRules.Count > 0)
        {
            engine.UpdateRules(loadedRules);
        }

        var interceptor = ServiceProvider.GetRequiredService<IInterceptor>();
        await interceptor.StartAsync(CancellationToken.None);

        TrayIcon = CreateTrayIcon();

        MainAppWindow = ServiceProvider.GetRequiredService<MainWindow>();
        MainAppWindow.Closed += OnMainWindowClosed;
        MainAppWindow.Activate();
    }

    private void OnMainWindowClosed(object sender, WindowEventArgs args)
    {
        ShutdownAsync().GetAwaiter().GetResult();
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        // Swallow so a stray exception inside a tray click or dialog doesn't tear
        // down the process (and with it the tray icon). The MainWindow Closed
        // handler is what actually performs firewall cleanup on a real exit.
        System.Diagnostics.Debug.WriteLine($"[VaultGuardian] Unhandled: {e.Message}");
        e.Handled = true;
    }

    private static async Task ShutdownAsync()
    {
        if (ServiceProvider != null)
        {
            try
            {
                var interceptor = ServiceProvider.GetService<IInterceptor>();
                if (interceptor != null) await interceptor.DisposeAsync();
            }
            catch { }

            if (ServiceProvider is IDisposable disposable) disposable.Dispose();
        }
        TrayIcon?.Dispose();
        TrayIcon = null;
    }

    private TaskbarIcon CreateTrayIcon()
    {
        var icon = new TaskbarIcon
        {
            ToolTipText = "VaultGuardian Passive Monitor",
            IconSource = new BitmapImage(new Uri("ms-appx:///Assets/Icon.ico")),
        };

        var menu = new MenuFlyout();

        var dashboard = new MenuFlyoutItem { Text = "Dashboard" };
        dashboard.Click += (_, _) =>
        {
            MainAppWindow?.Activate();
        };
        menu.Items.Add(dashboard);

        menu.Items.Add(new MenuFlyoutSeparator());

        var about = new MenuFlyoutItem { Text = "About" };
        about.Click += (_, _) => SafeOnUiThread(() => ShowInfoDialogAsync(
            "VaultGuardian v1.0\nSecure Performance Monitor\nBuilt with .NET 10 + WinUI 3", "About VaultGuardian"));
        menu.Items.Add(about);

        var help = new MenuFlyoutItem { Text = "Help" };
        help.Click += (_, _) => SafeOnUiThread(() => ShowInfoDialogAsync(
            "Visit https://github.com/p-potvin/vault-guardian for documentation and support.", "VaultGuardian Help"));
        menu.Items.Add(help);

        var settings = new MenuFlyoutItem { Text = "Settings" };
        settings.Click += (_, _) => SafeOnUiThread(() =>
            MainAppWindow != null ? MainAppWindow.ShowSettingsAsync() : Task.CompletedTask);
        menu.Items.Add(settings);

        menu.Items.Add(new MenuFlyoutSeparator());

        var quit = new MenuFlyoutItem { Text = "Quit" };
        quit.Click += (_, _) =>
        {
            ShutdownAsync().GetAwaiter().GetResult();
            Current.Exit();
        };
        menu.Items.Add(quit);

        icon.ContextFlyout = menu;
        icon.ForceCreate();
        return icon;
    }

    private static void SafeOnUiThread(Func<Task> work)
    {
        var queue = MainAppWindow?.DispatcherQueue;
        if (queue == null) return;
        queue.TryEnqueue(async () =>
        {
            try { await work(); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[VaultGuardian tray] {ex}"); }
        });
    }

    private static FrameworkElement? EnsureMainWindowVisible()
    {
        if (MainAppWindow == null) return null;
        // ContentDialog needs a XamlRoot. If the user closed the MainWindow into
        // the tray, Content.XamlRoot may be detached — re-activating restores it.
        try { MainAppWindow.Activate(); } catch { }
        return MainAppWindow.Content as FrameworkElement;
    }

    private static async Task ShowInfoDialogAsync(string content, string title)
    {
        var root = EnsureMainWindowVisible();
        if (root?.XamlRoot != null)
        {
            var dlg = new ContentDialog
            {
                XamlRoot = root.XamlRoot,
                Title = title,
                Content = content,
                CloseButtonText = "OK",
            };
            await dlg.ShowAsync();
        }
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddLogging(builder => builder.AddConsole());

        services.AddSingleton(new RuleDecisionEngine([]));
        services.AddSingleton<TrafficStats>();
        services.AddSingleton<CudaProfiler>();
        services.AddSingleton<ResourceMonitor>();
        services.AddSingleton<LiveMonitorService>();
        services.AddSingleton<IInterceptor, WinDivertInterceptor>();
        services.AddSingleton(_ => AppSettings.Load());

        services.AddSingleton<MainWindow>();
        services.AddSingleton<OverlayWindow>();
        services.AddTransient<RulesManagerWindow>();
    }
}
