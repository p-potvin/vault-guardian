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
using VaultGuardian.Core.Diagnostics;
using VaultGuardian.Core.Firewall;
using VaultGuardian.Core.Firewall.Wfp;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Hostname;
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Telemetry;
using VaultGuardian.Core.Ingress.Tracing;
using VaultGuardian.Core.Interception;
using VaultGuardian.Core.Observability;
using VaultGuardian.Core.Processes;

namespace VaultGuardian.UI;

public partial class App : Application
{
    public static IServiceProvider? ServiceProvider { get; private set; }
    public static TaskbarIcon? TrayIcon { get; private set; }
    public static MainWindow? MainAppWindow { get; private set; }

    private static System.Threading.Timer? _heartbeatTimer;
    private static DateTimeOffset _startedAt;

    public App()
    {
        InitializeComponent();
        UnhandledException += OnUnhandledException;

        // Suppress noisy debug output for assembly loading
        SuppressDebugLogging();
    }

    private static void SuppressDebugLogging()
    {
        // Note: Debug output filtering for "Skipped loading symbols" etc.
        // cannot be reliably done from managed code due to native debug output.
        // Visual Studio's debugger output window shows native debug output
        // that bypasses managed trace listeners entirely.
        // 
        // To suppress these messages in Visual Studio:
        // 1. Tools → Options → Debugging → Output Window
        // 2. Or use debugger breakpoint filters
        // 3. Or set environment variable: VAULTGUARDIAN_CUDA_ENABLED=1 to enable CUDA
    }

    protected override async void OnLaunched(LaunchActivatedEventArgs args)
    {
        var settings = AppSettingsLoader.Load();

        var services = new ServiceCollection();
        ConfigureServices(services, settings);
        ServiceProvider = services.BuildServiceProvider();

        var logger = ServiceProvider.GetRequiredService<ILogger<App>>();

        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        logger.LogInformation(
            "VaultGuardian v{Version} starting (pid {Pid}). Settings: ingressCapture={Ingress} hostnameCorrelation={Sni} browserMitm={Mitm} mitmPort={Port} refreshMs={Refresh} lang={Lang}",
            version, Environment.ProcessId, settings.EnableIngressPacketCapture, settings.EnableHostnameCorrelation,
            settings.EnableBrowserProfileMitm, settings.MitmProxyPort, settings.RefreshIntervalMs, settings.Language);

        // Load Rules
        var engine = ServiceProvider.GetRequiredService<RuleDecisionEngine>();
        var loadedRules = await RuleConfigurationLoader.LoadFromFileAsync("rules.json");
        if (loadedRules.Count > 0)
        {
            engine.UpdateRules(loadedRules);
        }

        logger.LogInformation("Loaded {Count} egress rule(s) from rules.json", loadedRules.Count);

        // Clean up any rules left in the Windows Firewall from the previous session,
        // then re-apply the current rule set (persistent rules will be reinstated).
        var firewall = ServiceProvider.GetRequiredService<IFirewallRuleApplier>();
        try
        {
            await firewall.CleanupPreviousSessionAsync();
            await firewall.ApplyAsync(engine.Rules);
            logger.LogInformation("Firewall rules applied at startup");
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
            logger.LogInformation("Egress interceptor started");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to start interceptor");
        }

        // Start passive SNI sniffing for the non-MITM hostname policy path.
        if (settings.EnableHostnameCorrelation)
        {
            var sniffer = ServiceProvider.GetRequiredService<IHostnameSniffer>();
            try
            {
                await sniffer.StartAsync(CancellationToken.None);
                logger.LogInformation("SNI sniffer started (outbound TCP/443)");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to start hostname (SNI) sniffer");
            }
        }
        else
        {
            logger.LogInformation("Hostname correlation disabled; SNI sniffer not started");
        }

        TrayIcon = CreateTrayIcon();

        MainAppWindow = ServiceProvider.GetRequiredService<MainWindow>();
        MainAppWindow.Closed += OnMainWindowClosed;
        MainAppWindow.Activate();
        logger.LogInformation("Main window activated");

        if (settings.EnableIngressPacketCapture)
        {
            _ = StartIngressWatcherAsync(logger);
        }
        else
        {
            logger.LogInformation("Ingress packet capture is disabled; enable it in settings to start passive capture on the next launch.");
        }

        StartHeartbeat(logger);
        logger.LogInformation("Startup complete");
    }

    private static void StartHeartbeat(ILogger logger)
    {
        _startedAt = DateTimeOffset.UtcNow;
        _heartbeatTimer = new System.Threading.Timer(
            _ => LogHeartbeat(logger),
            null,
            TimeSpan.FromSeconds(60),
            TimeSpan.FromSeconds(60));
    }

    private static void LogHeartbeat(ILogger logger)
    {
        try
        {
            using var self = System.Diagnostics.Process.GetCurrentProcess();
            self.Refresh();
            var uptime = DateTimeOffset.UtcNow - _startedAt;

            var stats = ServiceProvider?.GetService<TrafficStats>()?.GetSnapshot();
            var ingress = ServiceProvider?.GetService<IIngressTrafficWatcher>()?.GetStatus();
            var hostnames = ServiceProvider?.GetService<HostnameResolutionStore>()?.Count ?? 0;

            logger.LogInformation(
                "Heartbeat uptime={Uptime:d\\.hh\\:mm\\:ss} mem(ws={Ws}MB priv={Priv}MB) threads={Threads} handles={Handles} | " +
                "traffic(total={Total} allowed={Allowed} blocked={Blocked} sent={Sent}MB recv={Recv}MB) | " +
                "ingress({IngressState} archived={Archived} skipped={Skipped}) | hostnames={Hostnames}",
                uptime,
                self.WorkingSet64 / 1024 / 1024,
                self.PrivateMemorySize64 / 1024 / 1024,
                self.Threads.Count,
                self.HandleCount,
                stats?.TotalPackets ?? 0,
                stats?.AllowedPackets ?? 0,
                stats?.BlockedPackets ?? 0,
                (stats?.TotalBytesSent ?? 0) / 1024 / 1024,
                (stats?.TotalBytesRecv ?? 0) / 1024 / 1024,
                ingress?.State.ToString() ?? "n/a",
                ingress?.ArchivedPackets ?? 0,
                ingress?.SkippedPackets ?? 0,
                hostnames);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Heartbeat logging failed");
        }
    }

    private static async Task StartIngressWatcherAsync(ILogger<App> logger)
    {
        if (ServiceProvider == null)
        {
            return;
        }

        var ingressWatcher = ServiceProvider.GetRequiredService<IIngressTrafficWatcher>();
        try
        {
            await Task.Yield();
            await ingressWatcher.StartAsync(CancellationToken.None);
            logger.LogInformation("Ingress traffic watcher started");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to start ingress traffic watcher");
        }
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
        try
        {
            ServiceProvider?.GetService<ILogger<App>>()?.LogError(e.Exception, "Unhandled UI exception (handled, process kept alive)");
        }
        catch { }
        e.Handled = true;
    }

    private static async Task ShutdownAsync()
    {
        var logger = ServiceProvider?.GetService<ILogger<App>>();
        logger?.LogInformation("Shutdown starting");

        _heartbeatTimer?.Dispose();
        _heartbeatTimer = null;

        if (ServiceProvider != null)
        {
            // Clear session-only firewall rules before tearing down the container.
            try
            {
                var firewall = ServiceProvider.GetService<IFirewallRuleApplier>();
                if (firewall != null) await firewall.ClearSessionRulesAsync();
            }
            catch { }

            try
            {
                var interceptor = ServiceProvider.GetService<IInterceptor>();
                if (interceptor != null) await interceptor.DisposeAsync();
            }
            catch { }

            try
            {
                var sniffer = ServiceProvider.GetService<IHostnameSniffer>();
                if (sniffer != null) await sniffer.DisposeAsync();
            }
            catch { }

            try
            {
                var ingressWatcher = ServiceProvider.GetService<IIngressTrafficWatcher>();
                if (ingressWatcher != null) await ingressWatcher.DisposeAsync();
            }
            catch { }

            // ServiceProvider disposal cascades to singletons (incl. IInterceptor's
            // IAsyncDisposable). Prefer DisposeAsync where available.
            // Logged before disposal because the file logger lives in the container.
            logger?.LogInformation("Subsystems stopped; disposing service container (final log line)");
            try
            {
                if (ServiceProvider is IAsyncDisposable asyncDisposable)
                    await asyncDisposable.DisposeAsync();
                else if (ServiceProvider is IDisposable disposable)
                    disposable.Dispose();
            }
            catch { }
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
        var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        var versionText = version is null ? "1.1" : $"{version.Major}.{version.Minor}.{version.Build}";
        about.Click += (_, _) => SafeOnUiThread(() => ShowInfoDialogAsync(
            $"VaultGuardian v{versionText}\nSecure Performance Monitor\nBuilt with .NET 10 + WinUI 3", "About VaultGuardian"));
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

    private static void ConfigureServices(IServiceCollection services, AppSettings settings)
    {
        var logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
        services.AddLogging(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddConsole();
            // Persistent daily-rolling file so a multi-day stability run is diagnosable.
            builder.AddProvider(new Logging.FileLoggerProvider(logDirectory));
        });

        services.AddSingleton(settings);
        services.AddSingleton(new RuleDecisionEngine([]));

        services.AddSingleton<TrafficStats>();

        // Passive hostname resolution (DNS + SNI) shared by the ingress watcher
        // (write side) and the interceptor (read side, via IHostnameResolver).
        services.AddSingleton<HostnameResolutionStore>();
        services.AddSingleton<IHostnameResolver>(sp => sp.GetRequiredService<HostnameResolutionStore>());

        services.AddSingleton<IIngressTrafficStore>(_ =>
            new IngressTrafficStore(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ingress-archive.json")));
        services.AddSingleton<PrivacyWatchProfileStore>(_ =>
            new PrivacyWatchProfileStore(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "privacy-watch-profile.json")));
        services.AddSingleton<PrivacyTelemetryStore>(_ =>
            new PrivacyTelemetryStore(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "privacy-telemetry-hits.jsonl")));
        services.AddSingleton<FullTraceManager>();
        services.AddSingleton<MitmFlowImporter>();
        services.AddSingleton<IManagedProcessLauncher, ManagedProcessLauncher>();
        services.AddSingleton(sp =>
        {
            var appSettings = sp.GetRequiredService<AppSettings>();
            return new MitmProxyOptions(
                appSettings.MitmDumpPath,
                appSettings.MitmProxyPort,
                appSettings.MitmBrowserExecutablePath,
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "mitm-browser-profile"));
        });
        services.AddSingleton<MitmProxyService>();
        services.AddSingleton<LiveMitmFlowProcessor>();

        // CudaProfiler is lazily instantiated only when accessed and CUDA is enabled.
        // ResourceMonitor will handle the case where it's null.
        services.AddSingleton(sp => new Lazy<CudaProfiler>(() => new CudaProfiler(), isThreadSafe: true));

        services.AddSingleton<ResourceMonitor>();
        services.AddSingleton<LiveMonitorService>();
        services.AddSingleton<IInterceptor, WinDivertInterceptor>();
        services.AddSingleton<IIngressTrafficWatcher, WinDivertIngressTrafficWatcher>();
        services.AddSingleton<IHostnameSniffer, WinDivertSniSniffer>();
        services.AddSingleton<IProcessInspector, WindowsProcessInspector>();
        services.AddSingleton<IProcessRunner, ProcessRunner>();
        services.AddSingleton<IFirewallRuleApplier>(sp => FirewallApplierFactory.Create(
            sp.GetRequiredService<AppSettings>().FirewallBackend,
            engineFactory: () => new WfpEngine(sp.GetRequiredService<ILogger<WfpEngine>>()),
            wfpApplierFactory: engine => new WfpFirewallRuleApplier(
                engine, sp.GetRequiredService<ILogger<WfpFirewallRuleApplier>>()),
            netshApplierFactory: () => new WindowsFirewallRuleApplier(
                sp.GetRequiredService<IProcessRunner>(),
                sp.GetRequiredService<ILogger<WindowsFirewallRuleApplier>>()),
            sp.GetRequiredService<ILogger<App>>()));

        services.AddSingleton<MainWindow>();
        services.AddSingleton<OverlayWindow>();
        services.AddTransient<RulesManagerWindow>();
        services.AddTransient<SettingsWindow>();
    }
}
