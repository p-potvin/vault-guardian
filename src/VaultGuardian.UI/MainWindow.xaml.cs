using System;
using System.Text;
using System.Threading.Tasks;
using H.NotifyIcon;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VaultGuardian.Core;
using VaultGuardian.Core.Branding;
using VaultGuardian.Core.Ingress;
using VaultGuardian.Core.Ingress.Mitm;
using VaultGuardian.Core.Ingress.Tracing;
using VaultGuardian.Core.Observability;
using VaultGuardian.Core.Processes;

namespace VaultGuardian.UI;

public sealed partial class MainWindow : Window
{
    private readonly LiveMonitorService _monitor;
    private readonly OverlayWindow _overlay;
    private readonly AppSettings _settings;
    private readonly IIngressTrafficStore _ingressStore;
    private readonly MitmProxyService _mitmProxyService;
    private readonly IProcessInspector _processInspector;
    private readonly DispatcherQueueTimer _timer;
    private bool _processRefreshInFlight;
    private int _tickCounter;
    private List<IngressFlowSummary> _visibleIngressFlows = [];
    private IngressFlowSummary? _selectedIngressFlow;
    private IngressWatcherStatus _lastIngressStatus = IngressWatcherStatus.Stopped;
    private string _lastIngressListSignature = string.Empty;
    private readonly List<GpuPanel> _gpuPanels = [];

    public MainWindow(
        LiveMonitorService monitor,
        OverlayWindow overlay,
        AppSettings settings,
        IIngressTrafficStore ingressStore,
        MitmProxyService mitmProxyService,
        IProcessInspector processInspector)
    {
        _monitor = monitor;
        _overlay = overlay;
        _settings = settings;
        _ingressStore = ingressStore;
        _mitmProxyService = mitmProxyService;
        _processInspector = processInspector;

        InitializeComponent();
        Title = "VaultGuardian";
        ApplyBrandCopy();

        _timer = DispatcherQueue.CreateTimer();
        _timer.Interval = TimeSpan.FromMilliseconds(_settings.RefreshIntervalMs);
        _timer.Tick += OnTick;
        _timer.Start();

        _settings.Changed += OnSettingsChanged;

        if (_settings.ShowOverlayOnStart)
        {
            ShowOverlayCheckbox.IsChecked = true;
            _overlay.Activate();
        }
        else
        {
            ShowOverlayCheckbox.IsChecked = false;
        }

        Closed += OnWindowClosed;
    }

    private void OnSettingsChanged(object? sender, EventArgs e)
    {
        _timer.Interval = TimeSpan.FromMilliseconds(Math.Max(100, _settings.RefreshIntervalMs));
        ApplyBrandCopy();
    }

    private void ApplyBrandCopy()
    {
        var strings = BrandStrings.For(_settings.Language);
        BrandTaglineText.Text = strings.Tagline;
    }

    private void OnTick(DispatcherQueueTimer sender, object args)
    {
        var metrics = _monitor.GetSnapshot();

        double sentMbps = (metrics.Traffic.TotalBytesSent * 8.0) / 1024 / 1024;
        double recvMbps = (metrics.Traffic.TotalBytesRecv * 8.0) / 1024 / 1024;
        TrafficSentMetric.Update(Math.Min(100, sentMbps), $"{sentMbps:F1} Mbps");
        TrafficRecvMetric.Update(Math.Min(100, recvMbps), $"{recvMbps:F1} Mbps");

        TotalStats.Update(metrics.Traffic.TotalPackets);
        BlockedStats.Update(metrics.Traffic.BlockedPackets);

        double readMb = metrics.Resources.DiskReadBytesPerSec / 1024 / 1024;
        double writeMb = metrics.Resources.DiskWriteBytesPerSec / 1024 / 1024;
        DiskReadMetric.Update(Math.Min(100, readMb / 5), $"{readMb:F1} MB/s");
        DiskWriteMetric.Update(Math.Min(100, writeMb / 5), $"{writeMb:F1} MB/s");

        DiskQueueText.Text = metrics.Resources.DiskQueueLength.ToString();
        DiskActiveText.Text = $"{metrics.Resources.DiskActiveTimePercentage:F0}%";

        if (DetailsPopup.Visibility == Visibility.Visible)
        {
            UpdateDetailedSubsystemInfo(metrics);
        }

        UpdateIngressView(metrics.Ingress, metrics.IngressWatcher);
        UpdateIngressTelemetryView(metrics);

        CpuDetailed.Update(metrics.Resources.CpuUsagePercentage, $"{metrics.Resources.CpuUsagePercentage:F1}%");

        double totalRam = metrics.Resources.RamUsageBytes + metrics.Resources.RamAvailableBytes;
        double ramPercent = totalRam > 0 ? (metrics.Resources.RamUsageBytes / totalRam) * 100 : 0;
        RamDetailed.Update(ramPercent, $"{ramPercent:F1}%");
        RamDetailsText.Text = $"Available: {(metrics.Resources.RamAvailableBytes / 1024 / 1024 / 1024):F1} GB | Total: {(totalRam / 1024 / 1024 / 1024):F1} GB";

        GpuDetailed.Update(metrics.Resources.GpuUsagePercentage, $"{metrics.Resources.GpuUsagePercentage:F1}%");
        CudaDetailedMetric.Update(metrics.Resources.CudaCoreUtilization, $"{metrics.Resources.CudaCoreUtilization:F1}%");

        DiskDetailedRead.Update(Math.Min(100, readMb / 5), $"{readMb:F2} MB/s");
        DiskDetailedWrite.Update(Math.Min(100, writeMb / 5), $"{writeMb:F2} MB/s");
        DiskDetailedTime.Update(metrics.Resources.DiskActiveTimePercentage, $"{metrics.Resources.DiskActiveTimePercentage:F1}%");

        UpdateGpuPanels(metrics.Resources);
        CudaDetailedText.Text = $"{metrics.Resources.CudaCoreUtilization:F0}% Utilized";

        TrafficDetailsText.Text = $"Total Egress Sent: {(metrics.Traffic.TotalBytesSent / 1024 / 1024):F1} MB\n" +
                                  $"Allowed Packets: {metrics.Traffic.AllowedPackets}\n" +
                                  $"Blocked Packets: {metrics.Traffic.BlockedPackets}";

        _overlay.UpdateMetrics(metrics);

        if (App.TrayIcon != null)
        {
            App.TrayIcon.ToolTipText = $"VG Monitoring\nTraffic: {sentMbps:F1} Mbps Out\nDisk Load: {metrics.Resources.DiskActiveTimePercentage:F0}%";
        }

        // Refresh the process triage list a few seconds apart while its tab is open.
        _tickCounter++;
        if (IsProcessesTabSelected() && _tickCounter % 4 == 0)
        {
            RefreshProcesses();
        }
    }

    private bool IsProcessesTabSelected() =>
        MainPivot.SelectedItem is PivotItem { Header: "Processes" };

    private void OnPivotChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IsProcessesTabSelected())
        {
            RefreshProcesses();
        }
    }

    private void OnRefreshProcessesClick(object sender, RoutedEventArgs e) => RefreshProcesses();

    private void RefreshProcesses()
    {
        if (_processRefreshInFlight)
        {
            return;
        }

        _processRefreshInFlight = true;
        _ = Task.Run(() =>
        {
            try
            {
                var entries = _processInspector.Snapshot();
                DispatcherQueue.TryEnqueue(() => ApplyProcessSnapshot(entries));
            }
            catch (Exception ex)
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    ProcessStatusText.Text = $"Process enumeration failed: {ex.Message}";
                    _processRefreshInFlight = false;
                });
            }
        });
    }

    private void ApplyProcessSnapshot(IReadOnlyList<ProcessTriageEntry> entries)
    {
        var selectedPid = (ProcessList.SelectedItem as ProcessRowVM)?.Pid;

        var rows = entries.Select(entry => new ProcessRowVM(entry)).ToList();
        ProcessList.ItemsSource = rows;

        if (selectedPid is int pid)
        {
            var match = rows.FirstOrDefault(r => r.Pid == pid);
            if (match != null)
            {
                ProcessList.SelectedItem = match;
            }
        }

        var suspicious = rows.Count(r => r.Entry.Verdict.Disposition == ProcessDisposition.Suspicious);
        ProcessStatusText.Text = $"{rows.Count} processes · {suspicious} suspicious · updated {DateTimeOffset.Now:HH:mm:ss}";
        _processRefreshInFlight = false;
    }

    private void OnProcessSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ProcessList.SelectedItem is ProcessRowVM row)
        {
            ProcessReasonsText.Text = row.Reasons;
            TerminateProcessButton.IsEnabled = true;
        }
        else
        {
            ProcessReasonsText.Text = "Select a process to see why it was tagged.";
            TerminateProcessButton.IsEnabled = false;
        }
    }

    private async void OnTerminateProcessClick(object sender, RoutedEventArgs e)
    {
        if (ProcessList.SelectedItem is not ProcessRowVM row)
        {
            return;
        }

        var facts = row.Entry.Facts;
        var killSafety = row.Entry.Verdict.KillSafety;

        var warning = killSafety switch
        {
            KillSafety.BreaksWindows =>
                "This is an OS-critical process. Terminating it will very likely crash Windows or sign you out.",
            KillSafety.RiskyToShutdown =>
                "This process hosts services or a session component. Terminating it may disrupt Windows features.",
            _ => "This process appears safe to terminate."
        };

        var dialog = new ContentDialog
        {
            XamlRoot = Content.XamlRoot,
            Title = $"Terminate {facts.Name} (PID {facts.ProcessId})?",
            Content = $"{warning}\n\n{row.Reasons}",
            PrimaryButtonText = "Terminate",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(facts.ProcessId);
            process.Kill();
            ProcessStatusText.Text = $"Terminated {facts.Name} (PID {facts.ProcessId}).";
        }
        catch (Exception ex)
        {
            ProcessStatusText.Text = $"Could not terminate {facts.Name}: {ex.Message}";
        }

        RefreshProcesses();
    }

    private void UpdateDetailedSubsystemInfo(AggregateMetrics metrics)
    {
        var diskInfo = new StringBuilder();
        diskInfo.AppendLine($"Active Disk Queue: {metrics.Resources.DiskQueueLength}");
        diskInfo.AppendLine($"Disk Time: {metrics.Resources.DiskActiveTimePercentage:F2}%");
        diskInfo.AppendLine($"Current Read: {(metrics.Resources.DiskReadBytesPerSec / 1024):F0} KB/s");
        diskInfo.AppendLine($"Current Write: {(metrics.Resources.DiskWriteBytesPerSec / 1024):F0} KB/s");
        DiskDetailedDetails.Text = diskInfo.ToString();

        var netInfo = new StringBuilder();
        netInfo.AppendLine($"Total Sent: {(metrics.Traffic.TotalBytesSent / 1024 / 1024):F2} MB");
        netInfo.AppendLine($"Total Recv: {(metrics.Traffic.TotalBytesRecv / 1024 / 1024):F2} MB");
        netInfo.AppendLine($"Packet Throughput: {metrics.Traffic.TotalPackets} packets tracked");
        NetworkDetailedDetails.Text = netInfo.ToString();
    }

    private void OnToggleDetailsClick(object sender, RoutedEventArgs e)
    {
        DetailsPopup.Visibility = DetailsPopup.Visibility == Visibility.Visible
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private void OnOverlayToggled(object sender, RoutedEventArgs e)
    {
        if (ShowOverlayCheckbox.IsChecked == true) _overlay.Activate();
        else _overlay.HideOverlay();
    }

    private async void OnManageRulesClick(object sender, RoutedEventArgs e)
    {
        var rulesWindow = App.ServiceProvider?.GetRequiredService<RulesManagerWindow>();
        if (rulesWindow != null)
        {
            rulesWindow.Activate();
        }
        await Task.CompletedTask;
    }

    /// <summary>
    /// Rebuilds the per-GPU cards when the device count changes, then refreshes
    /// each in place so a multi-GPU machine shows every card rather than device 0.
    /// </summary>
    private void UpdateGpuPanels(SystemResourceMetrics resources)
    {
        var gpus = resources.GpuList;

        if (gpus.Count != _gpuPanels.Count)
        {
            _gpuPanels.Clear();
            GpuDetailedStack.Children.Clear();

            foreach (var _ in gpus)
            {
                var panel = new GpuPanel();
                _gpuPanels.Add(panel);
                GpuDetailedStack.Children.Add(panel);
            }
        }

        for (var i = 0; i < gpus.Count; i++)
        {
            _gpuPanels[i].Update(gpus[i]);
        }
    }

    private void UpdateIngressView(IngressTrafficSnapshot snapshot, IngressWatcherStatus watcherStatus)
    {
        _lastIngressStatus = watcherStatus;
        IngressStatusText.Text = FormatIngressStatus(watcherStatus);
        IngressPacketCountText.Text = snapshot.TotalPackets.ToString();
        IngressByteCountText.Text = $"{snapshot.TotalBytes / 1024.0 / 1024.0:F2} MB";
        IngressSourceCountText.Text = snapshot.Sources.Count.ToString();

        var previousKey = _selectedIngressFlow?.Key;
        _visibleIngressFlows = snapshot.Sources
            .SelectMany(source => source.Flows)
            .OrderByDescending(flow => flow.LastSeen)
            .ToList();

        // Only rebind ItemsSource when the visible set actually changed. Reassigning
        // every tick recreates the ListView item containers, causing scroll reset,
        // visible flicker, and unnecessary CPU on the timer thread.
        var signature = BuildIngressListSignature(_visibleIngressFlows);
        if (!string.Equals(signature, _lastIngressListSignature, StringComparison.Ordinal))
        {
            _lastIngressListSignature = signature;
            IngressSourceList.ItemsSource = _visibleIngressFlows.Select(FormatIngressFlowListItem).ToArray();
        }

        if (_visibleIngressFlows.Count == 0)
        {
            _selectedIngressFlow = null;
            IngressSourceList.SelectedIndex = -1;
            IngressDetailsText.Text = "No inbound packets archived yet.";
            IngressPayloadPreviewText.Text = "Payload preview will appear after inbound traffic is captured.";
            return;
        }

        var selectedIndex = previousKey == null
            ? 0
            : _visibleIngressFlows.FindIndex(flow => flow.Key == previousKey);

        IngressSourceList.SelectedIndex = selectedIndex >= 0 ? selectedIndex : 0;
        _selectedIngressFlow = _visibleIngressFlows[IngressSourceList.SelectedIndex];
        RenderIngressFlowDetails(_selectedIngressFlow);
    }

    private static string BuildIngressListSignature(IReadOnlyList<IngressFlowSummary> flows)
    {
        if (flows.Count == 0) return string.Empty;
        var sb = new System.Text.StringBuilder(flows.Count * 32);
        foreach (var flow in flows)
        {
            sb.Append(flow.Key).Append('@').Append(flow.LastSeen.UtcTicks).Append('|');
        }
        return sb.ToString();
    }

    private void OnIngressSourceSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (IngressSourceList.SelectedIndex < 0 || IngressSourceList.SelectedIndex >= _visibleIngressFlows.Count)
        {
            return;
        }

        _selectedIngressFlow = _visibleIngressFlows[IngressSourceList.SelectedIndex];
        RenderIngressFlowDetails(_selectedIngressFlow);
    }

    private void UpdateIngressTelemetryView(AggregateMetrics metrics)
    {
        MitmProxyStatusText.Text = FormatMitmStatus(metrics.MitmProxy);
        FullTraceStatusText.Text = metrics.FullTrace.State == FullTraceState.Active
            ? $"Full trace: active | {metrics.FullTrace.CapturedPackets:N0} packets | {metrics.FullTrace.CapturedBytes:N0} bytes"
            : $"Full trace: {metrics.FullTrace.State}";

        IngressTelemetryHitsList.ItemsSource = metrics.IngressTelemetryHits
            .Select(hit => $"{hit.DetectedAt:HH:mm:ss} | {hit.SelectorLabel} | {hit.Host ?? hit.Source} | {hit.EvidencePreview}")
            .ToArray();
    }

    private async void OnClearIngressArchiveClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var shouldClear = await ConfirmIngressArchiveClearAsync();
            if (!shouldClear)
            {
                return;
            }

            await _ingressStore.ClearAsync();
            _selectedIngressFlow = null;
            UpdateIngressView(IngressTrafficSnapshot.Empty, _lastIngressStatus);
            await ShowIngressDialogAsync("Ingress archive cleared.", "Archive cleared");
        }
        catch (Exception ex)
        {
            IngressPayloadPreviewText.Text = $"Failed to clear ingress archive:\n{ex.Message}";
        }
    }

    private async void OnExportIngressFlowClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_selectedIngressFlow == null)
            {
                IngressPayloadPreviewText.Text = "Select an ingress flow before exporting.";
                return;
            }

            var exportDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ingress-exports");
            var path = await _ingressStore.ExportFlowAsync(_selectedIngressFlow.Key, exportDirectory);
            IngressPayloadPreviewText.Text = $"Exported selected flow to:\n{path}";
            await ShowIngressDialogAsync(path, "Flow exported");
        }
        catch (Exception ex)
        {
            IngressPayloadPreviewText.Text = $"Failed to export ingress flow:\n{ex.Message}";
        }
    }

    private async void OnStartBrowserMitmClick(object sender, RoutedEventArgs e)
    {
        try
        {
            await _mitmProxyService.StartAsync(CancellationToken.None);
            MitmProxyStatusText.Text = FormatMitmStatus(_mitmProxyService.GetStatus());
        }
        catch (Exception ex)
        {
            MitmProxyStatusText.Text = $"Browser MITM: failed - {ex.Message}";
        }
    }

    private async void OnStopBrowserMitmClick(object sender, RoutedEventArgs e)
    {
        await _mitmProxyService.StopAsync(CancellationToken.None);
        MitmProxyStatusText.Text = FormatMitmStatus(_mitmProxyService.GetStatus());
    }

    private async Task<bool> ConfirmIngressArchiveClearAsync()
    {
        if (Content is not FrameworkElement root || root.XamlRoot == null)
        {
            return true;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = root.XamlRoot,
            Title = "Clear ingress archive?",
            Content = "This removes archived ingress metadata and payload samples from this machine.",
            PrimaryButtonText = "Clear",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };

        return await dialog.ShowAsync() == ContentDialogResult.Primary;
    }

    private async Task ShowIngressDialogAsync(string content, string title)
    {
        if (Content is not FrameworkElement root || root.XamlRoot == null)
        {
            return;
        }

        var dialog = new ContentDialog
        {
            XamlRoot = root.XamlRoot,
            Title = title,
            Content = new TextBox
            {
                Text = content,
                IsReadOnly = true,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                MinWidth = 420,
            },
            CloseButtonText = "OK",
        };
        await dialog.ShowAsync();
    }

    private static string FormatIngressFlowListItem(IngressFlowSummary flow)
    {
        return $"{flow.Key.RemoteAddress}:{flow.Key.RemotePort} -> {flow.Key.ProcessName}:{flow.Key.LocalPort} | " +
               $"{flow.PacketCount} packets | {flow.TotalPayloadBytes / 1024.0:F1} KB";
    }

    private string FormatIngressStatus(IngressWatcherStatus status)
    {
        if (!_settings.EnableIngressPacketCapture)
        {
            return "Capture: disabled in settings; enable passive ingress packet capture and restart to watch packets.";
        }

        if (status.IsRunning)
        {
            var counters = status.SkippedPackets > 0 || status.SuppressedPayloadSamples > 0
                ? $" | archived {status.ArchivedPackets:N0}, skipped {status.SkippedPackets:N0}, samples suppressed {status.SuppressedPayloadSamples:N0}"
                : $" | archived {status.ArchivedPackets:N0}";

            return status.StartedAt is { } startedAt
                ? $"Capture: running since {startedAt:ddd, dd MMM yyyy HH:mm:ss}{counters}"
                : "Capture: running" + counters;
        }

        if (status.State == IngressWatcherState.Faulted)
        {
            var detail = status.Warning ?? status.LastError ?? "Capture stopped after an ingress watcher fault.";
            return $"Capture: stopped - {detail}";
        }

        return $"Capture: {status.State}";
    }

    private static string FormatMitmStatus(MitmProxyStatus status)
    {
        var importDetail = status.ImportedFlows > 0
            ? $" | imported {status.ImportedFlows:N0} flows"
            : string.Empty;
        var errorDetail = string.IsNullOrWhiteSpace(status.LastError)
            ? string.Empty
            : $" | import warning: {status.LastError}";

        return status.State == MitmProxyState.Running
            ? $"Browser MITM: running on 127.0.0.1:{status.ListenPort}{importDetail}{errorDetail}"
            : $"Browser MITM: {status.State}{importDetail}{errorDetail}";
    }

    private void RenderIngressFlowDetails(IngressFlowSummary flow)
    {
        IngressDetailsText.Text =
            $"Remote: {flow.Key.RemoteAddress}:{flow.Key.RemotePort}\n" +
            $"Local: {flow.Key.LocalAddress}:{flow.Key.LocalPort}\n" +
            $"Process: {flow.Key.ProcessName} (PID {flow.Key.ProcessId})\n" +
            $"Path: {flow.Key.ProcessPath}\n" +
            $"Protocol: {flow.Key.Protocol}\n" +
            $"Packets: {flow.PacketCount}\n" +
            $"Bytes: {flow.TotalBytes:N0} total / {flow.TotalPayloadBytes:N0} payload\n" +
            $"First seen: {flow.FirstSeen:ddd, dd MMM yyyy HH:mm:ss}\n" +
            $"Last seen: {flow.LastSeen:ddd, dd MMM yyyy HH:mm:ss}";

        var sample = flow.RecentSamples.FirstOrDefault();
        if (sample == null)
        {
            IngressPayloadPreviewText.Text = "No payload bytes captured for this flow yet.";
            return;
        }

        var preview = sample.TextPreview;
        if (string.IsNullOrWhiteSpace(preview))
        {
            preview = Convert.ToHexString(sample.StoredBytes.Take(128).ToArray());
        }

        IngressPayloadPreviewText.Text =
            $"Classification: {sample.Classification}\n" +
            $"Stored: {sample.StoredBytes.Length:N0} of {sample.OriginalLength:N0} bytes\n" +
            $"Body capture suppressed: {sample.BodyCaptureSuppressed}\n" +
            $"Reason: {sample.Reason}\n\n" +
            preview;
    }

    public async Task ShowSettingsAsync()
    {
        try { this.Activate(); } catch { }
        if (Content is not FrameworkElement root || root.XamlRoot == null) return;
        try
        {
            var dialog = new SettingsDialog(_settings) { XamlRoot = root.XamlRoot };
            await dialog.ShowAsync();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[VaultGuardian] ShowSettingsAsync failed: {ex}");
        }
    }

    private void OnWindowClosed(object sender, WindowEventArgs args)
    {
        _timer.Stop();
        _settings.Changed -= OnSettingsChanged;

        if (_settings.MinimizeToTrayOnClose)
        {
            // Hide rather than fully close — re-show via tray.
            // WinUI 3 doesn't surface a clean cancel on Closed, so the consumer
            // hides on click instead via the AppWindow presenter.
        }
    }
}
