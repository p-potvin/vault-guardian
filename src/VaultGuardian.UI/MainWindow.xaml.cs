using System.Text;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using VaultGuardian.Core;
using VaultGuardian.Core.Observability;
using H.NotifyIcon;

namespace VaultGuardian.UI;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private readonly LiveMonitorService _monitor;
    private readonly OverlayWindow _overlay;
    private readonly AppSettings _settings;
    private readonly DispatcherTimer _timer;
    private readonly TaskbarIcon? _trayIcon;

    public MainWindow(LiveMonitorService monitor, OverlayWindow overlay, AppSettings settings)
    {
        _monitor = monitor;
        _overlay = overlay;
        _settings = settings;

        InitializeComponent();

        _trayIcon = Application.Current.FindResource("NotifyIcon") as TaskbarIcon;

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(_settings.RefreshIntervalMs)
        };
        _timer.Tick += OnTick;
        _timer.Start();

        _settings.Changed += OnSettingsChanged;

        if (_settings.ShowOverlayOnStart)
        {
            ShowOverlayCheckbox.IsChecked = true;
            _overlay.Show();
        }
        else
        {
            ShowOverlayCheckbox.IsChecked = false;
        }
    }

    private void OnSettingsChanged(object? sender, EventArgs e)
        => _timer.Interval = TimeSpan.FromMilliseconds(_settings.RefreshIntervalMs);

    private void OnTick(object? sender, EventArgs e)
    {
        var metrics = _monitor.GetLatestMetrics();

        // --- Tab 1: Dashboard Updates ---
        // Network
        double sentMbps = (metrics.Traffic.TotalBytesSent * 8.0) / 1024 / 1024;
        double recvMbps = (metrics.Traffic.TotalBytesRecv * 8.0) / 1024 / 1024;
        TrafficSentMetric.Update(Math.Min(100, sentMbps), $"{sentMbps:F1} Mbps");
        TrafficRecvMetric.Update(Math.Min(100, recvMbps), $"{recvMbps:F1} Mbps");

        TotalStats.Update(metrics.Traffic.TotalPackets);
        BlockedStats.Update(metrics.Traffic.BlockedPackets);

        // Disk
        double readMb = metrics.Resources.DiskReadBytesPerSec / 1024 / 1024;
        double writeMb = metrics.Resources.DiskWriteBytesPerSec / 1024 / 1024;
        DiskReadMetric.Update(Math.Min(100, readMb / 5), $"{readMb:F1} MB/s"); // Normalized to 500MB/s base
        DiskWriteMetric.Update(Math.Min(100, writeMb / 5), $"{writeMb:F1} MB/s");

        DiskQueueText.Text = metrics.Resources.DiskQueueLength.ToString();
        DiskActiveText.Text = $"{metrics.Resources.DiskActiveTimePercentage:F0}%";

        // Details Panel (Update only if visible)
        if (DetailsPopup.Visibility == Visibility.Visible)
        {
            UpdateDetailedSubsystemInfo(metrics);
        }

        // --- Tab 2: Performance Info Updates ---
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

        double vramPercent = metrics.Resources.GpuMemoryTotalBytes > 0 ? (metrics.Resources.GpuMemoryUsedBytes / metrics.Resources.GpuMemoryTotalBytes) * 100 : 0;
        GpuVramMetric.Update(vramPercent, $"{(metrics.Resources.GpuMemoryUsedBytes / 1024 / 1024 / 1024):F1} GB");

        GpuTempText.Text = $"{metrics.Resources.GpuTempCelsius:0}°C";
        GpuFanText.Text = $"{metrics.Resources.GpuFanSpeedPercentage}%";
        GpuPowerText.Text = $"{metrics.Resources.GpuPowerDrawWatts:F1} W";
        CudaDetailedText.Text = $"{metrics.Resources.CudaCoreUtilization:F0}% Utilized";

        TrafficDetailsText.Text = $"Total Egress Sent: {(metrics.Traffic.TotalBytesSent / 1024 / 1024):F1} MB\n" +
                                  $"Allowed Packets: {metrics.Traffic.AllowedPackets}\n" +
                                  $"Blocked Packets: {metrics.Traffic.BlockedPackets}";

        // Update Overlay
        if (_overlay.IsVisible)
        {
            _overlay.UpdateMetrics(metrics);
        }

        // Update Tray Tooltip
        if (_trayIcon != null)
        {
            _trayIcon.ToolTipText = $"VG Monitoring\nTraffic: {sentMbps:F1} Mbps Out\nDisk Load: {metrics.Resources.DiskActiveTimePercentage:F0}%";
        }
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
        if (ShowOverlayCheckbox.IsChecked == true) _overlay.Show();
        else _overlay.Hide();
    }

    private void OnManageRulesClick(object sender, RoutedEventArgs e)
    {
        var rulesWindow = App.ServiceProvider?.GetRequiredService<RulesManagerWindow>();
        if (rulesWindow != null)
        {
            rulesWindow.Owner = this;
            rulesWindow.ShowDialog();
        }
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (_settings.MinimizeToTrayOnClose)
        {
            e.Cancel = true;
            this.Hide();
        }
    }
}