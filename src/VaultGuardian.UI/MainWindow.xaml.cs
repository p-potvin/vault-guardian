using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
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
    private readonly DispatcherTimer _timer;
    private readonly TaskbarIcon? _trayIcon;

    public MainWindow(LiveMonitorService monitor, OverlayWindow overlay)
    {
        // Assign dependencies first
        _monitor = monitor;
        _overlay = overlay;

        InitializeComponent();

        _trayIcon = Application.Current.FindResource("NotifyIcon") as TaskbarIcon;

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _timer.Tick += OnTick;
        _timer.Start();

        // Note: _overlay.Show() may now be redundant if the CheckBox 
        // triggers it during InitializeComponent, but calling it 
        // again is safe in WPF.
        _overlay.Show();
    }

    private void OnTick(object? sender, EventArgs e)
    {
        var metrics = _monitor.GetLatestMetrics();
        
        // Update Dashboard
        CpuMetric.Update(metrics.Resources.CpuUsagePercentage, $"{metrics.Resources.CpuUsagePercentage:F1}%");
        
        double totalRam = metrics.Resources.RamUsageBytes + metrics.Resources.RamAvailableBytes;
        double ramPercent = totalRam > 0 ? (metrics.Resources.RamUsageBytes / totalRam) * 100 : 0;
        RamMetric.Update(ramPercent, $"{(metrics.Resources.RamUsageBytes / 1024 / 1024 / 1024):F1} GB");
        
        GpuMetric.Update(metrics.Resources.GpuUsagePercentage, $"{metrics.Resources.GpuUsagePercentage:F1}%");

        TotalStats.Update(metrics.Traffic.TotalPackets);
        AllowedStats.Update(metrics.Traffic.AllowedPackets);
        BlockedStats.Update(metrics.Traffic.BlockedPackets);

        // Update Overlay
        if (_overlay.IsVisible)
        {
            _overlay.UpdateMetrics(metrics);
        }

        // Update Tray Tooltip
        if (_trayIcon != null)
        {
            _trayIcon.ToolTipText = $"VG Monitor\nCPU: {metrics.Resources.CpuUsagePercentage:F0}% | GPU: {metrics.Resources.GpuUsagePercentage:F0}%\nBlocked: {metrics.Traffic.BlockedPackets}";
        }
    }

    private void OnOverlayToggled(object sender, RoutedEventArgs e)
    {
        if (ShowOverlayCheckbox.IsChecked == true) _overlay.Show();
        else _overlay.Hide();
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        // Minimize to tray instead of closing
        e.Cancel = true;
        this.Hide();
    }
}