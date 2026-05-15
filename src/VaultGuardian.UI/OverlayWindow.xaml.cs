using System.Windows;
using VaultGuardian.Core.Observability;

namespace VaultGuardian.UI;

public partial class OverlayWindow : Window
{
    public OverlayWindow()
    {
        InitializeComponent();
        PositionInCorner();
    }

    private void PositionInCorner()
    {
        var desktopWorkingArea = SystemParameters.WorkArea;
        this.Left = desktopWorkingArea.Right - this.Width - 10;
        this.Top = desktopWorkingArea.Top + 10;
    }

    public void UpdateMetrics(AggregateMetrics metrics)
    {
        CpuText.Text = $"{metrics.Resources.CpuUsagePercentage:F1}%";
        CpuBar.Value = metrics.Resources.CpuUsagePercentage;

        double totalRam = metrics.Resources.RamUsageBytes + metrics.Resources.RamAvailableBytes;
        double ramPercent = totalRam > 0 ? (metrics.Resources.RamUsageBytes / totalRam) * 100 : 0;
        RamText.Text = $"{(metrics.Resources.RamUsageBytes / 1024 / 1024 / 1024):F1} GB";
        RamBar.Value = ramPercent;

        GpuText.Text = $"{metrics.Resources.GpuUsagePercentage:F1}%";
        GpuBar.Value = metrics.Resources.GpuUsagePercentage;
        
        BlockedText.Text = metrics.Traffic.BlockedPackets.ToString();
    }
}
