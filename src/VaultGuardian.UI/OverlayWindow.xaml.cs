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

    private void Window_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.LeftButton == System.Windows.Input.MouseButtonState.Pressed)
        {
            this.DragMove();
        }
    }

    private void Window_LocationChanged(object sender, EventArgs e)
    {
        if (System.Windows.Input.Mouse.LeftButton == System.Windows.Input.MouseButtonState.Pressed)
        {
            const double snapDistance = 20.0;
            const double gridSize = 40.0;
            var workArea = SystemParameters.WorkArea;

            double newLeft = this.Left;
            double newTop = this.Top;

            // Snap to Grid (Virtual Desktop Desktop Icons simulation)
            newLeft = Math.Round(newLeft / gridSize) * gridSize;
            newTop = Math.Round(newTop / gridSize) * gridSize;

            // Snap to Edges
            if (Math.Abs(newLeft - workArea.Left) < snapDistance) newLeft = workArea.Left;
            if (Math.Abs(newLeft + this.Width - workArea.Right) < snapDistance) newLeft = workArea.Right - this.Width;

            if (Math.Abs(newTop - workArea.Top) < snapDistance) newTop = workArea.Top;
            if (Math.Abs(newTop + this.Height - workArea.Bottom) < snapDistance) newTop = workArea.Bottom - this.Height;

            // Only apply if it actually changed to prevent jitter
            if (Math.Abs(this.Left - newLeft) > 1) this.Left = newLeft;
            if (Math.Abs(this.Top - newTop) > 1) this.Top = newTop;
        }
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

        CudaText.Text = $"{metrics.Resources.CudaCoreUtilization:F1}%";
        CudaBar.Value = metrics.Resources.CudaCoreUtilization;

        BlockedText.Text = metrics.Traffic.BlockedPackets.ToString();
    }
}
