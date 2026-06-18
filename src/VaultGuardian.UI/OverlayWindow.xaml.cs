using System;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media.Animation;
using VaultGuardian.Core.Observability;
using Windows.Graphics;

namespace VaultGuardian.UI;

public sealed partial class OverlayWindow : Window
{
    private readonly AppWindow _appWindow;
    private readonly OverlappedPresenter _presenter;
    private readonly Storyboard _ledPulse;

    public OverlayWindow()
    {
        InitializeComponent();

        Title = "VaultGuardian Metrics Overlay";

        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var windowId = Win32Interop.GetWindowIdFromWindow(hwnd);
        _appWindow = AppWindow.GetFromWindowId(windowId);

        _presenter = OverlappedPresenter.Create();
        _presenter.IsAlwaysOnTop = true;
        _presenter.IsResizable = false;
        _presenter.IsMaximizable = false;
        _presenter.IsMinimizable = false;
        _presenter.SetBorderAndTitleBar(false, false);
        _appWindow.SetPresenter(_presenter);
        _appWindow.IsShownInSwitchers = false;

        _appWindow.Resize(new SizeInt32(200, 150));

        SystemBackdrop = new Microsoft.UI.Xaml.Media.DesktopAcrylicBackdrop();

        PositionInCorner();

        _ledPulse = BuildLedPulseStoryboard();
        _ledPulse.Begin();
    }

    private Storyboard BuildLedPulseStoryboard()
    {
        var sb = new Storyboard { RepeatBehavior = RepeatBehavior.Forever, AutoReverse = true };
        var animX = new DoubleAnimation
        {
            From = 1.0, To = 1.6, Duration = new Duration(TimeSpan.FromMilliseconds(900)),
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        var animY = new DoubleAnimation
        {
            From = 1.0, To = 1.6, Duration = new Duration(TimeSpan.FromMilliseconds(900)),
            EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
        };
        Storyboard.SetTarget(animX, LedScale);
        Storyboard.SetTargetProperty(animX, "ScaleX");
        Storyboard.SetTarget(animY, LedScale);
        Storyboard.SetTargetProperty(animY, "ScaleY");
        sb.Children.Add(animX);
        sb.Children.Add(animY);
        return sb;
    }

    private void OverlayRoot_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        var props = e.GetCurrentPoint((Microsoft.UI.Xaml.UIElement)sender).Properties;
        if (props.IsLeftButtonPressed)
        {
            _presenter.SetBorderAndTitleBar(false, false);

            // BeginMoveResize requires HTCAPTION (=2); WindowsAppSDK exposes this via OverlappedPresenter
            // through a Win32 SendMessage WM_NCLBUTTONDOWN. We call into Win32 directly.
            const int WM_NCLBUTTONDOWN = 0x00A1;
            const int HTCAPTION = 2;
            var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
            ReleaseCapture();
            SendMessage(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
            SnapToGrid();
        }
    }

    private void SnapToGrid()
    {
        const int snapDistance = 20;
        const int gridSize = 40;

        var workArea = DisplayArea.GetFromWindowId(_appWindow.Id, DisplayAreaFallback.Nearest).WorkArea;
        var pos = _appWindow.Position;
        var size = _appWindow.Size;

        int newLeft = (int)Math.Round(pos.X / (double)gridSize) * gridSize;
        int newTop = (int)Math.Round(pos.Y / (double)gridSize) * gridSize;

        if (Math.Abs(newLeft - workArea.X) < snapDistance) newLeft = workArea.X;
        if (Math.Abs(newLeft + size.Width - (workArea.X + workArea.Width)) < snapDistance)
            newLeft = workArea.X + workArea.Width - size.Width;

        if (Math.Abs(newTop - workArea.Y) < snapDistance) newTop = workArea.Y;
        if (Math.Abs(newTop + size.Height - (workArea.Y + workArea.Height)) < snapDistance)
            newTop = workArea.Y + workArea.Height - size.Height;

        if (newLeft != pos.X || newTop != pos.Y)
        {
            _appWindow.Move(new PointInt32(newLeft, newTop));
        }
    }

    private void PositionInCorner()
    {
        var workArea = DisplayArea.GetFromWindowId(_appWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        var size = _appWindow.Size;
        _appWindow.Move(new PointInt32(
            workArea.X + workArea.Width - size.Width - 10,
            workArea.Y + 10));
    }

    public void HideOverlay()
    {
        _appWindow.Hide();
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

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ReleaseCapture();
}
