using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using VaultGuardian.Core.Observability;
using Windows.Graphics;

namespace VaultGuardian.UI;

public sealed partial class OverlayWindow : Window
{
    private const int OverlayWidth = 224;

    // Header + CPU + RAM + CUDA + padding, with each GPU row added on top.
    private const int BaseHeight = 148;
    private const int PerGpuHeight = 27;

    private readonly AppWindow _appWindow;
    private readonly OverlappedPresenter _presenter;
    private readonly Storyboard _ledPulse;
    private readonly List<GpuRow> _gpuRows = [];

    private bool _isDragging;
    private POINT _dragStartCursor;
    private PointInt32 _dragStartWindowPosition;
    private int _renderedGpuCount = -1;

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

        ResizeForGpuCount(0);
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

    // ── Dragging ──────────────────────────────────────────────────────────
    //
    // Previously this handed off to Windows' modal move loop via
    // WM_NCLBUTTONDOWN/HTCAPTION. Because WinUI had already handled the press,
    // that loop started without a held button and behaved like click-to-pick-up,
    // move, click-to-drop. Tracking the pointer ourselves restores the normal
    // press, drag, release gesture.
    //
    // Screen cursor position is used rather than the event's position: the latter
    // is relative to the window we are moving, which would feed back into itself.

    private void OverlayRoot_PointerPressed(object sender, PointerRoutedEventArgs e)
    {
        var element = (UIElement)sender;
        var properties = e.GetCurrentPoint(element).Properties;
        if (!properties.IsLeftButtonPressed) return;

        if (!GetCursorPos(out _dragStartCursor)) return;

        _dragStartWindowPosition = _appWindow.Position;
        _isDragging = element.CapturePointer(e.Pointer);
        e.Handled = _isDragging;
    }

    private void OverlayRoot_PointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (!_isDragging) return;
        if (!GetCursorPos(out var current)) return;

        _appWindow.Move(new PointInt32(
            _dragStartWindowPosition.X + (current.X - _dragStartCursor.X),
            _dragStartWindowPosition.Y + (current.Y - _dragStartCursor.Y)));

        e.Handled = true;
    }

    private void OverlayRoot_PointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (!_isDragging) return;

        ((UIElement)sender).ReleasePointerCapture(e.Pointer);
        EndDrag();
        e.Handled = true;
    }

    private void OverlayRoot_PointerCaptureLost(object sender, PointerRoutedEventArgs e) => EndDrag();

    private void EndDrag()
    {
        if (!_isDragging) return;
        _isDragging = false;
        SnapToGrid();
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

    public void HideOverlay() => _appWindow.Hide();

    // ── Metrics ───────────────────────────────────────────────────────────

    public void UpdateMetrics(AggregateMetrics metrics)
    {
        CpuText.Text = $"{metrics.Resources.CpuUsagePercentage:F1}%";
        CpuBar.Value = metrics.Resources.CpuUsagePercentage;

        double totalRam = metrics.Resources.RamUsageBytes + metrics.Resources.RamAvailableBytes;
        double ramPercent = totalRam > 0 ? (metrics.Resources.RamUsageBytes / totalRam) * 100 : 0;
        RamText.Text = $"{(metrics.Resources.RamUsageBytes / 1024 / 1024 / 1024):F1} GB";
        RamBar.Value = ramPercent;

        UpdateGpuRows(metrics.Resources);

        CudaText.Text = $"{metrics.Resources.CudaCoreUtilization:F1}%";
        CudaBar.Value = metrics.Resources.CudaCoreUtilization;

        BlockedText.Text = metrics.Traffic.BlockedPackets.ToString();
    }

    private void UpdateGpuRows(SystemResourceMetrics resources)
    {
        var gpus = resources.GpuList;

        // Fall back to the flat single-GPU fields when NVML reported no devices,
        // so the overlay still shows a GPU line on non-NVIDIA machines.
        if (gpus.Count == 0)
        {
            EnsureGpuRows(1);
            _gpuRows[0].Update("GPU", resources.GpuUsagePercentage);
            return;
        }

        EnsureGpuRows(gpus.Count);
        for (var i = 0; i < gpus.Count; i++)
        {
            _gpuRows[i].Update(ShortGpuLabel(gpus[i], gpus.Count), gpus[i].UsagePercentage);
        }
    }

    /// <summary>Trims vendor prefixes so the label fits the narrow overlay.</summary>
    private static string ShortGpuLabel(GpuMetrics gpu, int totalGpus)
    {
        var name = gpu.Name
            .Replace("NVIDIA ", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("GeForce ", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Trim();

        if (string.IsNullOrWhiteSpace(name)) name = $"GPU {gpu.Index}";
        return totalGpus > 1 ? $"{gpu.Index}: {name}" : name;
    }

    private void EnsureGpuRows(int count)
    {
        if (_renderedGpuCount == count) return;

        GpuStack.Children.Clear();
        _gpuRows.Clear();

        for (var i = 0; i < count; i++)
        {
            var row = GpuRow.Create(this);
            _gpuRows.Add(row);
            GpuStack.Children.Add(row.Container);
        }

        _renderedGpuCount = count;
        ResizeForGpuCount(count);
    }

    /// <summary>Grows the window instead of scrolling, so no GPU is hidden.</summary>
    private void ResizeForGpuCount(int gpuCount)
    {
        var height = BaseHeight + (Math.Max(gpuCount, 1) * PerGpuHeight);
        _appWindow.Resize(new SizeInt32(OverlayWidth, height));
    }

    /// <summary>One label + percentage + bar, mirroring the CPU/RAM rows in XAML.</summary>
    private sealed class GpuRow
    {
        public required StackPanel Container { get; init; }
        public required TextBlock Label { get; init; }
        public required TextBlock Value { get; init; }
        public required ProgressBar Bar { get; init; }

        public void Update(string label, double percentage)
        {
            Label.Text = label;
            Value.Text = $"{percentage:F1}%";
            Bar.Value = percentage;
        }

        public static GpuRow Create(OverlayWindow owner)
        {
            var label = new TextBlock
            {
                FontSize = 11,
                Foreground = owner.Resource<Brush>("SecondaryTextBrush"),
                TextTrimming = TextTrimming.CharacterEllipsis,
            };

            var value = new TextBlock
            {
                FontSize = 11,
                FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Right,
                FontFamily = owner.Resource<FontFamily>("VaultMonoFontFamily"),
                Foreground = owner.Resource<Brush>("PrimaryTextBrush"),
            };

            var header = new Grid { Margin = new Thickness(0, 0, 0, 4) };
            header.Children.Add(label);
            header.Children.Add(value);

            var bar = new ProgressBar
            {
                Height = 2,
                Margin = new Thickness(0, 0, 0, 8),
                Foreground = owner.Resource<Brush>("IrisBrush"),
            };

            var container = new StackPanel();
            container.Children.Add(header);
            container.Children.Add(bar);

            return new GpuRow { Container = container, Label = label, Value = value, Bar = bar };
        }
    }

    private T Resource<T>(string key) => (T)Application.Current.Resources[key];

    // ── Win32 ─────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT lpPoint);
}
