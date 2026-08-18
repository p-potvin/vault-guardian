using Microsoft.UI.Xaml.Controls;
using VaultGuardian.Core.Observability;
using Windows.UI;

namespace VaultGuardian.UI;

/// <summary>
/// One card per physical GPU. The Performance tab stacks these, so a machine with
/// several cards shows each in full rather than only device 0.
/// </summary>
public sealed partial class GpuPanel : UserControl
{
    private const double BytesPerGigabyte = 1024d * 1024d * 1024d;

    public GpuPanel()
    {
        InitializeComponent();

        // Iris for load, coral for memory, so the two bars stay distinguishable.
        LoadMetric.Color = Color.FromArgb(0xFF, 0x6E, 0x7B, 0xF2);
        VramMetric.Color = Color.FromArgb(0xFF, 0xFF, 0x8A, 0x6B);
    }

    public void Update(GpuMetrics gpu)
    {
        TitleText.Text = $"GPU {gpu.Index} — {gpu.Name}".ToUpperInvariant();

        LoadMetric.Update(gpu.UsagePercentage, $"{gpu.UsagePercentage:F1}%");
        VramMetric.Update(gpu.MemoryUsedPercentage, $"{gpu.MemoryUsedPercentage:F1}%");
        VramDetailText.Text =
            $"{gpu.MemoryUsedBytes / BytesPerGigabyte:F1} / {gpu.MemoryTotalBytes / BytesPerGigabyte:F1} GB";

        TempText.Text = $"{gpu.TempCelsius:0}°C";
        FanText.Text = $"{gpu.FanSpeedPercentage}%";
        PowerText.Text = $"{gpu.PowerDrawWatts:F1} W";
    }
}
