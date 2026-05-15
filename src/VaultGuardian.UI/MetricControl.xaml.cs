using System.Windows.Media;
using System.Windows.Controls;

namespace VaultGuardian.UI;

public partial class MetricControl : UserControl
{
    public string Label { set => LabelText.Text = value; }
    public Color Color { set => Bar.Foreground = new SolidColorBrush(value); }

    public MetricControl()
    {
        InitializeComponent();
    }

    public void Update(double value, string display)
    {
        Bar.Value = value;
        ValueText.Text = display;
    }
}
