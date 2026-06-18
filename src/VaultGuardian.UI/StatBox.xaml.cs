using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace VaultGuardian.UI;

public partial class StatBox : UserControl
{
    public string Label { set => LabelText.Text = value; }
    public Color Color { set => NumText.Foreground = new SolidColorBrush(value); }

    public StatBox()
    {
        InitializeComponent();
    }

    public void Update(long value)
    {
        NumText.Text = value.ToString();
    }
}
