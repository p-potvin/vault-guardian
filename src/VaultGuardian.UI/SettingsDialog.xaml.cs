using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;

namespace VaultGuardian.UI;

public sealed partial class SettingsDialog : ContentDialog
{
    private readonly AppSettings _settings;

    public SettingsDialog(AppSettings settings)
    {
        InitializeComponent();
        _settings = settings;

        RefreshSlider.Value = _settings.RefreshRateMs;
        RefreshValueText.Text = $"{_settings.RefreshRateMs} ms";
        MinimizeToTrayCheck.IsChecked = _settings.MinimizeToTrayOnClose;
        StartupCheck.IsChecked = _settings.RunAtStartup;

        PrimaryButtonClick += OnPrimaryClick;
    }

    private void OnSliderChanged(object sender, RangeBaseValueChangedEventArgs e)
    {
        RefreshValueText.Text = $"{(int)e.NewValue} ms";
    }

    private void OnPrimaryClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        _settings.RefreshRateMs = (int)RefreshSlider.Value;
        _settings.MinimizeToTrayOnClose = MinimizeToTrayCheck.IsChecked == true;
        _settings.RunAtStartup = StartupCheck.IsChecked == true;
        _settings.Save();
        _settings.NotifyChanged();
    }
}
