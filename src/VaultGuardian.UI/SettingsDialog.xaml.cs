using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.Win32;
using VaultGuardian.Core;

namespace VaultGuardian.UI;

public sealed partial class SettingsDialog : ContentDialog
{
    private const string StartupRegistryKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupValueName = "VaultGuardian";

    private readonly AppSettings _settings;

    public SettingsDialog(AppSettings settings)
    {
        InitializeComponent();
        _settings = settings;

        RefreshSlider.Value = _settings.RefreshIntervalMs;
        RefreshValueText.Text = $"{_settings.RefreshIntervalMs} ms";
        MinimizeToTrayCheck.IsChecked = _settings.MinimizeToTrayOnClose;
        StartupCheck.IsChecked = IsRegisteredForStartup();
        IngressCaptureCheck.IsChecked = _settings.EnableIngressPacketCapture;

        PrimaryButtonClick += OnPrimaryClick;
    }

    private void OnSliderChanged(object sender, RangeBaseValueChangedEventArgs e)
    {
        RefreshValueText.Text = $"{(int)e.NewValue} ms";
    }

    private void OnPrimaryClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        _settings.RefreshIntervalMs = (int)RefreshSlider.Value;
        _settings.MinimizeToTrayOnClose = MinimizeToTrayCheck.IsChecked == true;
        _settings.EnableIngressPacketCapture = IngressCaptureCheck.IsChecked == true;
        ApplyStartupRegistration(StartupCheck.IsChecked == true);
        AppSettingsLoader.Save(_settings);
        _settings.NotifyChanged();
    }

    private static bool IsRegisteredForStartup()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistryKey, writable: false);
            return key?.GetValue(StartupValueName) != null;
        }
        catch { return false; }
    }

    private static void ApplyStartupRegistration(bool enable)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistryKey, writable: true);
            if (key == null) return;
            if (enable)
                key.SetValue(StartupValueName, $"\"{System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName}\"");
            else
                key.DeleteValue(StartupValueName, throwOnMissingValue: false);
        }
        catch { /* best-effort */ }
    }
}
