using System.Windows;
using Microsoft.Win32;
using VaultGuardian.Core;

namespace VaultGuardian.UI;

public partial class SettingsWindow : Window
{
    private const string StartupRegistryKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupValueName = "VaultGuardian";

    private readonly AppSettings _settings;

    public SettingsWindow(AppSettings settings)
    {
        _settings = settings;
        InitializeComponent();
        Populate();
    }

    private void Populate()
    {
        LaunchAtStartupBox.IsChecked = IsRegisteredForStartup();
        MinimizeToTrayBox.IsChecked = _settings.MinimizeToTrayOnClose;
        ShowOverlayOnStartBox.IsChecked = _settings.ShowOverlayOnStart;
        RefreshSlider.Value = _settings.RefreshIntervalMs;
        UpdateRefreshLabel(_settings.RefreshIntervalMs);
    }

    private void OnRefreshSliderChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        => UpdateRefreshLabel((int)e.NewValue);

    private void UpdateRefreshLabel(int ms)
        => RefreshLabel.Text = ms >= 1000 ? $"{ms / 1000.0:F2} s" : $"{ms} ms";

    private void OnCancelClick(object sender, RoutedEventArgs e)
        => DialogResult = false;

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        _settings.RefreshIntervalMs = (int)RefreshSlider.Value;
        _settings.MinimizeToTrayOnClose = MinimizeToTrayBox.IsChecked == true;
        _settings.ShowOverlayOnStart = ShowOverlayOnStartBox.IsChecked == true;

        ApplyStartupRegistration(LaunchAtStartupBox.IsChecked == true);

        try { AppSettingsLoader.Save(_settings); }
        catch (Exception ex)
        {
            MessageBox.Show(this,
                $"Settings saved in memory but could not be written to disk:\n{ex.Message}",
                "Save Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        _settings.NotifyChanged();
        DialogResult = true;
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
