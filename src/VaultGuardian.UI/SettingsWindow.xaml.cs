using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.Win32;
using VaultGuardian.Core;

namespace VaultGuardian.UI;

public sealed partial class SettingsWindow : Window
{
    private const string StartupRegistryKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupValueName = "VaultGuardian";

    private readonly AppSettings _settings;

    public SettingsWindow(AppSettings settings)
    {
        _settings = settings;
        InitializeComponent();
        Title = "Settings";
        Populate();
    }

    private void Populate()
    {
        LaunchAtStartupSwitch.IsOn = IsRegisteredForStartup();
        MinimizeToTraySwitch.IsOn = _settings.MinimizeToTrayOnClose;
        ShowOverlayOnStartSwitch.IsOn = _settings.ShowOverlayOnStart;
        RefreshSlider.Value = _settings.RefreshIntervalMs;
        UpdateRefreshLabel(_settings.RefreshIntervalMs);
    }

    private void OnRefreshSliderChanged(object sender, RangeBaseValueChangedEventArgs e)
        => UpdateRefreshLabel((int)e.NewValue);

    private void UpdateRefreshLabel(int ms)
        => RefreshLabel.Text = ms >= 1000 ? $"{ms / 1000.0:F2} s" : $"{ms} ms";

    private void OnCancelClick(object sender, RoutedEventArgs e)
        => this.Close();

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        _settings.RefreshIntervalMs = (int)RefreshSlider.Value;
        _settings.MinimizeToTrayOnClose = MinimizeToTraySwitch.IsOn;
        _settings.ShowOverlayOnStart = ShowOverlayOnStartSwitch.IsOn;

        ApplyStartupRegistration(LaunchAtStartupSwitch.IsOn);

        try { AppSettingsLoader.Save(_settings); }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[VaultGuardian] Settings save failed: {ex.Message}");
        }

        _settings.NotifyChanged();
        this.Close();
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
