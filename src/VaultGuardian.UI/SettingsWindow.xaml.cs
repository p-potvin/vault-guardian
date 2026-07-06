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
        HostnameCorrelationSwitch.IsOn = _settings.EnableHostnameCorrelation;
        RefreshSlider.Value = _settings.RefreshIntervalMs;
        UpdateRefreshLabel(_settings.RefreshIntervalMs);
        SelectLanguage(_settings.Language);
    }

    private void SelectLanguage(string language)
    {
        foreach (var item in LanguageCombo.Items)
        {
            if (item is Microsoft.UI.Xaml.Controls.ComboBoxItem cbi &&
                string.Equals(cbi.Tag as string, language, StringComparison.OrdinalIgnoreCase))
            {
                LanguageCombo.SelectedItem = cbi;
                return;
            }
        }

        LanguageCombo.SelectedIndex = 0;
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
        _settings.EnableHostnameCorrelation = HostnameCorrelationSwitch.IsOn;

        if ((LanguageCombo.SelectedItem as Microsoft.UI.Xaml.Controls.ComboBoxItem)?.Tag is string lang)
        {
            _settings.Language = lang;
        }

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
