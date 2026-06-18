using System;
using System.IO;
using System.Text.Json;
using Microsoft.Win32;

namespace VaultGuardian.UI;

public sealed class AppSettings
{
    private const string RegistryRunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RegistryValueName = "VaultGuardian";
    private const string SettingsFileName = "settings.json";

    public int RefreshRateMs { get; set; } = 1000;
    public bool MinimizeToTrayOnClose { get; set; } = true;
    public bool RunAtStartup { get; set; }

    public event EventHandler? Changed;

    public void NotifyChanged() => Changed?.Invoke(this, EventArgs.Empty);

    public static AppSettings Load()
    {
        var path = SettingsPath();
        if (!File.Exists(path))
        {
            var fresh = new AppSettings();
            fresh.SyncRunAtStartupFromRegistry();
            return fresh;
        }

        try
        {
            using var stream = File.OpenRead(path);
            var loaded = JsonSerializer.Deserialize<AppSettings>(stream) ?? new AppSettings();
            loaded.SyncRunAtStartupFromRegistry();
            return loaded;
        }
        catch
        {
            return new AppSettings();
        }
    }

    public void Save()
    {
        ApplyRunAtStartupRegistry();
        var path = SettingsPath();
        using var stream = File.Create(path);
        JsonSerializer.Serialize(stream, this, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string SettingsPath()
    {
        var dir = Path.GetDirectoryName(AppContext.BaseDirectory) ?? AppContext.BaseDirectory;
        return Path.Combine(dir, SettingsFileName);
    }

    private void SyncRunAtStartupFromRegistry()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegistryRunKey);
            RunAtStartup = key?.GetValue(RegistryValueName) is string;
        }
        catch
        {
            RunAtStartup = false;
        }
    }

    private void ApplyRunAtStartupRegistry()
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RegistryRunKey, writable: true);
            if (key == null) return;
            if (RunAtStartup)
            {
                var exePath = Environment.ProcessPath ?? string.Empty;
                if (!string.IsNullOrEmpty(exePath))
                {
                    key.SetValue(RegistryValueName, $"\"{exePath}\"");
                }
            }
            else if (key.GetValue(RegistryValueName) != null)
            {
                key.DeleteValue(RegistryValueName, throwOnMissingValue: false);
            }
        }
        catch
        {
            // Registry access can fail under restricted contexts; ignore.
        }
    }
}
