using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultGuardian.Core;

public static class AppSettingsLoader
{
    private const string FileName = "settings.json";

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        // Enum settings round-trip as readable names so settings.json stays
        // hand-editable. Without this a typed value like "Wfp" fails to
        // deserialize and Load() silently discards every other setting too.
        Converters = { new JsonStringEnumConverter() },
    };

    private static string FilePath =>
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FileName);

    public static AppSettings Load()
    {
        var path = FilePath;
        if (!File.Exists(path)) return new AppSettings();
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppSettings>(json, Options) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public static void Save(AppSettings settings)
    {
        var json = JsonSerializer.Serialize(settings, Options);
        File.WriteAllText(FilePath, json);
    }
}
