using System.Text.Json;
using System.Text.Json.Serialization;

namespace VaultGuardian.Core;

public static class RuleConfigurationLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task SaveToFileAsync(string filePath, IEnumerable<EgressRule> rules)
    {
        using var stream = File.Create(filePath);
        await JsonSerializer.SerializeAsync(stream, rules, Options);
    }

    public static async Task<List<EgressRule>> LoadFromFileAsync(string filePath)
    {
        if (!File.Exists(filePath))
        {
            return [];
        }

        using var stream = File.OpenRead(filePath);
        return await JsonSerializer.DeserializeAsync<List<EgressRule>>(stream, Options) ?? [];
    }
}
