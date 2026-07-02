using VaultGuardian.Core.Ingress.Telemetry;

namespace VaultGuardian.Core.Tests;

public sealed class IngressPrivacyWatchProfileTests
{
    [Fact]
    public void SelectorMatch_ReturnsLabelWithoutRawValue()
    {
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("email.primary", PrivacySelectorKind.Literal, "person@example.test", Enabled: true)
        ]);
        var text = "POST body contains person@example.test";

        var hits = PrivacySelectorMatcher.Match(profile, text, DateTimeOffset.UtcNow);

        var hit = Assert.Single(hits);
        Assert.Equal("email.primary", hit.SelectorLabel);
        Assert.DoesNotContain("person@example.test", hit.Summary);
        Assert.DoesNotContain("person@example.test", hit.EvidencePreview);
    }

    [Fact]
    public async Task Store_RoundTripsProfileWithoutWritingPlainSelectorValue()
    {
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}-privacy-profile.json");
        var store = new PrivacyWatchProfileStore(path);
        var profile = new PrivacyWatchProfile([
            new PrivacySelector("username.github", PrivacySelectorKind.Literal, "sensitive-user", Enabled: true)
        ]);

        await store.SaveAsync(profile);
        var rawFile = await File.ReadAllTextAsync(path);
        var loaded = await store.LoadAsync();

        Assert.DoesNotContain("sensitive-user", rawFile);
        Assert.Equal("sensitive-user", Assert.Single(loaded.Selectors).Value);
    }
}
