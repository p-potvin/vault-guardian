using System.Text;

namespace VaultGuardian.Core.Ingress;

public static class IngressPayloadClassifier
{
    public const int DefaultMaxStoredBytes = 4096;
    public const int SignatureBytesToKeep = 256;

    private static readonly string[] LargeMediaExtensions =
    [
        ".mp4",
        ".mkv",
        ".mov",
        ".webm",
        ".avi"
    ];

    public static PayloadSample ClassifyAndSample(
        byte[] payload,
        DateTimeOffset capturedAt,
        string? contentType = null,
        string? fileName = null,
        int maxStoredBytes = DefaultMaxStoredBytes)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (payload.Length == 0)
        {
            return new PayloadSample(
                capturedAt,
                0,
                [],
                IngressContentClassification.Unknown,
                BodyCaptureSuppressed: false,
                "No payload bytes were present.",
                TextPreview: null);
        }

        var asciiPreview = TryDecodeAscii(payload, Math.Min(payload.Length, DefaultMaxStoredBytes));
        if (LooksLikeLargeMedia(contentType, fileName, asciiPreview))
        {
            return new PayloadSample(
                capturedAt,
                payload.Length,
                payload.Take(Math.Min(SignatureBytesToKeep, payload.Length)).ToArray(),
                IngressContentClassification.LargeMedia,
                BodyCaptureSuppressed: true,
                "Known large media transfer detected; storing signature/header bytes only.",
                SafeTextPreview(asciiPreview));
        }

        var stored = payload.Take(Math.Min(maxStoredBytes, payload.Length)).ToArray();
        if (LooksLikeTls(payload))
        {
            return new PayloadSample(
                capturedAt,
                payload.Length,
                stored,
                IngressContentClassification.Encrypted,
                BodyCaptureSuppressed: false,
                "TLS-like encrypted payload; storing bounded opaque sample.",
                TextPreview: null);
        }

        if (LooksLikePlaintext(payload, asciiPreview, contentType))
        {
            return new PayloadSample(
                capturedAt,
                payload.Length,
                stored,
                IngressContentClassification.Plaintext,
                BodyCaptureSuppressed: false,
                "Plaintext payload sample stored.",
                SafeTextPreview(asciiPreview));
        }

        return new PayloadSample(
            capturedAt,
            payload.Length,
            stored,
            IngressContentClassification.Binary,
            BodyCaptureSuppressed: false,
            "Binary or unknown payload; storing bounded sample.",
            TextPreview: null);
    }

    private static bool LooksLikeLargeMedia(string? contentType, string? fileName, string asciiPreview)
    {
        if (!string.IsNullOrWhiteSpace(contentType) &&
            contentType.Trim().StartsWith("video/", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(fileName) &&
            LargeMediaExtensions.Any(extension => fileName.EndsWith(extension, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return asciiPreview.Contains("content-type: video/", StringComparison.OrdinalIgnoreCase) ||
               LargeMediaExtensions.Any(extension => asciiPreview.Contains(extension, StringComparison.OrdinalIgnoreCase));
    }

    private static bool LooksLikeTls(byte[] payload)
    {
        if (payload.Length < 3)
        {
            return false;
        }

        var recordType = payload[0];
        return (recordType is 0x14 or 0x15 or 0x16 or 0x17) &&
               payload[1] == 0x03 &&
               payload[2] <= 0x04;
    }

    private static bool LooksLikePlaintext(byte[] payload, string asciiPreview, string? contentType)
    {
        if (!string.IsNullOrWhiteSpace(contentType) &&
            (contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase) ||
             contentType.Contains("json", StringComparison.OrdinalIgnoreCase) ||
             contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (asciiPreview.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) ||
            asciiPreview.StartsWith("GET ", StringComparison.OrdinalIgnoreCase) ||
            asciiPreview.StartsWith("POST ", StringComparison.OrdinalIgnoreCase) ||
            asciiPreview.StartsWith("PUT ", StringComparison.OrdinalIgnoreCase) ||
            asciiPreview.StartsWith("HEAD ", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var printable = payload.Count(b => b is >= 32 and <= 126 or 9 or 10 or 13);
        return payload.Length > 0 && printable / (double)payload.Length >= 0.85;
    }

    private static string TryDecodeAscii(byte[] payload, int length)
    {
        return Encoding.ASCII.GetString(payload, 0, length);
    }

    private static string? SafeTextPreview(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return value.Length <= 2048 ? value : value[..2048];
    }
}
