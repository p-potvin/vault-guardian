using Microsoft.UI;
using Microsoft.UI.Xaml.Media;
using VaultGuardian.Core.Processes;
using Windows.UI;

namespace VaultGuardian.UI;

/// <summary>Display projection of a <see cref="ProcessTriageEntry"/> for the Processes list.</summary>
public sealed class ProcessRowVM
{
    private static readonly Color Online = Color.FromArgb(0xFF, 0x6B, 0xE6, 0x75);
    private static readonly Color Warning = Color.FromArgb(0xFF, 0xF0, 0xB9, 0x4B);
    private static readonly Color Alert = Color.FromArgb(0xFF, 0xFF, 0x6B, 0x7A);

    public ProcessRowVM(ProcessTriageEntry entry)
    {
        Entry = entry;
    }

    public ProcessTriageEntry Entry { get; }

    public int Pid => Entry.Facts.ProcessId;

    public string Display => $"{Entry.Facts.Name} · PID {Pid}";

    public string Cpu => $"{Entry.Facts.CpuPercent:0.0}%";

    public string Memory => FormatBytes(Entry.Facts.WorkingSetBytes);

    public string Disposition => Entry.Verdict.Disposition.ToString();

    public string KillSafety => Humanize(Entry.Verdict.KillSafety);

    public string Reasons => Entry.Verdict.Reasons.Count > 0
        ? string.Join("  •  ", Entry.Verdict.Reasons)
        : "No notable signals.";

    public Brush DispositionBrush => new SolidColorBrush(Entry.Verdict.Disposition switch
    {
        ProcessDisposition.Suspicious => Alert,
        ProcessDisposition.Unknown => Warning,
        _ => Online
    });

    public Brush KillSafetyBrush => new SolidColorBrush(Entry.Verdict.KillSafety switch
    {
        Core.Processes.KillSafety.BreaksWindows => Alert,
        Core.Processes.KillSafety.RiskyToShutdown => Warning,
        _ => Online
    });

    private static string Humanize(KillSafety killSafety) => killSafety switch
    {
        Core.Processes.KillSafety.BreaksWindows => "Breaks Windows",
        Core.Processes.KillSafety.RiskyToShutdown => "Risky — disrupts services",
        _ => "Safe to shut down"
    };

    private static string FormatBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "—";
        }

        double mb = bytes / 1024.0 / 1024.0;
        return mb >= 1024 ? $"{mb / 1024:0.0} GB" : $"{mb:0} MB";
    }
}
