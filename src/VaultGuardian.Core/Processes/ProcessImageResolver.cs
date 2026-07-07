using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace VaultGuardian.Core.Processes;

/// <summary>
/// Resolves a PID to its image name/path without throwing when the process has
/// already exited. <see cref="System.Diagnostics.Process.GetProcessById(int)"/>
/// throws for dead PIDs, and on the packet hot path that exception fires
/// constantly for short-lived connections — expensive and noisy. This uses
/// OpenProcess + QueryFullProcessImageName, which simply fails closed instead.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ProcessImageResolver
{
    private const int ProcessQueryLimitedInformation = 0x1000;

    public static bool TryResolve(int processId, out string name, out string path)
    {
        name = "Unknown";
        path = "Unknown";
        if (processId <= 0)
        {
            return false;
        }

        var handle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (handle == IntPtr.Zero)
        {
            return false; // exited, or access denied (e.g. protected process)
        }

        try
        {
            int capacity = 1024;
            var buffer = new StringBuilder(capacity);
            if (QueryFullProcessImageName(handle, 0, buffer, ref capacity) && capacity > 0)
            {
                path = buffer.ToString(0, capacity);
                name = Path.GetFileNameWithoutExtension(path);
                return !string.IsNullOrEmpty(name);
            }

            return false;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr handle, int flags, StringBuilder exeName, ref int size);
}
