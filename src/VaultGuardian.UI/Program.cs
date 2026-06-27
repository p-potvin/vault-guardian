using Microsoft.UI.Xaml;
using Microsoft.Windows.ApplicationModel.DynamicDependency;

namespace VaultGuardian.UI;

public static class Program
{
    [global::System.STAThreadAttribute]
    static void Main(string[] args)
    {
        // Bootstrap the Windows App SDK runtime so ms-appx:/// URI resolution
        // and MRT Core work correctly in unpackaged (no MSIX) mode.
        // 0x00020001 = major 2, minor 1 — matches WindowsAppSDK 2.1.x.
        Bootstrap.Initialize(0x00020001);

        try
        {
            global::WinRT.ComWrappersSupport.InitializeComWrappers();
            global::Microsoft.UI.Xaml.Application.Start((p) =>
            {
                var context = new global::Microsoft.UI.Dispatching.DispatcherQueueSynchronizationContext(
                    global::Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread());
                global::System.Threading.SynchronizationContext.SetSynchronizationContext(context);
                _ = new App();
            });
        }
        finally
        {
            Bootstrap.Shutdown();
        }
    }
}
