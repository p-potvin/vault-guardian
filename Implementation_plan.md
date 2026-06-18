# Phase 3 Plan — WinUI 3 Migration + VaultWares Redesign Theme

## Context

Phases 1 and 2 shipped firewall integration and rule persistence on WPF. This phase migrates the entire UI layer to WinUI 3 (Windows App SDK) and simultaneously applies the **VaultWares Redesign** theme (`vaultwares-revisited/` Console Mode) from the `vaultwares-themes` submodule. Doing both together avoids a double-pass through every XAML file and is what the user requested.

The redesign theme is the **Console Mode** variant from `vaultwares-themes/vaultwares-revisited/`: deep aubergine backgrounds, gold accent, LED-style signal colors, 28 px card radius, and Segoe UI / JetBrains Mono typography.

---

## Design Tokens — Redesign Console Mode

Source: `vaultwares-themes/vaultwares-revisited/revisited.css` and `TOKENS.md`.

| XAML resource key | Value | Role |
|---|---|---|
| `ConsoleBgBrush` | `#0b0813` | App background |
| `ConsoleSurfaceBrush` | `#13101c` | Default card/container |
| `ConsoleRaisedBrush` | `#2A2340` | Elevated card, popover |
| `ConsoleElevatedBrush` | `#453763` | Modal/tooltip layer |
| `ConsoleActiveBrush` | `#614d8a` | Pressed/active state |
| `ConsoleBorderBrush` | `#0FFFFFFF` (rgba 255,255,255,0.06) | Subtle dividers |
| `ConsoleGoldBrush` | `#D6A441` | Primary accent (links, buttons) |
| `ConsoleVioletBrush` | `#B07CFF` | Secondary accent, focus rings |
| `PrimaryTextBrush` | `#EDE6FF` | Main text |
| `SecondaryTextBrush` | `#a394cc` | Labels, descriptions |
| `SignalOnlineBrush` | `#6BE675` | Success / operational |
| `SignalRelayBrush` | `#55D6FF` | Info / processing |
| `SignalSyncBrush` | `#B07CFF` | Connecting / sync |
| `SignalWarningBrush` | `#F0B94B` | Warning |
| `SignalAlertBrush` | `#FF6B7A` | Error / destructive |

Cards use: `Border Background="#2A2340" CornerRadius="28" BorderBrush="{StaticResource ConsoleBorderBrush}"`.
Shell gradient (app root): radial gradient (violet at 15%/0%, fading) + linear from surface to bg.

Fonts: `Segoe UI` (UI), `JetBrains Mono` (data/metrics readout).

---

## Architecture Decisions

1. **In-place migration** — rename the existing `VaultGuardian.UI` project; no parallel project.
2. **Unpackaged** — `WindowsPackageType=None`, `RuntimeIdentifiers=win-x64`. No MSIX complexity.
3. **Dialogs** — `RuleEditDialog` and `SettingsWindow` become `ContentDialog`s (no `ShowDialog()` in WinUI 3). `RulesManagerWindow` stays a full `Window` (it has a ListView + multiple actions that don't fit a ContentDialog well).
4. **Overlay** — `OverlayWindow` uses `AppWindow` + `OverlappedPresenter` (no chrome, always-on-top) + `DesktopAcrylicBackdrop` instead of `AllowsTransparency`.
5. **Tray icon** — swap `H.NotifyIcon.Wpf` → `H.NotifyIcon.WinUI`; context menu moves to `MenuFlyout` items.
6. **Single theme** — Console Mode dark only for now; no theme-switching UI.

---

## Files to Change

### `src/VaultGuardian.UI/VaultGuardian.UI.csproj`

```xml
<TargetFramework>net10.0-windows10.0.19041.0</TargetFramework>
<UseWinUI>true</UseWinUI>  <!-- replaces UseWPF -->
<WindowsPackageType>None</WindowsPackageType>
<RuntimeIdentifiers>win-x64;win-x86</RuntimeIdentifiers>
```

Packages:
- Remove `H.NotifyIcon.Wpf`
- Add `Microsoft.WindowsAppSDK` (1.7.x latest stable)
- Add `H.NotifyIcon.WinUI`

### NEW: `src/VaultGuardian.UI/Themes/VaultRedesign.xaml`

`ResourceDictionary` containing all Console Mode `Color` and `SolidColorBrush` resources listed in the token table above, plus:
- `CardCornerRadius` = `CornerRadius 28`
- `VaultFontFamily` = `"Segoe UI"`
- `VaultMonoFontFamily` = `"JetBrains Mono"`
- A `ProgressBar` style override matching the new theme
- `ControlFillColorDefaultBrush`, `ApplicationPageBackgroundThemeBrush` mapped for WinUI 3 defaults

Merged into `App.xaml` via `MergedDictionaries`. Remove the old inline brush definitions from `App.xaml`.

### `src/VaultGuardian.UI/App.xaml` + `App.xaml.cs`

**XAML:**
- Update xmlns to WinUI 3: `xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"` stays the same URI but now resolves WinUI 3 types
- Add `xmlns:h="using:H.NotifyIcon"` (WinUI package)
- H.NotifyIcon `TaskbarIcon` context menu changes from WPF `ContextMenu`/`MenuItem` to `MenuFlyoutItem` (WinUI pattern — H.NotifyIcon.WinUI uses `MenuFlyout`)
- Merge `Themes/VaultRedesign.xaml`

**Code-behind:**
- `OnStartup(StartupEventArgs)` → `OnLaunched(LaunchActivatedEventArgs)` — all startup logic moves here
- `Application.Current.Shutdown()` → `Application.Current.Exit()`
- `ShutdownMode` → removed (no equivalent; WinUI exits when `MainWindow` closes or `Exit()` is called)
- `OnExit` → subscribe to `Application.Current.UnhandledException` and the main window's `Closed` event for firewall cleanup
- DI setup identical — no changes to `ConfigureServices`

### `src/VaultGuardian.UI/MainWindow.xaml` + `.cs`

**XAML:**
- `xmlns` → WinUI 3
- Remove `WindowStartupLocation`, `Icon` (set via `AppWindow`)
- Add gradient shell Border as root (instead of plain `Grid`) to implement the console gradient background
- Replace accent color references with redesign brush keys
- Replace `ProgressBar` style with redesign tokens
- Cards: `CornerRadius="28"` instead of `12`, redesign card brush keys
- "System Protected" footer: swap blue → gold accent (`ConsoleGoldBrush`) with subtle border
- LED indicator on OverlayWindow header: add `SignalOnlineBrush` + `vw-led` pulse animation equivalent via `Storyboard`

**Code-behind:**
- `DispatcherTimer` → `DispatcherQueue.GetForCurrentThread().CreateTimer()` — same `Tick` logic
- `OnSettingsChanged` still works via `AppSettings.Changed`
- `OnClosing` → `Closed` event (different signature in WinUI 3); `MinimizeToTrayOnClose` check same
- For "Manage Rules": `RulesManagerWindow` is now a plain Window; call `window.Activate()` instead of `ShowDialog()`
- `MessageBox.Show` → `await new ContentDialog { XamlRoot = Content.XamlRoot, ... }.ShowAsync()`

### `src/VaultGuardian.UI/OverlayWindow.xaml` + `.cs`

**XAML:**
- Remove `WindowStyle`, `AllowsTransparency`, `Background`, `Topmost`, `ShowInTaskbar` attributes (set in code)
- Root content: `Border` with `ConsoleRaisedBrush` background + `ConsoleBorderBrush` border + `CornerRadius="12"` (overlay keeps smaller radius for compactness)
- Replace `SuccessBrush`/`ErrorBrush` with `SignalOnlineBrush`/`SignalAlertBrush`
- Add LED pulse `Storyboard` to the status ellipse

**Code-behind:**
```csharp
// In constructor, after InitializeComponent():
var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
_appWindow = AppWindow.GetFromWindowId(windowId);
var presenter = OverlappedPresenter.Create();
presenter.IsAlwaysOnTop = true;
presenter.IsDecorated = false;   // no title bar / chrome
_appWindow.IsShownInSwitchers = false;
_appWindow.SetPresenter(presenter);
SystemBackdrop = new DesktopAcrylicBackdrop();
PositionInCorner();
```

- `DragMove()` → on `PointerPressed`, call `_appWindow.BeginMoveResize()`
- `SystemParameters.WorkArea` → `DisplayArea.GetFromWindowId(windowId, DisplayAreaFallback.Nearest).WorkArea`
- `this.Left/Top` → `_appWindow.Move(new PointInt32(x, y))`

### `src/VaultGuardian.UI/MetricControl.xaml` + `.cs`

- `xmlns` update
- XAML brush keys → redesign tokens
- Code: `using System.Windows.Media` → `using Microsoft.UI.Xaml.Media`; `Color` → `Windows.UI.Color`
- `SolidColorBrush` constructor identical in WinUI 3

### `src/VaultGuardian.UI/StatBox.xaml` + `.cs`

- Same namespace changes as MetricControl
- Card border → redesign tokens, `CornerRadius="20"` (`panel` radius from token spec)

### `src/VaultGuardian.UI/RulesManagerWindow.xaml` + `.cs`

**XAML:**
- WinUI 3 Window (not dialog)
- `ListView` → WinUI 3 `ListView` (same control name, API compatible)
- `GridView` columns → same
- Value converters: namespace update, `Brushes.Red` → `new SolidColorBrush(Colors.Red)`
- Redesign card for the list container

**Code-behind:**
- `IValueConverter` from `Microsoft.UI.Xaml.Data`
- No `Owner` property in WinUI 3 Window — remove; centering via `AppWindow.Move()`
- Add/Edit operations now show `ContentDialog` versions of `RuleEditDialog`
- `MessageBox.Show` → `ContentDialog`

### `src/VaultGuardian.UI/RuleEditDialog.xaml` + `.cs`

Converted from `Window` to `ContentDialog`:

```xml
<ContentDialog x:Class="VaultGuardian.UI.RuleEditDialog"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    Title="Egress Rule"
    PrimaryButtonText="Save"
    SecondaryButtonText="Cancel"
    DefaultButton="Primary">
    <!-- same form fields inside ContentDialog content -->
</ContentDialog>
```

- `DialogResult` / `ShowDialog()` → `ContentDialogResult result = await dialog.ShowAsync()`; `dialog.Result` is read after checking `result == ContentDialogResult.Primary`
- `OpenFileDialog` → `FileOpenPicker` (`WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd)`)
- `PrimaryButtonClick` event replaces `OnSaveClick` for validation; call `args.Cancel = true` on failed validation
- `MessageBox.Show` → `ContentDialog` (but nested dialogs are tricky — use inline error `TextBlock` instead for validation messages)

### `src/VaultGuardian.UI/SettingsWindow.xaml` + `.cs`

Converted from `Window` to `ContentDialog` (same pattern as RuleEditDialog):

```xml
<ContentDialog x:Class="VaultGuardian.UI.SettingsWindow"
    Title="Settings"
    PrimaryButtonText="Save"
    SecondaryButtonText="Cancel">
    <!-- same form fields -->
</ContentDialog>
```

- `FileOpenPicker` not needed here
- Registry calls unchanged
- `_settings.NotifyChanged()` still fires after save

---

## Key API Replacements (Quick Reference)

| WPF | WinUI 3 |
|---|---|
| `DispatcherTimer` | `DispatcherQueue.GetForCurrentThread().CreateTimer()` |
| `MessageBox.Show(...)` | `await new ContentDialog { XamlRoot = ..., ... }.ShowAsync()` |
| `OpenFileDialog` | `FileOpenPicker` + `InitializeWithWindow` |
| `Application.Current.Shutdown()` | `Application.Current.Exit()` |
| `OnStartup(StartupEventArgs)` | `OnLaunched(LaunchActivatedEventArgs)` |
| `Window.Owner` | no equivalent — center via `AppWindow.Move()` |
| `ShowDialog()` | `await contentDialog.ShowAsync()` or manual window management |
| `SystemParameters.WorkArea` | `DisplayArea.GetFromWindowId(...).WorkArea` |
| `this.Left/Top` (overlay) | `appWindow.Move(new PointInt32(x, y))` |
| `DragMove()` | `appWindow.BeginMoveResize()` on pointer press |
| `WindowStyle="None" AllowsTransparency="True"` | `OverlappedPresenter` with `IsDecorated=false` + `DesktopAcrylicBackdrop` |
| `Brushes.Red` | `new SolidColorBrush(Colors.Red)` |
| `System.Windows.Media.Color` | `Windows.UI.Color` |
| `IValueConverter` (System.Windows.Data) | `IValueConverter` (Microsoft.UI.Xaml.Data) |
| `H.NotifyIcon.Wpf` TaskbarIcon | `H.NotifyIcon.WinUI` TaskbarIcon with `MenuFlyout` |

---

## Verification

1. **Build** — `dotnet build -r win-x64` (no SDK needed in CI; verify no type errors)
2. **Manual smoke (Windows, run as Administrator)**:
   - App launches, tray icon appears
   - Dashboard displays live metrics on 1s tick
   - Overlay window is topmost, borderless, draggable; snaps to edges
   - Manage Rules opens; add/edit/remove rules work; firewall apply failure shows ContentDialog error
   - Settings opens; refresh slider updates dashboard tick rate live; startup checkbox writes registry key; save persists to `settings.json`
   - Theme: deep aubergine background, gold accent buttons, LED signal colors on status dots, 28 px card corners
   - Close button minimizes to tray; Quit exits cleanly (session firewall rules cleared)