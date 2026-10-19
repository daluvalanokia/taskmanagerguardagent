# TaskManagerGuardAgent

A standalone process guard for Windows. It runs in the background as a **single
auto-restartable process**, watches every process launched on the system, and
**freezes each new process the moment it appears**. A permission dialog shows the
publisher, version, source and a VirusTotal verdict, and you choose:

- **OK** → release the process onto the CPU (it continues running)
- **Cancel** → keep it blocked (the process is terminated)

The process is *suspended*, not killed, while the dialog waits, so nothing runs
until you allow it.

## Features

- **Single process** with a global-mutex single-instance guarantee, plus an
  optional auto-restart watchdog (a per-minute scheduled task relaunches the
  agent within one minute if it is ever killed or crashes; extra launches are
  silent no-ops while it is alive).
- **Instant detection** via WMI process-start tracing (1-second polling fallback
  if WMI is unavailable).
- **Suspend-on-launch** using `NtSuspendProcess`: the new process never executes
  before a decision.
- **Automatic release policy**
  1. A process with a **valid Authenticode signature** and a captured command
     line is released automatically (its SHA-256 is remembered so the file is
     never re-checked).
  2. Anything **unsigned**, with an **invalid signature**, or whose command
     line could not be captured is **never allowed silently** - it stays frozen
     until you answer the OK/Cancel dialog (auto-block on timeout).
- **Details shown**: executable path, Authenticode publisher + signature
  validity, file version, company, description, parent process chain
  ("requested source"), command line, SHA-256 hash.
- **VirusTotal v3 integration** (free API key) for hash validation against
  70+ antivirus engines, with a link to the full report.
- **Allow-list / block-list** with "always" decisions, persisted across restarts.
- **Agent window task management**: double-click (or right-click) any task row in the
  agent window to view the published details of that task and to *Allow always*,
  *Block always* or *Unblock* (remove from block list) the file. The block list is
  checked before the signature auto-release, so a blocked file stays blocked until
  you unblock it - even if its signature is valid.
- **Self-guard fix**: the engine never freezes its own executable, so the watchdog's
  per-minute relaunch always reaches its single-instance mutex and exits silently
  (previously the running copy suspended the new copy before it could check the mutex).
- **Auto-block countdown** (default 45 s) so unattended prompts never hang forever.

## Requirements

- Windows 10/11 x64 (also fine on Server 2016+)
- [.NET 8 Desktop Runtime x64](https://dotnet.microsoft.com/download/dotnet/8.0)
  (free, one-time install) for the published framework-dependent build
- Administrator rights (the app requests elevation via UAC automatically)
- Internet only needed for VirusTotal lookups (optional)

## Build

```bash
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true
# or a fully standalone exe (~139 MB, no runtime needed):
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## Source layout

| File | Purpose |
| --- | --- |
| `Program.cs` | Entry point, single-instance mutex |
| `MainForm.cs` | Status window, tray icon, watchdog installer |
| `GuardEngine.cs` | Detection, suspend/resume/kill, WMI + polling, signature check, VirusTotal lookup |
| `PromptForm.cs` | The OK/Cancel permission dialog |
| `SettingsForm.cs` | Settings UI |
| `Config.cs` | Persisted settings and allow/block lists |

Settings live in `%APPDATA%\TaskManagerGuardAgent\config.json`.

## Uninstall

1. Click **Remove auto-restart** (or run
   `schtasks /Delete /F /TN TaskManagerGuardAgent_Watchdog`).
2. Delete the exe and `%APPDATA%\TaskManagerGuardAgent`.

## Disclaimer

Freeze-on-launch is aggressive. A suspended process holds its locks, so a
forgotten prompt can make an installer appear to hang - answer prompts promptly
or raise the auto-block countdown in Settings. Auto-releasing validly signed
binaries means signed-but-malicious code would not prompt; this is a personal
convenience guard, not a replacement for a real antivirus.
