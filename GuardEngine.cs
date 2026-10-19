using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace TaskManagerGuardAgent
{
    /// <summary>Everything gathered about a newly launched process.</summary>
    public class ProcessEventInfo
    {
        public int Pid;
        public string Name;
        public string ExePath;
        public string CommandLine;
        public uint ParentPid;
        public string ParentName;
        public string ParentPath;
        public string CompanyName;
        public string FileDescription;
        public string FileVersion;
        public string Publisher;          // Authenticode signer, or "(unsigned)"
        public bool SignatureValid;
        public string Sha256;
        public DateTime StartedUtc = DateTime.UtcNow;
        public VirusTotalVerdict VT = new VirusTotalVerdict();

        /// <summary>Everything published about this task, as shown in the prompt
        /// and details views (without the VirusTotal line).</summary>
        public string BuildDetailsText()
        {
            return
                "Executable : " + (string.IsNullOrEmpty(ExePath) ? "(unknown path)" : ExePath) + Environment.NewLine +
                "Publisher  : " + Publisher + (SignatureValid ? "  [signature valid]" :
                    (Publisher == "(unsigned)" ? "  [NOT SIGNED]" : "  [SIGNATURE INVALID]")) + Environment.NewLine +
                "Version    : " + (string.IsNullOrEmpty(FileVersion) ? "(none)" : FileVersion) + Environment.NewLine +
                "Company    : " + (string.IsNullOrEmpty(CompanyName) ? "(none)" : CompanyName) + Environment.NewLine +
                "Description: " + (string.IsNullOrEmpty(FileDescription) ? "(none)" : FileDescription) + Environment.NewLine +
                "Requested source:" + Environment.NewLine +
                "   Parent  : " + (string.IsNullOrEmpty(ParentName)
                    ? "(parent already exited)"
                    : $"{ParentName} (PID {ParentPid})" + (string.IsNullOrEmpty(ParentPath) ? "" : Environment.NewLine + "   " + ParentPath)) + Environment.NewLine +
                "Command    : " + (string.IsNullOrEmpty(CommandLine) ? "(not captured)" : CommandLine) + Environment.NewLine +
                "SHA-256    : " + (string.IsNullOrEmpty(Sha256) ? "(unavailable)" : Sha256);
        }
    }

    public class VirusTotalVerdict
    {
        public bool ApiKeyConfigured;
        public bool Started;
        public bool Completed;
        public int Malicious;
        public int Suspicious;
        public int Undetected;
        public string Permalink;
        public string Error;
        public string Summary => !ApiKeyConfigured ? "VirusTotal key not configured"
            : !Completed ? "Checking with VirusTotal..."
            : Error != null ? "VirusTotal: " + Error
            : $"VirusTotal: {Malicious} malicious / {Suspicious} suspicious / {Undetected} clean of {Malicious + Suspicious + Undetected} engines";
    }

    /// <summary>Core guard engine: detects new processes, suspends them (freezes the
    /// process the instant it appears), gathers details, and hands them to the UI
    /// for an Allow/Block decision.</summary>
    public class GuardEngine : IDisposable
    {
        // ---------- native interop ----------
        private const uint PROCESS_SUSPEND_RESUME = 0x0800;
        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("ntdll.dll")]
        private static extern uint NtSuspendProcess(IntPtr hProcess);

        [DllImport("ntdll.dll")]
        private static extern uint NtResumeProcess(IntPtr hProcess);

        // ---------- events ----------
        /// <summary>Raised on the UI thread whenever a new (suspended) process needs a decision.</summary>
        public event Action<ProcessEventInfo> PromptRequired;
        /// <summary>Log lines for the main window.</summary>
        public event Action<string> Log;
        /// <summary>Fired when a decision has been applied (info, decision string).</summary>
        public event Action<ProcessEventInfo, string> DecisionApplied;

        /// <summary>Public logging hook so forms can write to the log too.</summary>
        public void WriteLog(string message) => Log?.Invoke(message);

        private readonly Config _config;
        private ManagementEventWatcher _wmiWatcher;
        private System.Threading.Timer _pollTimer;
        private HashSet<int> _knownPids = new HashSet<int>();
        private readonly ConcurrentQueue<ProcessEventInfo> _queue = new();
        private CancellationTokenSource _cts = new();
        private Task _pumpTask;
        private Task _vtTask;
        private bool _running;
        private readonly int _ownPid = Environment.ProcessId;
        private readonly string _ownExePath = Environment.ProcessPath ?? "";

        public bool UsingWmiTrace { get; private set; }
        public bool IsRunning => _running;

        public GuardEngine(Config config)
        {
            _config = config;
        }

        public void Start()
        {
            if (_running) return;
            _running = true;
            if (_cts.IsCancellationRequested) _cts = new CancellationTokenSource();

            // Snapshot the processes that already exist; those are trusted baseline.
            _knownPids = new HashSet<int>(Process.GetProcesses().Select(p => p.Id));

            // Preferred mode: WMI start-trace (instant, needs admin).
            try
            {
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace");
                _wmiWatcher = new ManagementEventWatcher(scope, query);
                _wmiWatcher.EventArrived += OnWmiProcessStart;
                _wmiWatcher.Start();
                UsingWmiTrace = true;
                Log?.Invoke($"Monitoring active (WMI start-trace). { _knownPids.Count} existing processes accepted as baseline.");
            }
            catch (Exception ex)
            {
                UsingWmiTrace = false;
                Log?.Invoke("WMI start-trace unavailable (" + ex.Message + "). Falling back to 1-second polling.");
            }

            if (!UsingWmiTrace)
                _pollTimer = new System.Threading.Timer(PollCallback, null, 1000, 1000);

            // Queue pump: one prompt at a time, in order.
            _pumpTask = Task.Run(() => PumpLoop(_cts.Token));

            // VirusTotal lookup worker: enriches queued items while the user reads the dialog.
            _vtTask = Task.Run(() => VtLoop(_cts.Token));
        }

        public void Stop()
        {
            if (!_running) return;
            _running = false;
            try { _cts.Cancel(); } catch { }
            try { _wmiWatcher?.Stop(); _wmiWatcher?.Dispose(); } catch { }
            _wmiWatcher = null;
            try { _pollTimer?.Dispose(); } catch { }
            _pollTimer = null;
            _knownPids.Clear();
            Log?.Invoke("Monitoring stopped.");
        }

        private void OnWmiProcessStart(object sender, EventArrivedEventArgs e)
        {
            try
            {
                int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                string name = (e.NewEvent["ProcessName"] ?? "").ToString();
                HandleNewProcess(pid, name);
            }
            catch (Exception ex)
            {
                Log?.Invoke("WMI event error: " + ex.Message);
            }
        }

        private void PollCallback(object state)
        {
            try
            {
                var current = Process.GetProcesses();
                var currentPids = new HashSet<int>(current.Select(p => p.Id));
                foreach (var p in current)
                {
                    if (!_knownPids.Contains(p.Id))
                        HandleNewProcess(p.Id, null);
                }
                _knownPids = currentPids;
            }
            catch { /* transient access errors are normal while polling */ }
        }

        /// <summary>Main entry: a new pid appeared. Suspend it, gather details, queue for prompting.</summary>
        private void HandleNewProcess(int pid, string name)
        {
            if (pid == _ownPid) return;
            if (Environment.HasShutdownStarted) return;

            // ignore our own helper/relaunch instances
            try
            {
                var proc = Process.GetProcessById(pid);
                name ??= proc.ProcessName;
                proc.Dispose();
            }
            catch { return; } // already gone - nothing to guard

            // Wait briefly for the image path to be queryable (common right at start).
            string exePath = null;
            for (int i = 0; i < 20; i++)
            {
                exePath = GetProcessImagePath(pid);
                if (!string.IsNullOrEmpty(exePath)) break;
                Thread.Sleep(50);
            }

            // Never guard our own executable. The auto-restart watchdog relaunches the
            // agent every minute; the fresh copy must reach its single-instance mutex
            // check (and exit silently) instead of being frozen here by the running copy.
            // Before this fix a relaunch was suspended before Main() ever ran, so frozen
            // second copies piled up in Task Manager no matter what the mutex allowed.
            if (!string.IsNullOrEmpty(exePath) && _ownExePath.Length > 0 &&
                string.Equals(exePath, _ownExePath, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var info = new ProcessEventInfo
            {
                Pid = pid,
                Name = name ?? $"pid {pid}",
                ExePath = exePath ?? "",
            };

            // Details are required by the release policy. For well-known Windows
            // system paths we evaluate quietly WITHOUT freezing the process;
            // everything else is suspended the moment it appears.
            bool isNoise = _config.QuietSystemProcesses && IsNoise(info);

            if (isNoise)
            {
                GatherDetails(info);
                if (info.SignatureValid && !string.IsNullOrEmpty(info.CommandLine))
                {
                    Log?.Invoke($"Auto-allowed system process (signature valid): {info.Name} ({pid})");
                    return;
                }
                // Signature not valid or command line not captured: policy says
                // NEVER silently allow - fall through and prompt like everything else.
            }

            bool suspended = Suspend(pid);
            if (!suspended)
            {
                // Could not freeze it (already dead or access denied). Still report it.
                Log?.Invoke($"Could not suspend {info.Name} ({pid}); prompting anyway.");
            }

            if (!isNoise) GatherDetails(info);

            // Permanent lists first - explicit user decisions always win.
            string pathKey = info.ExePath.ToLowerInvariant();
            if (_config.BlocklistPaths.Contains(pathKey))
            {
                Kill(pid);
                DecisionApplied?.Invoke(info, "Blocked (block list)");
                return;
            }
            if (_config.IsAllowed(info.ExePath, info.Sha256))
            {
                Resume(pid);
                DecisionApplied?.Invoke(info, "Allowed (allow list)");
                return;
            }

            if (!_config.ProtectionEnabled)
            {
                Log?.Invoke($"Protection paused - {info.Name} ({pid}) allowed without prompting.");
                return;
            }

            // RELEASE POLICY:
            // 1. Valid Authenticode signature + captured command line -> allow
            //    automatically (the hash is remembered so the file is not re-checked).
            // 2. Signature invalid/unsigned, OR command line not captured ->
            //    NEVER allowed silently: the process stays suspended and the
            //    permission dialog (OK/Cancel) decides.
            if (info.SignatureValid && !string.IsNullOrEmpty(info.CommandLine))
            {
                if (!string.IsNullOrEmpty(info.Sha256)) _config.AllowHash(info.Sha256);
                if (suspended) Resume(pid);
                DecisionApplied?.Invoke(info, "Allowed automatically (signature valid)");
                return;
            }

            if (!suspended)
            {
                // process could not be frozen and could not be killed either - just log it
                DecisionApplied?.Invoke(info, "Reported (no control over process)");
                return;
            }

            _queue.Enqueue(info);
            Log?.Invoke($"Held new process for review: {info.Name} ({pid})");
        }

        private void PumpLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (_queue.TryDequeue(out var info))
                    {
                        PromptRequired?.Invoke(info);
                    }
                    else
                    {
                        ct.WaitHandle.WaitOne(200);
                    }
                }
                catch (ObjectDisposedException) { break; }
                catch (OperationCanceledException) { break; }
            }
        }

        private void VtLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (_queue.TryPeek(out var info) && !info.VT.Completed && !info.VT.Started)
                    {
                        if (string.IsNullOrEmpty(_config.VirusTotalApiKey))
                        {
                            info.VT.ApiKeyConfigured = false;
                            info.VT.Completed = true;
                        }
                        else if (!string.IsNullOrEmpty(info.Sha256))
                        {
                            info.VT.ApiKeyConfigured = true;
                            info.VT.Started = true;
                            VirusTotalLookup(info, _config.VirusTotalApiKey).ConfigureAwait(false)
                                .GetAwaiter().GetResult();
                            info.VT.Completed = true;
                        }
                        else
                        {
                            info.VT.Completed = true;
                        }
                    }
                    else
                    {
                        ct.WaitHandle.WaitOne(300);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { ct.WaitHandle.WaitOne(500); }
            }
        }

        // ---------- decisions (called by the UI after OK/Cancel) ----------
        public void Allow(ProcessEventInfo info)
        {
            Resume(info.Pid);
            DecisionApplied?.Invoke(info, "Allowed by user");
        }

        public void AllowAlways(ProcessEventInfo info)
        {
            _config.AllowPath(info.ExePath);
            if (!string.IsNullOrEmpty(info.Sha256)) _config.AllowHash(info.Sha256);
            Resume(info.Pid);
            DecisionApplied?.Invoke(info, "Allowed by user (always for this file)");
        }

        public void Block(ProcessEventInfo info)
        {
            Kill(info.Pid);
            _config.BlockPath(info.ExePath);
            DecisionApplied?.Invoke(info, "Blocked by user");
        }

        public void BlockOnce(ProcessEventInfo info)
        {
            Kill(info.Pid);
            DecisionApplied?.Invoke(info, "Blocked by user");
        }

        // ---------- helpers ----------
        private bool Suspend(int pid)
        {
            IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                // NtSuspendProcess freezes all threads of the target process.
                uint status = NtSuspendProcess(h);
                return status == 0;
            }
            finally { CloseHandle(h); }
        }

        private bool Resume(int pid)
        {
            IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return NtResumeProcess(h) == 0; }
            finally { CloseHandle(h); }
        }

        private void Kill(int pid)
        {
            try
            {
                var p = Process.GetProcessById(pid);
                p.Kill(true); // entire tree
            }
            catch { /* already exited */ }
        }

        private string GetProcessImagePath(int pid)
        {
            // QueryFullProcessImageName is the most reliable on modern Windows.
            try
            {
                IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h == IntPtr.Zero) return null;
                try
                {
                    var sb = new StringBuilder(1024);
                    int size = sb.Capacity;
                    if (QueryFullProcessImageName(h, 0, sb, ref size))
                        return sb.ToString(0, size);
                    return null;
                }
                finally { CloseHandle(h); }
            }
            catch { return null; }
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags,
            StringBuilder lpExeName, ref int lpdwSize);

        /// <summary>Fills publisher, version, parent, command line and hash. Safe to call on any pid.</summary>
        private void GatherDetails(ProcessEventInfo info)
        {
            // Command line first: the release policy requires it to be captured
            // before anything is allowed silently.
            try
            {
                using var cmdSearcher = new ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {info.Pid}");
                foreach (var o in cmdSearcher.Get())
                {
                    info.CommandLine = o["CommandLine"]?.ToString();
                    break;
                }
            }
            catch { /* best-effort */ }

            try
            {
                if (!string.IsNullOrEmpty(info.ExePath) && File.Exists(info.ExePath))
                {
                    var fvi = FileVersionInfo.GetVersionInfo(info.ExePath);
                    info.FileDescription = fvi?.FileDescription;
                    info.FileVersion = fvi?.FileVersion;
                    info.CompanyName = fvi?.CompanyName;

                    try
                    {
                        using var sha = SHA256.Create();
                        using var fs = new FileStream(info.ExePath, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete);
                        info.Sha256 = BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLowerInvariant();
                    }
                    catch { /* file locked - hash unavailable */ }

                    var sig = SignatureHelper.GetSignature(info.ExePath);
                    info.Publisher = sig.Signer;
                    info.SignatureValid = sig.IsValid;
                }
            }
            catch { /* details are best-effort */ }

            info.Publisher ??= "(unsigned)";

            // Parent chain = "requested source"
            try
            {
                uint ppid = GetParentPid(info.Pid);
                info.ParentPid = ppid;
                if (ppid != 0)
                {
                    var parent = Process.GetProcessById((int)ppid);
                    info.ParentName = parent.ProcessName;
                    info.ParentPath = GetProcessImagePath((int)ppid) ?? "";
                    parent.Dispose();
                }
            }
            catch { /* parent may be gone */ }
        }

        private uint GetParentPid(int pid)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (var o in searcher.Get())
                    return Convert.ToUInt32(o["ParentProcessId"]);
            }
            catch { }
            return 0;
        }

        /// <summary>Very common Windows background spawn-ins that would make the tool
        /// unusable if prompted every time. Only used when QuietSystemProcesses is on,
        /// and never covers anything that is not a well-known signed Microsoft path.</summary>
        private bool IsNoise(ProcessEventInfo info)
        {
            if (string.IsNullOrEmpty(info.ExePath)) return false;
            string path = info.ExePath.ToLowerInvariant();
            if (!path.StartsWith(@"c:\windows\", StringComparison.Ordinal)) return false;

            string[] known =
            {
                @"c:\windows\system32\conhost.exe",
                @"c:\windows\system32\csrss.exe",
                @"c:\windows\system32\wininit.exe",
                @"c:\windows\system32\services.exe",
                @"c:\windows\system32\lsass.exe",
                @"c:\windows\system32\svchost.exe",
                @"c:\windows\system32\dllhost.exe",
                @"c:\windows\system32\backgroundtaskhost.exe",
                @"c:\windows\system32\sihost.exe",
                @"c:\windows\system32\taskhostw.exe",
                @"c:\windows\system32\smss.exe",
                @"c:\windows\system32\winlogon.exe",
                @"c:\windows\system32\fontdrvhost.exe",
                @"c:\windows\system32\rundll32.exe",
                @"c:\windows\system32\sgrmagent.exe",
                @"c:\windows\system32\securityhealthservice.exe",
                @"c:\windows\explorer.exe",
                @"c:\windows\system32\msdtc.exe",
                @"c:\windows\system32\vssvc.exe",
                @"c:\windows\system32\wbem\wmiprvse.exe",
                @"c:\windows\system32\audiodg.exe",
            };
            return known.Contains(path);
        }

        // ---------- VirusTotal ----------
        private async Task VirusTotalLookup(ProcessEventInfo info, string apiKey)
        {
            try
            {
                using var http = new System.Net.Http.HttpClient();
                http.Timeout = TimeSpan.FromSeconds(10);
                var req = new System.Net.Http.HttpRequestMessage(
                    System.Net.Http.HttpMethod.Get,
                    $"https://www.virustotal.com/api/v3/files/{info.Sha256}");
                req.Headers.Add("x-apikey", apiKey);
                req.Headers.Add("User-Agent", "TaskManagerGuardAgent/1.0");

                using var resp = await http.SendAsync(req);
                if ((int)resp.StatusCode == 404)
                {
                    info.VT.Error = "no report for this file yet";
                    return;
                }
                if (!resp.IsSuccessStatusCode)
                {
                    info.VT.Error = $"VirusTotal returned HTTP {(int)resp.StatusCode}";
                    return;
                }

                using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
                if (doc.RootElement.TryGetProperty("data", out var data) &&
                    data.TryGetProperty("attributes", out var attrs) &&
                    attrs.TryGetProperty("last_analysis_stats", out var stats))
                {
                    int GetNum(string name) =>
                        stats.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
                    info.VT.Malicious = GetNum("malicious");
                    info.VT.Suspicious = GetNum("suspicious");
                    info.VT.Undetected = GetNum("undetected");
                }
                info.VT.Permalink = $"https://www.virustotal.com/gui/file/{info.Sha256}";
            }
            catch (Exception ex)
            {
                info.VT.Error = ex.Message;
            }
        }

        public void Dispose()
        {
            Stop();
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>Authenticode signature checking via WinVerifyTrust.</summary>
    internal static class SignatureHelper
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_FILE_INFO
        {
            public int cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        private enum WinTrustDataUIChoice { None = 2 }
        private enum WinTrustDataRevocationChecks { None = 0 }
        private enum WinTrustDataStateAction { Verify = 1, Close = 2 }
        private enum WinTrustDataUIContext { File = 1 }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public int cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public int dwUIChoice;           // UIChoice
            public int fdwRevocationChecks;  // RevocationChecks
            public int dwUnionChoice;        // 1 = file
            public IntPtr pFile;
            public int dwStateAction;        // StateAction
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public int dwProvFlags;
            public int dwUIContext;
        }

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(IntPtr hWnd, IntPtr pgActionID, ref WINTRUST_DATA pWVTData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        public static (string Signer, bool IsValid) GetSignature(string exePath)
        {
            // 1) Verify the Authenticode signature cryptographically.
            bool valid = Verify(exePath);

            // 2) Extract the signer name for display.
            string signer = null;
            try
            {
                var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(exePath);
                var cn = new System.Security.Cryptography.X509Certificates.X509Certificate2(cert)
                    .GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);
                signer = string.IsNullOrEmpty(cn) ? cert.Subject : cn;
            }
            catch
            {
                // CreateFromSignedFile throws for unsigned files.
                return ("(unsigned)", false);
            }

            return (signer, valid);
        }

        private static bool Verify(string filePath)
        {
            IntPtr pgAction = IntPtr.Zero;
            IntPtr pFileInfo = IntPtr.Zero;
            IntPtr pFilePath = IntPtr.Zero;
            IntPtr pFile = IntPtr.Zero;
            try
            {
                pFilePath = Marshal.StringToHGlobalUni(filePath);
                var fileInfo = new WINTRUST_FILE_INFO
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                    pcwszFilePath = pFilePath,
                    hFile = IntPtr.Zero
                };
                pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
                Marshal.StructureToPtr(fileInfo, pFileInfo, false);

                // WinVerifyTrust action GUID: WINTRUST_ACTION_GENERIC_VERIFY_V2
                var actionGuid = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
                pgAction = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
                Marshal.StructureToPtr(actionGuid, pgAction, false);

                var data = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf<WINTRUST_DATA>(),
                    dwUIChoice = (int)WinTrustDataUIChoice.None,
                    fdwRevocationChecks = (int)WinTrustDataRevocationChecks.None,
                    dwUnionChoice = 1, // WTD_CHOICE_FILE
                    pFile = pFileInfo,
                    dwStateAction = (int)WinTrustDataStateAction.Verify,
                    dwProvFlags = 0x00000010, // WTD_REVOCATION_CHECK_NONE is not needed; use default + no UI
                };

                int result = WinVerifyTrust(IntPtr.Zero, pgAction, ref data);

                // Close the state data created by the verify call.
                data.dwStateAction = (int)WinTrustDataStateAction.Close;
                WinVerifyTrust(IntPtr.Zero, pgAction, ref data);

                return result == 0; // ERROR_SUCCESS
            }
            catch
            {
                return false;
            }
            finally
            {
                if (pFileInfo != IntPtr.Zero) Marshal.FreeHGlobal(pFileInfo);
                if (pFilePath != IntPtr.Zero) Marshal.FreeHGlobal(pFilePath);
                if (pgAction != IntPtr.Zero) Marshal.FreeHGlobal(pgAction);
                _ = pFile;
            }
        }
    }
}
