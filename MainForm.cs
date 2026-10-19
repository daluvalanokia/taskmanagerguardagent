using System;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Windows.Forms;

namespace TaskManagerGuardAgent
{
    /// <summary>Compact status window (bottom-right corner) + tray icon. Lists every
    /// process currently frozen awaiting a decision, with Details / Unblock / Block
    /// controls right in this window. The permission dialog opens for one item at a
    /// time; everything else is manageable from here.</summary>
    public class MainForm : Form
    {
        public const string AppVersion = "1.1.1";
        private const string ShowSignalName = @"Global\TaskManagerGuardAgent_ShowSignal";

        private readonly Config _config;
        private readonly GuardEngine _engine;
        private NotifyIcon _tray;
        private ListView _listHeld;
        private ListView _listLog;
        private Label _lblStatus;
        private Button _btnDetails;
        private Button _btnUnblock;
        private Button _btnBlock;
        private Button _btnPause;
        private Button _btnSettings;
        private Button _btnWatchdog;
        private Button _btnExit;
        private readonly string _exePath = Application.ExecutablePath;
        private const string WatchdogTaskName = "TaskManagerGuardAgent_Watchdog";

        private EventWaitHandle _showSignal;
        private Thread _showSignalThread;
        private PromptForm _openPrompt;

        public MainForm(Config config)
        {
            _config = config;
            _engine = new GuardEngine(config);

            Text = $"TaskManager Guard Agent v{AppVersion}";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.Manual;
            ClientSize = new Size(560, 316);
            ShowInTaskbar = true;
            PositionBottomRight();

            BuildUi();
            BuildTray();

            _engine.HeldAdded += OnHeldAdded;
            _engine.HeldRemoved += OnHeldRemoved;
            _engine.Log += OnLog;
            _engine.DecisionApplied += OnDecisionApplied;

            ListenForSecondInstance();
            _engine.Start();
            UpdateWatchdogButton();
        }

        private void PositionBottomRight()
        {
            var wa = Screen.PrimaryScreen.WorkingArea;
            Location = new Point(wa.Right - Width - 10, wa.Bottom - Height - 10);
        }

        // ---------- second-instance signal (single process enforcement) ----------
        private void ListenForSecondInstance()
        {
            try
            {
                _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
                _showSignalThread = new Thread(() =>
                {
                    try
                    {
                        while (_showSignal.WaitOne())
                        {
                            if (IsDisposed) break;
                            try { BeginInvoke(new Action(ShowWindow)); } catch { break; }
                        }
                    }
                    catch { }
                })
                { IsBackground = true };
                _showSignalThread.Start();
            }
            catch { /* signal is a convenience; the mutex does the real work */ }
        }

        // ---------- UI ----------
        private void BuildUi()
        {
            _lblStatus = new Label
            {
                Text = "Starting...",
                AutoSize = true,
                Location = new Point(12, 10),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold)
            };

            var lblHeld = new Label
            {
                Text = "Held processes (frozen, awaiting your decision):",
                AutoSize = true,
                Location = new Point(12, 34),
                Font = new Font("Segoe UI", 8.25F)
            };

            _listHeld = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Location = new Point(12, 52),
                Size = new Size(430, 92),
                Font = new Font("Segoe UI", 8.25F)
            };
            _listHeld.Columns.Add("Process", 120);
            _listHeld.Columns.Add("PID", 44);
            _listHeld.Columns.Add("Publisher", 130);
            _listHeld.Columns.Add("Held because", 122);
            _listHeld.DoubleClick += (s, e) => ShowDetailsForSelected();

            _btnDetails = new Button { Text = "Details...", Size = new Size(106, 27), Location = new Point(450, 52) };
            _btnDetails.Click += (s, e) => ShowDetailsForSelected();

            _btnUnblock = new Button { Text = "Unblock (run)", Size = new Size(106, 27), Location = new Point(450, 83) };
            _btnUnblock.Click += (s, e) => DecideSelected(allow: true, remember: false);

            _btnBlock = new Button { Text = "Block (kill)", Size = new Size(106, 27), Location = new Point(450, 114) };
            _btnBlock.Click += (s, e) => DecideSelected(allow: false, remember: false);

            var lblLog = new Label
            {
                Text = "Event log:",
                AutoSize = true,
                Location = new Point(12, 150),
                Font = new Font("Segoe UI", 8.25F)
            };

            _listLog = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                Location = new Point(12, 168),
                Size = new Size(536, 100),
                Font = new Font("Segoe UI", 8.25F)
            };
            _listLog.Columns.Add("Time", 70);
            _listLog.Columns.Add("Process", 150);
            _listLog.Columns.Add("Action", 120);
            _listLog.Columns.Add("Publisher", 190);
            _listLog.DoubleClick += (s, e) => OpenDetailsForLogRow();

            _btnPause = new Button { Text = "Pause protection", Size = new Size(120, 28), Location = new Point(12, 280) };
            _btnPause.Click += (s, e) => ToggleProtection();

            _btnSettings = new Button { Text = "Settings...", Size = new Size(100, 28), Location = new Point(140, 280) };
            _btnSettings.Click += (s, e) => new SettingsForm(_config).ShowDialog(this);

            _btnWatchdog = new Button { Text = "Install auto-restart", Size = new Size(140, 28), Location = new Point(248, 280) };
            _btnWatchdog.Click += (s, e) => ToggleWatchdog();

            _btnExit = new Button { Text = "Exit", Size = new Size(80, 28), Location = new Point(396, 280) };
            _btnExit.Click += (s, e) => CloseApp();

            Controls.AddRange(new Control[]
            {
                _lblStatus, lblHeld, _listHeld, _btnDetails, _btnUnblock, _btnBlock,
                lblLog, _listLog, _btnPause, _btnSettings, _btnWatchdog, _btnExit
            });

            UpdatePauseButton();
        }

        private void BuildTray()
        {
            _tray = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "TaskManager Guard Agent",
                Visible = true,
                ContextMenuStrip = new ContextMenuStrip()
            };
            _tray.ContextMenuStrip.Items.Add("Open", null, (s, e) => ShowWindow());
            _tray.ContextMenuStrip.Items.Add("Settings...", null, (s, e) => new SettingsForm(_config).ShowDialog(this));
            _tray.ContextMenuStrip.Items.Add("Exit", null, (s, e) => CloseApp());
            _tray.DoubleClick += (s, e) => ShowWindow();
        }

        // ---------- engine events (marshal to UI thread) ----------
        private void OnHeldAdded(ProcessEventInfo info)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => HeldAddedUi(info))); }
            else HeldAddedUi(info);
        }

        private void HeldAddedUi(ProcessEventInfo info)
        {
            var item = new ListViewItem(string.IsNullOrEmpty(info.Name) ? $"pid {info.Pid}" : info.Name);
            item.SubItems.Add(info.Pid.ToString());
            item.SubItems.Add(string.IsNullOrEmpty(info.Publisher) ? "(unknown)" : info.Publisher);
            item.SubItems.Add(info.HeldReason ?? "");
            item.Tag = info;
            _listHeld.Items.Add(item);

            // Show one permission dialog at a time; the rest wait in the list.
            if (_openPrompt == null || _openPrompt.IsDisposed)
                OpenPromptFor(info);
        }

        private void OnHeldRemoved(ProcessEventInfo info, string decision)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => HeldRemovedUi(info))); }
            else HeldRemovedUi(info);
        }

        private void HeldRemovedUi(ProcessEventInfo info)
        {
            foreach (ListViewItem item in _listHeld.Items)
            {
                if (item.Tag is ProcessEventInfo pi && pi.Pid == info.Pid)
                {
                    _listHeld.Items.Remove(item);
                    break;
                }
            }
            // if the open dialog was for this process, close it and show the next
            if (_openPrompt != null && !_openPrompt.IsDisposed && _openPrompt.Info.Pid == info.Pid)
            {
                _openPrompt.Close(); // FormClosed handler shows the next one
            }
        }

        private void OpenPromptFor(ProcessEventInfo info)
        {
            if (_openPrompt != null && !_openPrompt.IsDisposed) return;
            var dlg = new PromptForm(_engine, info, _config);
            dlg.FormClosed += (s, e) =>
            {
                _openPrompt = null;
                OpenNextHeldPrompt();
            };
            _openPrompt = dlg;
            dlg.Show(this);
        }

        private void OpenNextHeldPrompt()
        {
            // refresh held rows from engine truth
            SyncHeldRows();
            var next = _engine.HeldProcesses.Values.OrderBy(h => h.StartedUtc).FirstOrDefault();
            if (next != null) OpenPromptFor(next);
        }

        private void SyncHeldRows()
        {
            _listHeld.Items.Clear();
            foreach (var h in _engine.HeldProcesses.Values.OrderBy(h => h.StartedUtc))
            {
                var item = new ListViewItem(string.IsNullOrEmpty(h.Name) ? $"pid {h.Pid}" : h.Name);
                item.SubItems.Add(h.Pid.ToString());
                item.SubItems.Add(string.IsNullOrEmpty(h.Publisher) ? "(unknown)" : h.Publisher);
                item.SubItems.Add(h.HeldReason ?? "");
                item.Tag = h;
                _listHeld.Items.Add(item);
            }
        }

        private void OpenDetailsForLogRow()
        {
            if (_listLog.SelectedItems.Count == 0) return;
            if (_listLog.SelectedItems[0].Tag is ProcessEventInfo pi)
            {
                using var dlg = new DetailsForm(_config, pi);
                dlg.ShowDialog(this);
            }
        }

        // ---------- held-list actions ----------
        private ProcessEventInfo SelectedHeld()
        {
            if (_listHeld.SelectedItems.Count == 0)
            {
                MessageBox.Show(this, "Select a held process first.",
                    "TaskManager Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return null;
            }
            return _listHeld.SelectedItems[0].Tag as ProcessEventInfo;
        }

        private void ShowDetailsForSelected()
        {
            var info = SelectedHeld();
            if (info == null) return;
            if (_openPrompt != null && !_openPrompt.IsDisposed) _openPrompt.Close();
            OpenPromptFor(info);
        }

        private void DecideSelected(bool allow, bool remember)
        {
            var info = SelectedHeld();
            if (info == null) return;
            _engine.Decide(info, allow, remember);
        }

        // ---------- log ----------
        private void OnLog(string message)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AppendLog(message))); }
            else AppendLog(message);
        }

        private void AppendLog(string message)
        {
            UpdateStatusText();
            var item = new ListViewItem(DateTime.Now.ToString("HH:mm:ss"));
            item.SubItems.Add(message);
            item.SubItems.Add("");
            item.SubItems.Add("");
            _listLog.Items.Insert(0, item);
            if (_listLog.Items.Count > 500) _listLog.Items.RemoveAt(_listLog.Items.Count - 1);
        }

        private void OnDecisionApplied(ProcessEventInfo info, string decision)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AddDecisionRow(info, decision))); }
            else AddDecisionRow(info, decision);
        }

        private void AddDecisionRow(ProcessEventInfo info, string decision)
        {
            UpdateStatusText();
            var item = new ListViewItem(DateTime.Now.ToString("HH:mm:ss"));
            item.SubItems.Add($"{decision}: {info.Name}");
            item.SubItems.Add(info.Pid.ToString());
            item.SubItems.Add(info.Publisher);
            item.Tag = info;
            _listLog.Items.Insert(0, item);
            if (_listLog.Items.Count > 500) _listLog.Items.RemoveAt(_listLog.Items.Count - 1);
        }

        private void UpdateStatusText()
        {
            _lblStatus.Text = (_config.ProtectionEnabled ? "Protection ACTIVE" : "Protection PAUSED")
                + (_engine.UsingWmiTrace ? "  |  WMI instant trace" : "  |  1s polling")
                + (_engine.HeldProcesses.IsEmpty ? "" : $"  |  {_engine.HeldProcesses.Count} held");
        }

        private void UpdatePauseButton()
        {
            _btnPause.Text = _config.ProtectionEnabled ? "Pause protection" : "Resume protection";
            UpdateStatusText();
        }

        private void ToggleProtection()
        {
            _config.ProtectionEnabled = !_config.ProtectionEnabled;
            _config.Save();
            UpdatePauseButton();
        }

        // ---------- watchdog / autostart ----------
        private bool WatchdogInstalled()
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $"/Query /TN {WatchdogTaskName}",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = System.Diagnostics.Process.Start(psi);
                p.WaitForExit(5000);
                return p.ExitCode == 0;
            }
            catch { return false; }
        }

        private void UpdateWatchdogButton()
        {
            _btnWatchdog.Text = WatchdogInstalled() ? "Remove auto-restart" : "Install auto-restart";
        }

        private void ToggleWatchdog()
        {
            try
            {
                if (WatchdogInstalled())
                {
                    RunSchtasks($"/Delete /F /TN {WatchdogTaskName}");
                    MessageBox.Show(this,
                        "Auto-restart watchdog removed.\nThe agent will no longer relaunch itself.",
                        "TaskManager Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    // A per-minute scheduled task. The single-instance mutex makes the
                    // extra launches no-ops while we are alive; if we are killed or
                    // crash, the task brings us back within a minute.
                    RunSchtasks($"/Create /F /TN {WatchdogTaskName} /TR \"{_exePath}\" /SC MINUTE /RL HIGHEST");
                    MessageBox.Show(this,
                        "Auto-restart watchdog installed.\nThe agent relaunches within one minute if it is ever closed or killed.",
                        "TaskManager Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Watchdog error: " + ex.Message, "TaskManager Guard",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            UpdateWatchdogButton();
        }

        private static void RunSchtasks(string args)
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "schtasks",
                Arguments = args,
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var p = System.Diagnostics.Process.Start(psi);
            p.WaitForExit(10000);
            if (p.ExitCode != 0)
                throw new Exception($"schtasks failed (exit code {p.ExitCode}).");
        }

        // ---------- window lifecycle ----------
        private void ShowWindow()
        {
            Show();
            WindowState = FormWindowState.Normal;
            PositionBottomRight();
            Activate();
        }

        private void CloseApp()
        {
            _engine.Dispose();
            _tray.Visible = false;
            _tray.Dispose();
            Application.Exit();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // minimize to tray instead of exiting
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
                _tray.ShowBalloonTip(1500, "TaskManager Guard", "Still guarding in the background. Double-click the shield icon to reopen.", ToolTipIcon.Info);
                return;
            }
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try { _showSignal?.Dispose(); } catch { }
                _engine?.Dispose();
                _tray?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
