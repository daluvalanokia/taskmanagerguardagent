using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace TaskManagerGuardAgent
{
    /// <summary>Compact status window pinned to the bottom-right corner + tray icon.
    /// Runs the guard engine in the background and pops PromptForm for every new
    /// process. Double-click a row (or right-click -> View details) to see the
    /// published details of a task and to allow, block or unblock it permanently.</summary>
    public class MainForm : Form
    {
        private readonly Config _config;
        private readonly GuardEngine _engine;
        private NotifyIcon _tray;
        private ListView _list;
        private Label _lblStatus;
        private Button _btnPause;
        private Button _btnSettings;
        private Button _btnWatchdog;
        private Button _btnDetails;
        private Button _btnExit;
        private readonly string _exePath = Application.ExecutablePath;
        private const string WatchdogTaskName = "TaskManagerGuardAgent_Watchdog";

        public MainForm(Config config)
        {
            _config = config;
            _engine = new GuardEngine(config);

            Text = "TaskManager Guard Agent";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.Manual;
            ClientSize = new Size(620, 236);
            ShowInTaskbar = true;

            BuildUi();
            BuildTray();
            MoveToBottomCorner();

            _engine.PromptRequired += OnPromptRequired;
            _engine.Log += OnLog;
            _engine.DecisionApplied += OnDecisionApplied;

            _engine.Start();
            UpdateWatchdogButton();
        }

        // ---------- window placement ----------
        /// <summary>Pins the window to the bottom-right corner of the screen,
        /// leaving a small margin from the taskbar edge.</summary>
        private void MoveToBottomCorner()
        {
            var wa = Screen.PrimaryScreen.WorkingArea;
            Location = new Point(wa.Right - Width - 12, wa.Bottom - Height - 12);
        }

        private void BuildUi()
        {
            _lblStatus = new Label
            {
                Text = "Starting...",
                AutoSize = true,
                Location = new Point(12, 12),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            _list = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                HideSelection = false,
                Location = new Point(12, 36),
                Size = new Size(596, 152)
            };
            _list.Columns.Add("Time", 78);
            _list.Columns.Add("Process", 140);
            _list.Columns.Add("PID", 52);
            _list.Columns.Add("Action", 120);
            _list.Columns.Add("Publisher", 200);

            // Right-click menu on a task row: view the published details and
            // allow / block / unblock the file permanently without waiting for
            // it to launch again.
            var ctx = new ContextMenuStrip();
            ctx.Items.Add("View details", null, (s, e) => ShowDetails());
            ctx.Items.Add("Allow always (this file)", null, (s, e) => AllowSelectedAlways());
            ctx.Items.Add("Block always (this file)", null, (s, e) => BlockSelectedAlways());
            ctx.Items.Add("Unblock (remove from block list)", null, (s, e) => UnblockSelected());
            _list.ContextMenuStrip = ctx;
            _list.DoubleClick += (s, e) => ShowDetails();

            _btnPause = new Button { Text = "Pause protection", Size = new Size(110, 30), Location = new Point(12, 196) };
            _btnPause.Click += (s, e) => ToggleProtection();

            _btnSettings = new Button { Text = "Settings...", Size = new Size(110, 30), Location = new Point(128, 196) };
            _btnSettings.Click += (s, e) =>
            {
                var sf = new SettingsForm(_config);
                var wa = Screen.FromControl(this).WorkingArea;
                sf.Location = new Point(wa.Right - sf.Width - 12, wa.Bottom - sf.Height - 12);
                sf.ShowDialog(this);
            };

            _btnWatchdog = new Button { Text = "Install auto-restart", Size = new Size(130, 30), Location = new Point(246, 196) };
            _btnWatchdog.Click += (s, e) => ToggleWatchdog();

            _btnDetails = new Button { Text = "Details...", Size = new Size(90, 30), Location = new Point(384, 196) };
            _btnDetails.Click += (s, e) => ShowDetails();

            _btnExit = new Button { Text = "Exit", Size = new Size(90, 30), Location = new Point(482, 196) };
            _btnExit.Click += (s, e) => CloseApp();

            Controls.AddRange(new Control[] { _lblStatus, _list, _btnPause, _btnSettings, _btnWatchdog, _btnDetails, _btnExit });

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
            _tray.ContextMenuStrip.Items.Add("Settings...", null, (s, e) =>
            {
                var sf = new SettingsForm(_config);
                var wa = Screen.FromControl(this).WorkingArea;
                sf.Location = new Point(wa.Right - sf.Width - 12, wa.Bottom - sf.Height - 12);
                sf.ShowDialog(this);
            });
            _tray.ContextMenuStrip.Items.Add("Exit", null, (s, e) => CloseApp());
            _tray.DoubleClick += (s, e) => ShowWindow();
        }

        // ---------- task details / allow / block / unblock ----------
        private ProcessEventInfo SelectedInfo()
        {
            if (_list.SelectedItems.Count == 0) return null;
            return _list.SelectedItems[0].Tag as ProcessEventInfo;
        }

        private void ShowDetails()
        {
            var info = SelectedInfo();
            if (info == null)
            {
                MessageBox.Show(this, "This row is a log line; there are no task details to view.\nSelect a row with a process name first.",
                    "TaskManager Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            using var dlg = new DetailsForm(_config, info);
            var wa = Screen.FromControl(this).WorkingArea;
            dlg.Location = new Point(wa.Right - dlg.Width - 12, wa.Bottom - dlg.Height - 12);
            dlg.ShowDialog(this);
        }

        private void AllowSelectedAlways()
        {
            var info = SelectedInfo();
            if (info == null) return;
            _config.UnblockPath(info.ExePath); // an allow decision overrides any block entry
            _config.AllowPath(info.ExePath);
            if (!string.IsNullOrEmpty(info.Sha256)) _config.AllowHash(info.Sha256);
            _engine.WriteLog($"Unblocked + allowed always: {info.Name} ({info.ExePath})");
        }

        private void BlockSelectedAlways()
        {
            var info = SelectedInfo();
            if (info == null) return;
            _config.BlockPath(info.ExePath);
            _engine.WriteLog($"Blocked always: {info.Name} ({info.ExePath})");
        }

        private void UnblockSelected()
        {
            var info = SelectedInfo();
            if (info == null) return;
            _config.UnblockPath(info.ExePath);
            _engine.WriteLog($"Unblocked (removed from block list): {info.Name} ({info.ExePath})");
        }

        // ---------- engine events (marshal to UI thread) ----------
        private void OnPromptRequired(ProcessEventInfo info)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => ShowPrompt(info))); }
            else ShowPrompt(info);
        }

        private void ShowPrompt(ProcessEventInfo info)
        {
            using var dlg = new PromptForm(_engine, info, _config);
            var wa = Screen.FromControl(this).WorkingArea;
            dlg.Location = new Point(wa.Right - dlg.Width - 12, wa.Bottom - dlg.Height - 12);
            dlg.ShowDialog(this); // modal; OK=allow, Cancel=block (decided inside)
        }

        private void OnLog(string message)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AppendLog(message))); }
            else AppendLog(message);
        }

        private void AppendLog(string message)
        {
            _lblStatus.Text = (_config.ProtectionEnabled ? "Protection ACTIVE" : "Protection PAUSED")
                + (_engine.UsingWmiTrace ? "  |  mode: WMI instant trace" : "  |  mode: 1s polling");
            AddRow(DateTime.Now, message, null);
        }

        private void OnDecisionApplied(ProcessEventInfo info, string decision)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AddRow(DateTime.Now, decision, info))); }
            else AddRow(DateTime.Now, decision, info);
        }

        private void AddRow(DateTime time, string action, ProcessEventInfo info)
        {
            var item = new ListViewItem(time.ToString("HH:mm:ss"));
            item.SubItems.Add(info?.Name ?? "");
            item.SubItems.Add(info?.Pid.ToString() ?? "");
            item.SubItems.Add(action ?? "");
            item.SubItems.Add(info?.Publisher ?? "");
            item.Tag = info;
            _list.Items.Insert(0, item);
            if (_list.Items.Count > 500) _list.Items.RemoveAt(_list.Items.Count - 1);
        }

        private void UpdatePauseButton()
        {
            _btnPause.Text = _config.ProtectionEnabled ? "Pause protection" : "Resume protection";
            _lblStatus.Text = (_config.ProtectionEnabled ? "Protection ACTIVE" : "Protection PAUSED")
                + (_engine.UsingWmiTrace ? "  |  mode: WMI instant trace" : "  |  mode: 1s polling");
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
                    // crash, the task brings us back within a minute. The engine also
                    // never guards its own exe, so the relaunched copy always reaches
                    // its mutex check instead of being frozen by this instance.
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
            MoveToBottomCorner();
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
                _engine?.Dispose();
                _tray?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
