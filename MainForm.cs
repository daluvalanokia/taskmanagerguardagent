using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace TaskManagerGuardAgent
{
    /// <summary>Small always-on-top-able status window + tray icon. Runs the guard
    /// engine in the background and pops PromptForm for every new process.</summary>
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
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(620, 400);
            ShowInTaskbar = true;

            BuildUi();
            BuildTray();

            _engine.PromptRequired += OnPromptRequired;
            _engine.Log += OnLog;
            _engine.DecisionApplied += OnDecisionApplied;

            _engine.Start();
            UpdateWatchdogButton();
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
                Location = new Point(12, 40),
                Size = new Size(596, 268)
            };
            _list.Columns.Add("Time", 78);
            _list.Columns.Add("Process", 140);
            _list.Columns.Add("PID", 52);
            _list.Columns.Add("Action", 120);
            _list.Columns.Add("Publisher", 200);

            _btnPause = new Button { Text = "Pause protection", Size = new Size(130, 30), Location = new Point(12, 320) };
            _btnPause.Click += (s, e) => ToggleProtection();

            _btnSettings = new Button { Text = "Settings...", Size = new Size(130, 30), Location = new Point(150, 320) };
            _btnSettings.Click += (s, e) => new SettingsForm(_config).ShowDialog(this);

            _btnWatchdog = new Button { Text = "Install auto-restart", Size = new Size(150, 30), Location = new Point(288, 320) };
            _btnWatchdog.Click += (s, e) => ToggleWatchdog();

            _btnExit = new Button { Text = "Exit", Size = new Size(100, 30), Location = new Point(446, 320) };
            _btnExit.Click += (s, e) => CloseApp();

            Controls.AddRange(new Control[] { _lblStatus, _list, _btnPause, _btnSettings, _btnWatchdog, _btnExit });

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
        private void OnPromptRequired(ProcessEventInfo info)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => ShowPrompt(info))); }
            else ShowPrompt(info);
        }

        private void ShowPrompt(ProcessEventInfo info)
        {
            using var dlg = new PromptForm(_engine, info, _config);
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
            AddRow(DateTime.Now, message, "", "");
        }

        private void OnDecisionApplied(ProcessEventInfo info, string decision)
        {
            if (InvokeRequired) { BeginInvoke(new Action(() => AddRow(DateTime.Now, $"{decision}: {info.Name}", info.Pid.ToString(), info.Publisher))); }
            else AddRow(DateTime.Now, $"{decision}: {info.Name}", info.Pid.ToString(), info.Publisher);
        }

        private void AddRow(DateTime time, string process, string pid, string publisher)
        {
            var item = new ListViewItem(time.ToString("HH:mm:ss"));
            item.SubItems.Add(process);
            item.SubItems.Add(pid);
            item.SubItems.Add("");
            item.SubItems.Add(publisher);
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
