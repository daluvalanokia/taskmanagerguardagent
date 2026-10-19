using System;
using System.Drawing;
using System.Windows.Forms;

namespace TaskManagerGuardAgent
{
    /// <summary>The permission dialog for a held process. OK = release it onto the
    /// CPU, Cancel = keep it blocked (killed). Shown non-modally so the main window
    /// stays usable while the dialog is open.</summary>
    public class PromptForm : Form
    {
        private readonly GuardEngine _engine;
        private readonly ProcessEventInfo _info;
        private readonly Config _config;
        private readonly System.Windows.Forms.Timer _countdown;
        private int _secondsLeft;
        private System.Windows.Forms.Timer _vtPoll;
        private bool _decided;

        private Label _lblTitle;
        private TextBox _txtDetails;
        private Button _btnOk;
        private Button _btnCancel;
        private Label _lblVt;
        private LinkLabel _lnkVt;
        private Label _lblCountdown;
        private CheckBox _chkAlways;

        public ProcessEventInfo Info => _info;

        public PromptForm(GuardEngine engine, ProcessEventInfo info, Config config)
        {
            _engine = engine;
            _info = info;
            _config = config;
            _secondsLeft = config.AutoBlockSeconds;

            BuildUi();

            if (config.AutoBlockSeconds > 0)
            {
                _countdown = new System.Windows.Forms.Timer { Interval = 1000 };
                _countdown.Tick += OnCountdownTick;
                _countdown.Start();
            }
            else _countdown = null;

            // Poll for the VirusTotal result arriving from the worker thread.
            _vtPoll = new System.Windows.Forms.Timer { Interval = 500 };
            _vtPoll.Tick += (s, e) =>
            {
                if (_info.VT.Completed)
                {
                    _lblVt.Text = _info.VT.Summary;
                    if (!string.IsNullOrEmpty(_info.VT.Permalink))
                    {
                        _lnkVt.Text = "View full report on VirusTotal";
                        _lnkVt.Links.Add(0, _lnkVt.Text.Length, _info.VT.Permalink);
                    }
                    else _lnkVt.Visible = false;
                    _vtPoll.Stop();
                }
            };
            _vtPoll.Start();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            Activate();
        }

        private void BuildUi()
        {
            Text = "TaskManager Guard - Permission Required";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.Manual;
            TopMost = true;
            ShowInTaskbar = true;
            ClientSize = new Size(560, 400);

            // Bottom-right corner of the working area (above the taskbar).
            var wa = Screen.PrimaryScreen.WorkingArea;
            Location = new Point(wa.Right - Width - 10, wa.Bottom - Height - 10);

            _lblTitle = new Label
            {
                Text = $"A new process was blocked and held:\n{_info.Name}  (PID {_info.Pid})",
                Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
                AutoSize = false,
                Width = 540,
                Height = 40,
                Location = new Point(12, 10)
            };

            _txtDetails = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Location = new Point(12, 54),
                Size = new Size(536, 210),
                Font = new Font("Consolas", 9F)
            };
            _txtDetails.Text = _info.BuildDetailsText();

            _lblVt = new Label
            {
                Text = "Checking with VirusTotal...",
                AutoSize = true,
                Location = new Point(12, 270),
                Font = new Font("Segoe UI", 9F)
            };

            _lnkVt = new LinkLabel
            {
                Text = "",
                AutoSize = true,
                Location = new Point(12, 289),
                Visible = false
            };
            _lnkVt.LinkClicked += (s, e) =>
            {
                if (e.Link.LinkData is string url) System.Diagnostics.Process.Start(
                    new System.Diagnostics.ProcessStartInfo { FileName = url, UseShellExecute = true });
            };

            _chkAlways = new CheckBox
            {
                Text = "Remember this decision for this file",
                AutoSize = true,
                Location = new Point(12, 312)
            };

            _btnOk = new Button
            {
                Text = "OK - Allow to run",
                Size = new Size(150, 32),
                Location = new Point(12, 340)
            };
            _btnOk.Click += (s, e) => Decide(true, _chkAlways.Checked);

            _btnCancel = new Button
            {
                Text = "Cancel - Keep blocked",
                Size = new Size(150, 32),
                Location = new Point(168, 340)
            };
            _btnCancel.Click += (s, e) => Decide(false, _chkAlways.Checked);

            _lblCountdown = new Label
            {
                Text = _config.AutoBlockSeconds > 0
                    ? $"Auto-block in {_secondsLeft}s"
                    : "",
                AutoSize = true,
                Location = new Point(330, 348),
                Font = new Font("Segoe UI", 8.25F),
                ForeColor = Color.Firebrick
            };

            AcceptButton = _btnOk;
            CancelButton = _btnCancel;

            Controls.AddRange(new Control[] {
                _lblTitle, _txtDetails, _lblVt, _lnkVt, _chkAlways,
                _btnOk, _btnCancel, _lblCountdown
            });
        }

        private void OnCountdownTick(object sender, EventArgs e)
        {
            _secondsLeft--;
            _lblCountdown.Text = $"Auto-block in {_secondsLeft}s";
            if (_secondsLeft <= 0)
            {
                _countdown?.Stop();
                if (!_decided)
                {
                    _engine.WriteLog($"Auto-blocked after timeout: {_info.Name} ({_info.Pid})");
                    Decide(false, remember: false);
                }
            }
        }

        private void Decide(bool allow, bool remember)
        {
            if (_decided) return;
            _decided = true;
            _countdown?.Stop();
            _vtPoll?.Stop();

            _engine.Decide(_info, allow, remember);

            Close();
        }

        /// <summary>Closing the dialog any other way (Alt+F4) counts as Cancel = keep blocked.</summary>
        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);
            if (!_decided)
            {
                Decide(false, remember: false);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _countdown?.Dispose();
                _vtPoll?.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
