using System;
using System.Drawing;
using System.Windows.Forms;

namespace TaskManagerGuardAgent
{
    /// <summary>Read-only view of everything published about a task (the same
    /// details the permission dialog showed), plus permanent actions:
    /// allow always, block always, or unblock (remove from the block list).</summary>
    public class DetailsForm : Form
    {
        private readonly Config _config;
        private readonly ProcessEventInfo _info;

        private TextBox _txtDetails;
        private Button _btnAllowAlways;
        private Button _btnBlockAlways;
        private Button _btnUnblock;
        private Button _btnClose;
        private Label _lblListStatus;

        public DetailsForm(Config config, ProcessEventInfo info)
        {
            _config = config;
            _info = info;

            Text = $"TaskManager Guard - Details: {_info.Name}";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            StartPosition = FormStartPosition.Manual;
            ShowInTaskbar = false;
            ClientSize = new Size(560, 396);

            var lblTitle = new Label
            {
                Text = $"{_info.Name}  (PID {_info.Pid})",
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(12, 12)
            };

            _txtDetails = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Location = new Point(12, 36),
                Size = new Size(536, 220),
                Font = new Font("Consolas", 9F)
            };
            _txtDetails.Text = _info.BuildDetailsText() + Environment.NewLine + Environment.NewLine
                + _info.VT.Summary;

            _lblListStatus = new Label
            {
                AutoSize = true,
                Location = new Point(12, 262),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold)
            };

            _btnAllowAlways = new Button
            {
                Text = "Allow always",
                Size = new Size(120, 32),
                Location = new Point(12, 292)
            };
            _btnAllowAlways.Click += (s, e) =>
            {
                _config.UnblockPath(_info.ExePath); // an allow decision overrides any block entry
                _config.AllowPath(_info.ExePath);
                if (!string.IsNullOrEmpty(_info.Sha256)) _config.AllowHash(_info.Sha256);
                UpdateStatus();
                MessageBox.Show(this,
                    "Added to the allow list (and removed from the block list).\r\nThis file will now be released automatically.",
                    "TaskManager Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            _btnBlockAlways = new Button
            {
                Text = "Block always",
                Size = new Size(120, 32),
                Location = new Point(140, 292)
            };
            _btnBlockAlways.Click += (s, e) =>
            {
                _config.BlockPath(_info.ExePath); // the block list is checked first, so it wins
                UpdateStatus();
                MessageBox.Show(this,
                    "Added to the block list.\r\nThis file will be terminated the moment it appears.",
                    "TaskManager Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            _btnUnblock = new Button
            {
                Text = "Unblock (remove from block list)",
                Size = new Size(196, 32),
                Location = new Point(268, 292)
            };
            _btnUnblock.Click += (s, e) =>
            {
                _config.UnblockPath(_info.ExePath);
                UpdateStatus();
                MessageBox.Show(this,
                    "Removed from the block list.\r\nThe file is no longer blocked permanently.",
                    "TaskManager Guard", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            _btnClose = new Button
            {
                Text = "Close",
                DialogResult = DialogResult.Cancel,
                Size = new Size(80, 32),
                Location = new Point(472, 292)
            };

            Controls.AddRange(new Control[]
            {
                lblTitle, _txtDetails, _lblListStatus,
                _btnAllowAlways, _btnBlockAlways, _btnUnblock, _btnClose
            });

            UpdateStatus();
        }

        private void UpdateStatus()
        {
            if (string.IsNullOrEmpty(_info.ExePath))
            {
                _lblListStatus.Text = "No executable path was captured for this task.";
                return;
            }
            if (_config.IsBlockedPath(_info.ExePath))
                _lblListStatus.Text = "Current permanent rule: BLOCKED (on the block list)";
            else if (_config.IsAllowed(_info.ExePath, _info.Sha256))
                _lblListStatus.Text = "Current permanent rule: ALLOWED (on the allow list)";
            else
                _lblListStatus.Text = "Current permanent rule: none (decisions are one-off)";
        }
    }
}
