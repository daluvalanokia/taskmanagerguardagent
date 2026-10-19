using System;
using System.Drawing;
using System.Windows.Forms;

namespace TaskManagerGuardAgent
{
    public class SettingsForm : Form
    {
        private readonly Config _config;
        private TextBox _txtApiKey;
        private NumericUpDown _numAutoBlock;
        private CheckBox _chkQuiet;
        private Button _btnSave;
        private Button _btnClose;

        public SettingsForm(Config config)
        {
            _config = config;

            Text = "TaskManager Guard - Settings";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            StartPosition = FormStartPosition.Manual;
            ClientSize = new Size(540, 192);

            var lblKey = new Label
            {
                Text = "VirusTotal API key (free at virustotal.com, profile -> API key):",
                AutoSize = true,
                Location = new Point(12, 14)
            };
            _txtApiKey = new TextBox
            {
                Location = new Point(12, 30),
                Size = new Size(516, 23),
                UseSystemPasswordChar = true,
                Text = _config.VirusTotalApiKey
            };

            var lblSecs = new Label
            {
                Text = "Auto-block countdown on the permission dialog (seconds, 0 = wait forever):",
                AutoSize = true,
                Location = new Point(12, 74)
            };
            _numAutoBlock = new NumericUpDown
            {
                Location = new Point(12, 94),
                Minimum = 0,
                Maximum = 600,
                Value = _config.AutoBlockSeconds
            };

            _chkQuiet = new CheckBox
            {
                Text = "Silently allow well-known Windows system background processes",
                AutoSize = true,
                Location = new Point(12, 128),
                Checked = _config.QuietSystemProcesses
            };

            _btnSave = new Button
            {
                Text = "Save",
                Size = new Size(100, 30),
                Location = new Point(12, 168)
            };
            _btnSave.Click += (s, e) =>
            {
                _config.VirusTotalApiKey = _txtApiKey.Text.Trim();
                _config.AutoBlockSeconds = (int)_numAutoBlock.Value;
                _config.QuietSystemProcesses = _chkQuiet.Checked;
                _config.Save();
                MessageBox.Show(this, "Settings saved.", "TaskManager Guard",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                Close();
            };

            _btnClose = new Button
            {
                Text = "Cancel",
                Size = new Size(100, 30),
                Location = new Point(120, 168)
            };
            _btnClose.Click += (s, e) => Close();

            Controls.AddRange(new Control[] { lblKey, _txtApiKey, lblSecs, _numAutoBlock, _chkQuiet, _btnSave, _btnClose });
        }
    }
}
