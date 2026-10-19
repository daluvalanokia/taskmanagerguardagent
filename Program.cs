using System;
using System.Threading;
using System.Windows.Forms;

namespace TaskManagerGuardAgent
{
    internal static class Program
    {
        // Single process guarantee: a global mutex means only one instance ever runs.
        private static Mutex _singleInstanceMutex;

        [STAThread]
        static void Main()
        {
            bool createdNew;
            _singleInstanceMutex = new Mutex(true, @"Global\TaskManagerGuardAgent_SingleInstance", out createdNew);
            if (!createdNew)
            {
                // The auto-restart watchdog relaunches us every minute; if an instance
                // is already alive we exit silently so there is never a second process.
                return;
            }

            ApplicationConfiguration.Initialize();

            var config = Config.Load();
            using var mainForm = new MainForm(config);
            Application.Run(mainForm);

            GC.KeepAlive(_singleInstanceMutex);
        }
    }
}
