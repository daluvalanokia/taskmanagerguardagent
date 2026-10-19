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
                // Single process: only one instance is ever allowed to run. Ask the
                // live instance to show its window, then exit immediately.
                try
                {
                    using var signal = EventWaitHandle.OpenExisting(@"Global\TaskManagerGuardAgent_ShowSignal");
                    signal.Set();
                }
                catch { }
                _singleInstanceMutex.Dispose();
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
