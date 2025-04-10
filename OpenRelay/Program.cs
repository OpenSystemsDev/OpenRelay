using System;
using System.Windows.Forms;

namespace OpenRelay
{
    internal static class Program
    {
        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            // Enable better DPI scaling - this setting is crucial for 4K displays
            if (Environment.OSVersion.Version.Major >= 6)
            {
                SetProcessDPIAware();
            }

            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Initialize the Rust library
            int result = NativeMethods.openrelay_init();
            if (result != 0)
            {
                MessageBox.Show("Failed to initialize OpenRelay core library.", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // Start the OpenRelay services
            result = NativeMethods.openrelay_start();
            if (result != 0)
            {
                MessageBox.Show("Failed to start OpenRelay services.", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // Start the application with our main form
            Application.Run(new Form1());

            // Cleanup on exit
            NativeMethods.openrelay_cleanup();
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();
    }
}