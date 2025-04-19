using System;
using System.Runtime.InteropServices;
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
            // TODO this doesn't work well on 1440p sadly
            if (Environment.OSVersion.Version.Major >= 6)
            {
                SetProcessDPIAware();
            }

            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                // Load the openrelay_core.dll
                string dllPath = System.IO.Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory,
                    "openrelay_core.dll");

                if (!System.IO.File.Exists(dllPath))
                {
                    MessageBox.Show(
                        $"The core DLL was not found at: {dllPath}\n" +
                        "Please make sure to copy the DLL to the application directory.",
                        "DLL Not Found",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }

                // Start the application with our main form
                Application.Run(new Form1());
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"Error starting OpenRelay: {ex.Message}\n\n" +
                    $"Stack trace: {ex.StackTrace}",
                    "Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

        [DllImport("user32.dll")]
        private static extern bool SetProcessDPIAware();
    }
}