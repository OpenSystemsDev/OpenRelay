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
            if (Environment.OSVersion.Version.Major >= 6)
            {
                SetProcessDPIAware();
            }

            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            try
            {
                // Check if the DLL is properly loaded - this will throw if not
                System.Diagnostics.Debug.WriteLine("Checking if DLL is loaded...");
                IntPtr moduleHandle = LoadLibrary("openrelay_core.dll");
                if (moduleHandle == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    MessageBox.Show($"Failed to load openrelay_core.dll. Error code: {error}", "Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                System.Diagnostics.Debug.WriteLine("DLL loaded successfully");

                // Initialize the Rust library
                System.Diagnostics.Debug.WriteLine("Initializing Rust library...");
                int result = NativeMethods.openrelay_init();
                if (result != 0)
                {
                    MessageBox.Show($"Failed to initialize OpenRelay core library. Error code: {result}", "Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                System.Diagnostics.Debug.WriteLine("Rust library initialized successfully");

                // Start the OpenRelay services
                System.Diagnostics.Debug.WriteLine("Starting OpenRelay services...");
                result = NativeMethods.openrelay_start();
                if (result != 0)
                {
                    MessageBox.Show($"Failed to start OpenRelay services. Error code: {result}", "Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                System.Diagnostics.Debug.WriteLine("OpenRelay services started successfully");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error initializing OpenRelay: {ex.Message}\n\nStack trace: {ex.StackTrace}", "Error",
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

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        private static extern IntPtr LoadLibrary(string libname);
    }
}