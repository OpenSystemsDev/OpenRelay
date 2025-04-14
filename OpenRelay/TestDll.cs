using System;
using System.Runtime.InteropServices;

namespace OpenRelay
{
    public static class TestDll
    {
        // A simple test method to check if basic P/Invoke is working
        // This will help isolate if the issue is with P/Invoke itself or with the Rust DLL

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern int MessageBox(IntPtr hWnd, String text, String caption, uint type);

        public static void TestPInvoke()
        {
            try
            {
                // Try a simple P/Invoke call
                MessageBox(IntPtr.Zero, "Testing P/Invoke functionality", "P/Invoke Test", 0);
                System.Diagnostics.Debug.WriteLine("Basic P/Invoke test successful");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"P/Invoke test failed: {ex}");
            }
        }
    }
}