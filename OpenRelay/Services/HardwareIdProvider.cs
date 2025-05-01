using System;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace OpenRelay.Services
{
    /// <summary>
    /// Provides hardware-based device identification for Windows
    /// using only the most stable hardware components
    /// </summary>
    public class HardwareIdProvider
    {
        // Cache the HWID to avoid repeated expensive WMI calls
        private static string _cachedHwid = null;

        /// <summary>
        /// Get a unique hardware identifier for this device
        /// </summary>
        public static string GetHardwareId()
        {
            if (!string.IsNullOrEmpty(_cachedHwid))
                return _cachedHwid;

            // Generate hardware ID for Windows
            _cachedHwid = GenerateWindowsHardwareId();

            System.Diagnostics.Debug.WriteLine($"[HWID] Generated hardware ID: {_cachedHwid}");
            return _cachedHwid;
        }

        /// <summary>
        /// Generate a hardware ID for Windows using WMI
        /// Focuses only on the most stable components that rarely change:
        /// - CPU information
        /// - BIOS information
        /// - Motherboard information
        /// - Windows Hardware ID
        /// </summary>
        private static string GenerateWindowsHardwareId()
        {
            StringBuilder hardwareInfo = new StringBuilder();

            // CPU Information - high stability
            string processorId = GetWmiIdentifier("Win32_Processor", "ProcessorId");
            hardwareInfo.AppendLine("CPU >> " + processorId);

            // Fallback CPU identifiers if ProcessorId is not available
            if (string.IsNullOrEmpty(processorId))
            {
                hardwareInfo.AppendLine("CPU-Name >> " + GetWmiIdentifier("Win32_Processor", "Name"));
                hardwareInfo.AppendLine("CPU-Manufacturer >> " + GetWmiIdentifier("Win32_Processor", "Manufacturer"));
                hardwareInfo.AppendLine("CPU-Cores >> " + GetWmiIdentifier("Win32_Processor", "NumberOfCores"));
                hardwareInfo.AppendLine("CPU-Socket >> " + GetWmiIdentifier("Win32_Processor", "SocketDesignation"));
            }

            // BIOS Information - high stability
            hardwareInfo.AppendLine("BIOS-Manufacturer >> " + GetWmiIdentifier("Win32_BIOS", "Manufacturer"));
            hardwareInfo.AppendLine("BIOS-Version >> " + GetWmiIdentifier("Win32_BIOS", "SMBIOSBIOSVersion"));
            hardwareInfo.AppendLine("BIOS-Serial >> " + GetWmiIdentifier("Win32_BIOS", "SerialNumber"));
            hardwareInfo.AppendLine("BIOS-UUID >> " + GetWmiIdentifier("Win32_ComputerSystemProduct", "UUID"));

            // Motherboard Information - high stability
            hardwareInfo.AppendLine("MB-Manufacturer >> " + GetWmiIdentifier("Win32_BaseBoard", "Manufacturer"));
            hardwareInfo.AppendLine("MB-Product >> " + GetWmiIdentifier("Win32_BaseBoard", "Product"));
            hardwareInfo.AppendLine("MB-Serial >> " + GetWmiIdentifier("Win32_BaseBoard", "SerialNumber"));
            hardwareInfo.AppendLine("MB-Version >> " + GetWmiIdentifier("Win32_BaseBoard", "Version"));

            // Windows Machine GUID (very stable, survives reinstalls if not clean install)
            try
            {
                string machineGuid = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Cryptography")?.GetValue("MachineGuid")?.ToString() ?? string.Empty;

                hardwareInfo.AppendLine("Windows-MachineGuid >> " + machineGuid);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HWID] Error getting Windows Machine GUID: {ex.Message}");
            }

            // ComputerSystem SIDs can also be stable
            try
            {
                string computerSID = GetWmiIdentifier("Win32_ComputerSystem", "Name");
                hardwareInfo.AppendLine("ComputerSystem-Name >> " + computerSID);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HWID] Error getting Computer System ID: {ex.Message}");
            }

            // First try SHA256 for modern systems
            try
            {
                using (var sha256 = SHA256.Create())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(hardwareInfo.ToString());
                    byte[] hashBytes = sha256.ComputeHash(inputBytes);

                    var sb = new StringBuilder();
                    for (int i = 0; i < hashBytes.Length; i++)
                    {
                        sb.Append(hashBytes[i].ToString("X2"));
                    }
                    return sb.ToString();
                }
            }
            catch
            {
                // Fall back to MD5 if SHA256 is not available on older systems
                using (var md5 = MD5.Create())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(hardwareInfo.ToString());
                    byte[] hashBytes = md5.ComputeHash(inputBytes);

                    var sb = new StringBuilder();
                    for (int i = 0; i < hashBytes.Length; i++)
                    {
                        sb.Append(hashBytes[i].ToString("X2"));
                    }
                    return sb.ToString();
                }
            }
        }

        /// <summary>
        /// Retrieve WMI hardware identifier (with optional filter)
        /// </summary>
        private static string GetWmiIdentifier(string className, string propertyName, string filterName = null, string filterValue = null)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher($"SELECT {propertyName} FROM {className}" +
                    (filterName != null ? $" WHERE {filterName}='{filterValue}'" : "")))
                {
                    foreach (var obj in searcher.Get())
                    {
                        if (obj[propertyName] != null)
                        {
                            return obj[propertyName].ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[HWID] Error getting {className}.{propertyName}: {ex.Message}");
            }
            return string.Empty;
        }
    }
}