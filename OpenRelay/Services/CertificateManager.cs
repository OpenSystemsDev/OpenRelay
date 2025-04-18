using System;
using System.IO;
using System.Linq; // Required for LINQ methods on collections
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal; // Required for WindowsIdentity
using System.Threading.Tasks;

namespace OpenRelay.Services
{
    /// <summary>
    /// Manages TLS certificates for secure communication
    /// </summary>
    public class CertificateManager
    {
        private const string CertificateName = "OpenRelay_Certificate";
        private const int CertificateValidDays = 365 * 2; // 2 years
        private const StoreName CertificateStoreName = StoreName.My; // Personal store
        private const StoreLocation CertificateStoreLocation = StoreLocation.LocalMachine; // Machine store

        /// <summary>
        /// Get or create an X.509 certificate for TLS, ensuring it's in the machine store.
        /// </summary>
        public async Task<X509Certificate2> GetOrCreateCertificateAsync()
        {
            // Certificate path in AppData (used for persistence if store fails or for backup)
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var appFolder = Path.Combine(appData, "OpenRelay");
            var certPath = Path.Combine(appFolder, "certificate.pfx");
            var password = "openrelay"; // Simple password for the pfx

            // Create directory if it doesn't exist
            Directory.CreateDirectory(appFolder);

            // First, try to find the certificate in the machine store
            X509Certificate2? certificate = FindCertificateInStore();
            if (certificate != null && certificate.NotAfter > DateTime.Now.AddMonths(1))
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Found valid certificate '{CertificateName}' in {CertificateStoreLocation}/{CertificateStoreName} store.");
                return certificate;
            }
            else if (certificate != null)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Found certificate '{CertificateName}' in store, but it's expired or expiring soon. Removing old certificate.");
                RemoveCertificateFromStore(certificate); // Attempt to remove the old one
            }
            else
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Certificate '{CertificateName}' not found in {CertificateStoreLocation}/{CertificateStoreName} store.");
            }

            // If not found in store or expired, try loading from PFX file (fallback/previous versions)
            if (File.Exists(certPath))
            {
                try
                {
                    // Load with flags suitable for machine store installation
                    var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet;
                    var collection = new X509Certificate2Collection();
                    collection.Import(certPath, password, flags);
                    certificate = collection[0];

                    if (certificate.NotAfter > DateTime.Now.AddMonths(1))
                    {
                        System.Diagnostics.Debug.WriteLine("[CERT] Loaded valid certificate from PFX file. Attempting to install to store.");
                        if (InstallCertificateToStore(certificate))
                        {
                            return certificate;
                        }
                        else
                        {
                            System.Diagnostics.Debug.WriteLine("[CERT] Failed to install certificate from PFX to store. Will create a new one.");
                        }
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine("[CERT] Certificate loaded from PFX file is expired or expiring soon.");
                        // Optionally delete the expired PFX file
                        // File.Delete(certPath);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[CERT] Error loading certificate from PFX: {ex.Message}. Will create a new one.");
                    // Optionally delete the corrupted PFX file
                    // File.Delete(certPath);
                }
            }

            // If no valid certificate found/loaded, create a new one
            System.Diagnostics.Debug.WriteLine("[CERT] Creating a new self-signed certificate.");
            certificate = await Task.Run(() => CreateSelfSignedCertificate(certPath, password));

            // Install the newly created certificate to the store
            if (!InstallCertificateToStore(certificate))
            {
                // If installation fails (e.g., no admin rights), the app might still work if binding is skipped or handled differently,
                // but netsh binding will likely fail. Log this clearly.
                System.Diagnostics.Debug.WriteLine("[CERT] WARNING: Failed to install the new certificate to the machine store. TLS binding might fail.");
            }

            return certificate;
        }

        /// <summary>
        /// Create a self-signed X.509 certificate, save to PFX, and return it.
        /// </summary>
        private X509Certificate2 CreateSelfSignedCertificate(string certPath, string password)
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

            var req = new CertificateRequest($"CN={CertificateName}", ecdsa, HashAlgorithmName.SHA384);

            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false)); // Server Auth
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);
            sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
            sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
            try
            {
                var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
                foreach (var ip in host.AddressList.Where(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork || ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6))
                {
                    sanBuilder.AddIpAddress(ip);
                }
            }
            catch { /* Ignore errors getting local IPs */ }
            req.CertificateExtensions.Add(sanBuilder.Build());

            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(CertificateValidDays));

            // Export to PFX with MachineKeySet flag to ensure private key is stored correctly for machine context
            try
            {
                var flags = X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet;
                byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password);
                File.WriteAllBytes(certPath, pfxBytes);
                System.Diagnostics.Debug.WriteLine($"[CERT] Saved new certificate to {certPath}");

                // Reload the certificate from bytes with the correct flags to ensure it's ready for store installation
                var collection = new X509Certificate2Collection();
                collection.Import(pfxBytes, password, flags);
                return collection[0];
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Failed to export or save certificate PFX: {ex.Message}");
                // Return the in-memory cert; installation might fail later if private key isn't correctly persisted
                return cert;
            }
        }

        /// <summary>
        /// Finds the certificate in the specified machine store.
        /// </summary>
        private X509Certificate2? FindCertificateInStore()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return null;

            try
            {
                using var store = new X509Store(CertificateStoreName, CertificateStoreLocation);
                store.Open(OpenFlags.ReadOnly);
                var certs = store.Certificates.Find(X509FindType.FindBySubjectName, CertificateName, false);

                // Find the most recent valid certificate with a private key
                return certs.OfType<X509Certificate2>()
                            .Where(c => c.HasPrivateKey)
                            .OrderByDescending(c => c.NotAfter)
                            .FirstOrDefault(); // Return the most recent one, even if expired (caller checks expiration)
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Error accessing certificate store: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Installs the certificate to the specified machine store. Requires Admin privileges.
        /// </summary>
        private bool InstallCertificateToStore(X509Certificate2 certificate)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;

            if (!IsAdministrator())
            {
                System.Diagnostics.Debug.WriteLine("[CERT] Administrator privileges required to install certificate to LocalMachine store.");
                return false;
            }

            if (!certificate.HasPrivateKey)
            {
                System.Diagnostics.Debug.WriteLine("[CERT] Certificate does not have a private key, cannot install to store.");
                return false;
            }

            try
            {
                using var store = new X509Store(CertificateStoreName, CertificateStoreLocation);
                store.Open(OpenFlags.ReadWrite);
                // Remove existing ones first to avoid duplicates with the same subject name
                RemoveCertificateFromStore(certificate.SubjectName.Name);
                store.Add(certificate);
                System.Diagnostics.Debug.WriteLine($"[CERT] Successfully installed certificate '{certificate.SubjectName.Name}' to {CertificateStoreLocation}/{CertificateStoreName} store.");
                return true;
            }
            catch (CryptographicException ex) when ((uint)ex.HResult == 0x80070005) // Access Denied
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Access denied installing certificate to {CertificateStoreLocation}/{CertificateStoreName}. Ensure running as Administrator.");
                return false;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Error installing certificate to store: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Removes certificates from the store by subject name.
        /// </summary>
        private void RemoveCertificateFromStore(string subjectName)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || !IsAdministrator()) return;
            try
            {
                using var store = new X509Store(CertificateStoreName, CertificateStoreLocation);
                store.Open(OpenFlags.ReadWrite);
                var certsToRemove = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, false);
                if (certsToRemove.Count > 0)
                {
                    store.RemoveRange(certsToRemove);
                    System.Diagnostics.Debug.WriteLine($"[CERT] Removed {certsToRemove.Count} existing certificate(s) with subject '{subjectName}' from store.");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Error removing certificate(s) with subject '{subjectName}' from store: {ex.Message}");
            }
        }

        /// <summary>
        /// Removes a specific certificate instance from the store.
        /// </summary>
        private void RemoveCertificateFromStore(X509Certificate2 certificate)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || !IsAdministrator()) return;
            try
            {
                using var store = new X509Store(CertificateStoreName, CertificateStoreLocation);
                store.Open(OpenFlags.ReadWrite);
                store.Remove(certificate);
                System.Diagnostics.Debug.WriteLine($"[CERT] Removed certificate '{certificate.SubjectName.Name}' (Thumbprint: {certificate.Thumbprint}) from store.");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Error removing specific certificate (Thumbprint: {certificate.Thumbprint}) from store: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks if the current process is running as administrator.
        /// </summary>
        private static bool IsAdministrator()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Utility to set the certificate on an HttpListener binding
    /// </summary>
    public static class TlsBindingManager
    {
        /// <summary>
        /// Set up the certificate on the given port using netsh (Windows only)
        /// </summary>
        public static bool SetupCertificate(int port, X509Certificate2 certificate)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                System.Diagnostics.Debug.WriteLine("[CERT] Skipping netsh binding setup on non-Windows platform.");
                return true; // Assume non-Windows handles this differently or doesn't need it
            }

            if (!IsAdministrator())
            {
                System.Diagnostics.Debug.WriteLine("[CERT] SetupCertificate requires Administrator privileges.");
                return false;
            }

            try
            {
                // Ensure URL ACL is registered (ignore errors if already exists)
                RunNetshCommand($"http add urlacl url=https://+:{port}/ user=Everyone", true);

                // Remove any existing certificate binding for this ipport (ignore errors if not found)
                System.Diagnostics.Debug.WriteLine($"[CERT] Attempting to delete existing SSL cert binding for 0.0.0.0:{port}");
                RunNetshCommand($"http delete sslcert ipport=0.0.0.0:{port}", true);

                // Add the certificate binding using the certificate's thumbprint
                string appId = "{D1E10C3D-0623-4B54-9A1C-9FF3C55C3EDC}"; // Example AppId, ensure it's valid
                string command = $"http add sslcert ipport=0.0.0.0:{port} certhash={certificate.Thumbprint} appid={appId}";
                System.Diagnostics.Debug.WriteLine($"[CERT] Running netsh command: {command}");
                string result = RunNetshCommand(command); // Don't ignore errors here

                // Check result carefully
                if (result.Contains("SSL Certificate successfully added"))
                {
                    System.Diagnostics.Debug.WriteLine($"[CERT] Certificate binding successful for port {port}");
                    return true;
                }
                else
                {
                    // Log the full error from netsh
                    System.Diagnostics.Debug.WriteLine($"[CERT] Certificate binding failed. Netsh output:\n{result}");
                    // Throw an exception to make the failure explicit in logs and potentially halt startup
                    throw new Exception($"SSL Certificate add failed. Output: {result}");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Error setting up certificate binding: {ex.Message}\n{ex.StackTrace}");
                // Check specifically for error 1312 and provide guidance
                if (ex.Message.Contains("Error: 1312") || (ex.InnerException is System.ComponentModel.Win32Exception w32ex && w32ex.NativeErrorCode == 1312))
                {
                    System.Diagnostics.Debug.WriteLine("[CERT] Error 1312: 'A specified logon session does not exist.' This often means netsh lacks the necessary context or permissions, even as admin. Ensure the certificate's private key is accessible by the 'NETWORK SERVICE' account (or the account running netsh) and the certificate is correctly installed in the Local Machine store.");
                }
                return false;
            }
        }

        /// <summary>
        /// Run a netsh command and return the combined output/error. Throws on non-zero exit code unless ignoreErrors is true.
        /// </summary>
        private static string RunNetshCommand(string arguments, bool ignoreErrors = false)
        {
            var process = new System.Diagnostics.Process();
            process.StartInfo.FileName = "netsh";
            process.StartInfo.Arguments = arguments;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            // process.StartInfo.Verb = "runas"; // Usually not needed if the app is already elevated

            try
            {
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                string fullOutput = $"Exit Code: {process.ExitCode}\nOutput:\n{output}\nError:\n{error}";

                if (!ignoreErrors && process.ExitCode != 0)
                {
                    throw new Exception($"Netsh command failed.\nArguments: {arguments}\n{fullOutput}");
                }

                return fullOutput;
            }
            catch (Exception ex)
            {
                string errorMsg = $"Netsh command execution failed.\nArguments: {arguments}\nError: {ex.Message}";
                if (ex is System.ComponentModel.Win32Exception winEx && winEx.NativeErrorCode == 1223) // ERROR_CANCELLED (UAC prompt denied)
                {
                    errorMsg += "\nOperation cancelled, likely due to UAC denial.";
                }

                if (!ignoreErrors)
                {
                    throw new Exception(errorMsg, ex);
                }
                return errorMsg; // Return error message if ignoring errors
            }
        }

        /// <summary>
        /// Checks if the current process is running as administrator.
        /// </summary>
        private static bool IsAdministrator()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return false;
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}