using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.InteropServices;

namespace OpenRelay.Services
{
    /// <summary>
    /// Manages TLS certificates for secure communication
    /// </summary>
    public class CertificateManager
    {
        private const string CertificateName = "OpenRelay_Certificate";
        private const int CertificateValidDays = 365 * 2; // 2 years

        /// <summary>
        /// Get or create an X.509 certificate for TLS
        /// </summary>
        public async Task<X509Certificate2> GetOrCreateCertificateAsync()
        {
            // Certificate path in AppData
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var appFolder = Path.Combine(appData, "OpenRelay");
            var certPath = Path.Combine(appFolder, "certificate.pfx");
            var password = "openrelay"; // Simple password for the pfx

            // Create directory if it doesn't exist
            if (!Directory.Exists(appFolder))
            {
                Directory.CreateDirectory(appFolder);
            }

            // Check if certificate already exists
            if (File.Exists(certPath))
            {
                try
                {
                    // Try to load the certificate using X509Certificate2Collection
                    var collection = new X509Certificate2Collection();
                    collection.Import(certPath, password, X509KeyStorageFlags.Exportable);
                    var cert = collection[0]; // Get the first certificate in the collection

                    // Check if certificate is still valid
                    if (cert.NotAfter > DateTime.Now.AddMonths(1))
                    {
                        return cert;
                    }

                    // Certificate is about to expire, create a new one
                    System.Diagnostics.Debug.WriteLine("[CERT] Certificate is expiring soon, creating a new one");
                }
                catch (Exception ex)
                {
                    // Certificate could not be loaded, create a new one
                    System.Diagnostics.Debug.WriteLine($"[CERT] Error loading certificate: {ex.Message}");
                }
            }

            // Create a new certificate
            return await Task.Run(() => CreateSelfSignedCertificate(certPath, password));
        }

        /// <summary>
        /// Create a self-signed X.509 certificate
        /// </summary>
        private X509Certificate2 CreateSelfSignedCertificate(string certPath, string password)
        {
            // Generate a new key pair
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);

            // Create a certificate request
            var req = new CertificateRequest(
                $"CN={CertificateName}",
                ecdsa,
                HashAlgorithmName.SHA384);

            // Add enhanced key usage extension for server authentication
            req.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server Authentication
                    false));

            // Add basic constraints
            req.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));

            // Add key usage extension
            req.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    false));

            // Add subject alternative name extension with localhost
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);
            sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
            sanBuilder.AddIpAddress(System.Net.IPAddress.IPv6Loopback);

            // Try to add all local IP addresses
            try
            {
                var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
                foreach (var ip in host.AddressList)
                {
                    sanBuilder.AddIpAddress(ip);
                }
            }
            catch
            {
                // Ignore errors when getting local IPs
            }

            req.CertificateExtensions.Add(sanBuilder.Build());

            // Create the certificate
            var cert = req.CreateSelfSigned(
                DateTimeOffset.Now.AddDays(-1), // Valid from yesterday (to avoid time zone issues)
                DateTimeOffset.Now.AddDays(CertificateValidDays));

            // Export to PFX with password
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password);

            // Save to file
            File.WriteAllBytes(certPath, pfxBytes);

            // Load the certificate using the modern approach
            var collection = new X509Certificate2Collection();
            collection.Import(certPath, password, X509KeyStorageFlags.Exportable);
            return collection[0];
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
            try
            {
                if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // On non-Windows platforms, this is handled differently
                    return true;
                }

                // First ensure URL is registered
                RunNetshCommand($"http add urlacl url=https://+:{port}/ user=Everyone", true);

                // Remove any existing certificate binding
                RunNetshCommand($"http delete sslcert ipport=0.0.0.0:{port}", true);

                // Add the certificate binding
                string result = RunNetshCommand($"http add sslcert ipport=0.0.0.0:{port} certhash={certificate.Thumbprint} appid={{D1E10C3D-0623-4B54-9A1C-9FF3C55C3EDC}}");

                if (result.Contains("SSL Certificate successfully added"))
                {
                    System.Diagnostics.Debug.WriteLine($"[CERT] Certificate binding successful for port {port}");
                    return true;
                }
                else if (result.Contains("Error") || result.Contains("failed"))
                {
                    System.Diagnostics.Debug.WriteLine($"[CERT] Certificate binding failed: {result}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Error setting up certificate: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Run a netsh command and return the output
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

            try
            {
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (!ignoreErrors && process.ExitCode != 0)
                {
                    throw new Exception($"{output}\n{error}");
                }

                return output + "\n" + error;
            }
            catch (Exception ex)
            {
                if (!ignoreErrors)
                {
                    throw;
                }
                return $"Command execution failed: {ex.Message}";
            }
        }
    }
}