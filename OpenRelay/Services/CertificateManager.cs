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
                    // Try to load the certificate
                    var cert = new X509Certificate2(certPath, string.Empty, X509KeyStorageFlags.Exportable);

                    // Check if certificate is still valid
                    if (cert.NotAfter > DateTime.Now.AddMonths(1))
                    {
                        return cert;
                    }

                    // Certificate is about to expire, create a new one
                }
                catch
                {
                    // Certificate could not be loaded, create a new one
                }
            }

            // Create a new certificate
            var cert2 = await Task.Run(() => CreateSelfSignedCertificate());

            // Save the certificate
            File.WriteAllBytes(certPath, cert2.Export(X509ContentType.Pfx));

            return cert2;
        }

        /// <summary>
        /// Create a self-signed X.509 certificate
        /// </summary>
        private X509Certificate2 CreateSelfSignedCertificate()
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

            // Create a copy of the certificate with exportable private key
            return new X509Certificate2(
                cert.Export(X509ContentType.Pfx),
                string.Empty,
                X509KeyStorageFlags.Exportable);
        }
    }

    /// <summary>
    /// Utility to set the certificate on an HttpListener binding
    /// </summary>
    public static class TlsBindingManager
    {
        [DllImport("httpapi.dll", SetLastError = true)]
        private static extern uint HttpSetServiceConfiguration(
            IntPtr serviceIntPtr,
            int configId, // HTTP_SERVICE_CONFIG_ID
            IntPtr configInformation,
            int configInformationLength,
            IntPtr overlapped);

        private const int HttpServiceConfigSslCertInfo = 0;

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

                // Use netsh to bind the certificate on Windows
                var process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = $"http add sslcert ipport=0.0.0.0:{port} certhash={certificate.Thumbprint} appid={{D1E10C3D-0623-4B54-9A1C-9FF3C55C3EDC}}";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.Start();

                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                // If exit code is not 0, command failed
                if (process.ExitCode != 0)
                {
                    // If certificate is already bound, try to delete and rebind
                    if (output.Contains("already assigned") || error.Contains("already assigned"))
                    {
                        // Delete existing binding
                        var deleteProcess = new System.Diagnostics.Process();
                        deleteProcess.StartInfo.FileName = "netsh";
                        deleteProcess.StartInfo.Arguments = $"http delete sslcert ipport=0.0.0.0:{port}";
                        deleteProcess.StartInfo.UseShellExecute = false;
                        deleteProcess.StartInfo.CreateNoWindow = true;
                        deleteProcess.Start();
                        deleteProcess.WaitForExit();

                        // Try binding again
                        process = new System.Diagnostics.Process();
                        process.StartInfo.FileName = "netsh";
                        process.StartInfo.Arguments = $"http add sslcert ipport=0.0.0.0:{port} certhash={certificate.Thumbprint} appid={{D1E10C3D-0623-4B54-9A1C-9FF3C55C3EDC}}";
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.CreateNoWindow = true;
                        process.Start();
                        process.WaitForExit();

                        return process.ExitCode == 0;
                    }

                    System.Diagnostics.Debug.WriteLine($"Failed to set up certificate: {output}\n{error}");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error setting up certificate: {ex.Message}");
                return false;
            }
        }
    }
}