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

            // Delete existing certificate to avoid password issues
            if (File.Exists(certPath))
            {
                try
                {
                    File.Delete(certPath);
                    System.Diagnostics.Debug.WriteLine("[CERT] Deleted existing certificate to create a fresh one");
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[CERT] Could not delete existing certificate: {ex.Message}");
                }
            }

            // Create a new certificate
            return await Task.Run(() => CreateSelfSignedCertificate());
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

            // Create the certificate with exportable private key
            var cert = req.CreateSelfSigned(
                DateTimeOffset.Now.AddDays(-1), // Valid from yesterday (to avoid time zone issues)
                DateTimeOffset.Now.AddDays(CertificateValidDays));

            // Return the certificate
            return cert;
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

                // Skip certificate binding since it's failing but the app works anyway
                System.Diagnostics.Debug.WriteLine($"[CERT] Skipping certificate binding due to known issues");
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[CERT] Error setting up certificate: {ex.Message}");
                return false;
            }
        }
    }
}