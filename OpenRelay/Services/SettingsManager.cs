using System;
using System.IO;
using System.Text.Json;
using System.Security.Cryptography;

namespace OpenRelay.Services
{
    /// <summary>
    /// Stores application settings
    /// </summary>
    public class Settings
    {
        /// <summary>
        /// Whether to use the relay server for device connectivity
        /// </summary>
        public bool UseRelayServer { get; set; } = false;

        /// <summary>
        /// Whether to expose this device to the OpenRelay network
        /// </summary>
        public bool ExposeToRelayNetwork { get; set; } = false;

        /// <summary>
        /// The URI of the relay server
        /// </summary>
        public string RelayServerUri { get; set; } = "wss://relay.pmshaw.com/relay";
    }

    /// <summary>
    /// Manages application settings with encrypted storage
    /// </summary>
    public class SettingsManager
    {
        private Settings _settings = new Settings();
        private readonly string _settingsFilePath;
        private readonly EncryptionService _encryptionService;

        /// <summary>
        /// Initialize the settings manager
        /// </summary>
        public SettingsManager(EncryptionService encryptionService)
        {
            _encryptionService = encryptionService;

            // Get application data folder
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var appFolder = Path.Combine(appData, "OpenRelay");

            // Create directory if it doesn't exist
            if (!Directory.Exists(appFolder))
            {
                Directory.CreateDirectory(appFolder);
            }

            _settingsFilePath = Path.Combine(appFolder, "settings.dat");

            // Load settings if they exist
            LoadSettings();
        }

        /// <summary>
        /// Get the current settings
        /// </summary>
        public Settings GetSettings()
        {
            return _settings;
        }

        /// <summary>
        /// Update settings and save to disk
        /// </summary>
        public void UpdateSettings(Settings settings)
        {
            _settings = settings;
            SaveSettings();
        }

        /// <summary>
        /// Save settings to disk with encryption
        /// </summary>
        private void SaveSettings()
        {
            try
            {
                // Create a master device key if we don't have one
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var appFolder = Path.Combine(appData, "OpenRelay");
                var masterKeyPath = Path.Combine(appFolder, "settings_key.bin");

                // Generate or retrieve master key
                string masterKey;
                if (File.Exists(masterKeyPath))
                {
                    masterKey = SecureRetrieveString(masterKeyPath);
                }
                else
                {
                    masterKey = _encryptionService.GenerateKey();
                    SecureStoreString(masterKeyPath, masterKey);
                }

                // Serialize settings
                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(_settings, options);

                // Encrypt settings
                byte[] jsonBytes = System.Text.Encoding.UTF8.GetBytes(json);
                byte[] encryptedData = _encryptionService.EncryptData(jsonBytes, Convert.FromBase64String(masterKey));

                // Save encrypted settings
                File.WriteAllBytes(_settingsFilePath, encryptedData);

                System.Diagnostics.Debug.WriteLine("[SETTINGS] Saved settings to disk");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SETTINGS] Error saving settings: {ex.Message}");
            }
        }

        /// <summary>
        /// Load settings from disk with decryption
        /// </summary>
        private void LoadSettings()
        {
            try
            {
                if (!File.Exists(_settingsFilePath))
                {
                    // No settings file, use defaults
                    return;
                }

                // Get master key path
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var appFolder = Path.Combine(appData, "OpenRelay");
                var masterKeyPath = Path.Combine(appFolder, "settings_key.bin");

                if (!File.Exists(masterKeyPath))
                {
                    // No master key, can't decrypt settings
                    return;
                }

                // Retrieve master key
                string masterKey = SecureRetrieveString(masterKeyPath);

                // Read encrypted settings
                byte[] encryptedData = File.ReadAllBytes(_settingsFilePath);

                // Decrypt settings
                byte[] jsonBytes = _encryptionService.DecryptData(encryptedData, Convert.FromBase64String(masterKey));
                string json = System.Text.Encoding.UTF8.GetString(jsonBytes);

                // Deserialize settings
                var loadedSettings = JsonSerializer.Deserialize<Settings>(json);
                if (loadedSettings != null)
                {
                    _settings = loadedSettings;
                    System.Diagnostics.Debug.WriteLine("[SETTINGS] Loaded settings from disk");
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SETTINGS] Error loading settings: {ex.Message}");
                // Use defaults if loading fails
            }
        }

        /// <summary>
        /// Securely store a string using DPAPI or similar
        /// </summary>
        private void SecureStoreString(string path, string data)
        {
            try
            {
#if WINDOWS
                // Use Windows DPAPI
                byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
                byte[] protectedData = System.Security.Cryptography.ProtectedData.Protect(
                    dataBytes,
                    null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                File.WriteAllBytes(path, protectedData);
#else
                // For non-Windows platforms, encrypt using our own service
                byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
                
                // Create a device-specific key based on machine ID and user
                string deviceSpecificInfo = Environment.MachineName + Environment.UserName;
                byte[] deviceKeyBytes = System.Security.Cryptography.SHA256.Create()
                    .ComputeHash(System.Text.Encoding.UTF8.GetBytes(deviceSpecificInfo));
                
                // Encrypt with this key
                byte[] encryptedData = _encryptionService.EncryptData(dataBytes, deviceKeyBytes);
                File.WriteAllBytes(path, encryptedData);
#endif
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error securely storing data: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Securely retrieve a string using DPAPI or similar
        /// </summary>
        private string SecureRetrieveString(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    throw new FileNotFoundException("Secure data file not found", path);
                }

                byte[] protectedData = File.ReadAllBytes(path);

                // Use Windows DPAPI
                byte[] dataBytes = System.Security.Cryptography.ProtectedData.Unprotect(
                    protectedData,
                    null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return System.Text.Encoding.UTF8.GetString(dataBytes);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error securely retrieving data: {ex.Message}");
                throw;
            }
        }
    }
}