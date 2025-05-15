using System;
using System.Drawing;
using System.Windows.Forms;
using OpenRelay.Models;
using OpenRelay.Services;

namespace OpenRelay.UI
{
    public class DeviceManagementDialog : Form
    {
        private ListView deviceListView;
        private Button removeButton;
        private Button refreshButton;
        private Button closeButton;
        private readonly DeviceManager _deviceManager;

        public DeviceManagementDialog(DeviceManager deviceManager)
        {
            _deviceManager = deviceManager;
            InitializeComponents();
            LoadDevices();
        }

        private void InitializeComponents()
        {
            // Form settings
            this.Text = "Manage Paired Devices";
            this.Size = new System.Drawing.Size(600, 400);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MinimizeBox = false;
            this.MaximizeBox = false;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.AutoScaleMode = AutoScaleMode.Dpi;

            // Device list view
            deviceListView = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = false,
                Dock = DockStyle.Fill,
                GridLines = true
            };

            deviceListView.Columns.Add("Device Name", 150);
            deviceListView.Columns.Add("Connection Type", 100);
            deviceListView.Columns.Add("Address/ID", 150);
            deviceListView.Columns.Add("Platform", 100);
            deviceListView.Columns.Add("Last Seen", 120);

            // Buttons
            removeButton = new Button
            {
                Text = "Remove Device",
                Width = 120,
                Height = 30,
                Enabled = false
            };

            refreshButton = new Button
            {
                Text = "Refresh",
                Width = 100,
                Height = 30
            };

            closeButton = new Button
            {
                Text = "Close",
                Width = 100,
                Height = 30,
                DialogResult = DialogResult.Cancel
            };

            // Event handlers
            deviceListView.SelectedIndexChanged += (s, e) =>
                removeButton.Enabled = deviceListView.SelectedItems.Count > 0;

            removeButton.Click += RemoveDevice;
            refreshButton.Click += (s, e) => LoadDevices();

            // Layout
            var buttonPanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.RightToLeft,
                Dock = DockStyle.Bottom,
                Height = 50,
                Padding = new Padding(10)
            };

            buttonPanel.Controls.Add(closeButton);
            buttonPanel.Controls.Add(removeButton);
            buttonPanel.Controls.Add(refreshButton);

            this.Controls.Add(deviceListView);
            this.Controls.Add(buttonPanel);
            this.AcceptButton = closeButton;
            this.CancelButton = closeButton;
        }

        private void LoadDevices()
        {
            deviceListView.Items.Clear();
            var devices = _deviceManager.GetPairedDevices();

            foreach (var device in devices)
            {
                var item = new ListViewItem(device.DeviceName);

                // Add connection type
                item.SubItems.Add(device.ConnectionType.ToString());

                // Add address/ID based on connection type
                if (device.ConnectionType == ConnectionType.Relay)
                {
                    item.SubItems.Add(device.RelayDeviceId);
                }
                else
                {
                    item.SubItems.Add(device.IpAddress);
                }

                item.SubItems.Add(device.Platform);
                item.SubItems.Add(device.LastSeen.ToString("MM/dd/yyyy h:mm:ss tt"));

                item.Tag = device.DeviceId;
                deviceListView.Items.Add(item);
            }

            // Auto-size columns
            foreach (ColumnHeader column in deviceListView.Columns)
            {
                column.Width = -2; // Auto-size to header and content
            }
        }

        private void RemoveDevice(object sender, EventArgs e)
        {
            if (deviceListView.SelectedItems.Count > 0)
            {
                var selectedItem = deviceListView.SelectedItems[0];
                string deviceId = selectedItem.Tag.ToString();
                string deviceName = selectedItem.Text;

                var result = MessageBox.Show(
                    $"Are you sure you want to remove the device '{deviceName}'?",
                    "Confirm Removal",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (result == DialogResult.Yes)
                {
                    _deviceManager.RemoveDevice(deviceId);
                    LoadDevices();
                }
            }
        }
    }
}