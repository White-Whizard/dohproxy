#!/bin/bash
# Installation script for DoH Proxy systemd service with virtual environment

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Define installation directory
INSTALL_DIR="/opt/dohproxy"
SERVICE_NAME="dohproxy.service"
VENV_DIR="$INSTALL_DIR/venv"

# Check for required tools
if ! command -v python3 &>/dev/null; then
  echo "Error: python3 is required but not installed."
  exit 1
fi

if ! command -v python3-venv &>/dev/null; then
  echo "Warning: python3-venv might not be installed."
  echo "If installation fails, try: apt-get install python3-venv (Debian/Ubuntu)"
  echo "or: yum install python3-venv (CentOS/RHEL)"
fi

# Create installation directory
echo "Creating installation directory..."
mkdir -p $INSTALL_DIR

# Copy files to installation directory
echo "Copying files to $INSTALL_DIR..."
cp dohproxy.py $INSTALL_DIR/
cp config.yaml $INSTALL_DIR/
cp requirements.txt $INSTALL_DIR/

# Create and set up virtual environment
echo "Creating Python virtual environment..."
python3 -m venv $VENV_DIR
if [ $? -ne 0 ]; then
  echo "Failed to create virtual environment. Please install python3-venv package."
  exit 1
fi

# Activate virtual environment and install dependencies
echo "Installing Python dependencies in virtual environment..."
source $VENV_DIR/bin/activate
$VENV_DIR/bin/pip install --upgrade pip
$VENV_DIR/bin/pip install -r $INSTALL_DIR/requirements.txt
deactivate

# Set proper permissions
echo "Setting proper permissions..."
chown -R nobody:nogroup $INSTALL_DIR
chmod -R 750 $INSTALL_DIR
chmod 640 $INSTALL_DIR/config.yaml

# Copy and enable systemd service
echo "Installing systemd service..."
cp $SERVICE_NAME /etc/systemd/system/
systemctl daemon-reload
systemctl enable $SERVICE_NAME

# Start the service
echo "Starting DoH proxy service..."
systemctl start $SERVICE_NAME

# Display status
echo "Service status:"
systemctl status $SERVICE_NAME

echo ""
echo "Installation complete!"
echo ""
echo "Details:"
echo "- Application installed to: $INSTALL_DIR"
echo "- Virtual environment: $VENV_DIR"
echo "- Configuration file: $INSTALL_DIR/config.yaml"
echo ""
echo "You can manage the service with the following commands:"
echo "  systemctl start $SERVICE_NAME"
echo "  systemctl stop $SERVICE_NAME"
echo "  systemctl restart $SERVICE_NAME"
echo "  systemctl status $SERVICE_NAME"
echo ""
echo "Logs can be viewed with: journalctl -u $SERVICE_NAME"
echo ""
echo "To update dependencies in the future:"
echo "  source $VENV_DIR/bin/activate"
echo "  pip install -r $INSTALL_DIR/requirements.txt"
echo "  deactivate"
echo "  systemctl restart $SERVICE_NAME"