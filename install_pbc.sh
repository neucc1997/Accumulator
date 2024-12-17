#!/bin/bash

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run the script as root."
    exit 1
fi

# Define PBC version and download link
PBC_VERSION="0.5.14"
PBC_URL="https://crypto.stanford.edu/pbc/files/pbc-$PBC_VERSION.tar.gz"

# Detect system type
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Unable to detect the operating system type. The script only supports Ubuntu and CentOS systems."
    exit 1
fi

# Function to wait for the lock
wait_for_lock() {
    local lockfile=$1
    echo "Lock file $lockfile detected, waiting for release..."
    while [ -e "$lockfile" ]; do
        # Check if any process is using the lock file
        if lsof "$lockfile" > /dev/null 2>&1; then
            sleep 1
        else
            break
        fi
    done
    echo "Lock file $lockfile has been released, continuing execution."
}

# Function to install dependencies
install_dependencies() {
    if [ "$OS" == "ubuntu" ]; then
        echo "Ubuntu system detected, installing dependencies..."
        wait_for_lock /var/lib/dpkg/lock-frontend
        apt update
        wait_for_lock /var/lib/dpkg/lock-frontend
        apt install -y build-essential libgmp-dev flex bison wget tar
    elif [ "$OS" == "centos" ]; then
        echo "CentOS system detected, installing dependencies..."

        # Detect CentOS version
        if grep -q "^7" /etc/centos-release; then
            echo "CentOS 7 system detected, using yum to install dependencies..."
            yum groupinstall -y "Development Tools"
            yum install -y epel-release gmp-devel flex bison wget tar
        elif grep -q "^8" /etc/centos-release; then
            echo "CentOS 8 system detected, using dnf to install dependencies..."
            dnf groupinstall -y "Development Tools"
            dnf install -y epel-release gmp-devel flex bison wget tar
        else
            echo "Unknown CentOS version, exiting."
            exit 1
        fi
    else
        echo "Unsupported operating system type: $OS"
        exit 1
    fi
}

# Function to download and install PBC
install_pbc() {
    echo "Downloading PBC library..."
    wget $PBC_URL -O pbc-$PBC_VERSION.tar.gz

    if [ $? -ne 0 ]; then
        echo "Download failed, please check the network connection or the validity of the download link."
        exit 1
    fi

    echo "Extracting PBC files..."
    tar -zxvf pbc-$PBC_VERSION.tar.gz

    cd pbc-$PBC_VERSION || { echo "Extraction failed or folder does not exist."; exit 1; }

    echo "Configuring PBC..."
    ./configure

    if [ $? -ne 0 ]; then
        echo "Configuration failed, please check if dependencies are correctly installed."
        exit 1
    fi

    echo "Compiling and installing PBC..."
    make && make install

    if [ $? -ne 0 ]; then
        echo "Compilation or installation failed, please check the error messages."
        exit 1
    fi

    echo "PBC installation completed."
}

# Start the installation
install_dependencies
install_pbc

# Update dynamic link library cache
if [ "$OS" == "ubuntu" ]; then
    ldconfig
elif [ "$OS" == "centos" ]; then
    ldconfig
fi

echo "PBC installation script completed."
