#!/bin/bash

# Check if swap is already enabled
if swapon --show | grep -q 'swapfile'; then
    echo "Swap is already enabled."
    exit 0
fi

# Create a swap file (1GB size)
if [ ! -f /swapfile ]; then
    echo "Creating swap file..."
    fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "Swap file created and enabled."
else
    echo "/swapfile already exists."
fi

# Make swap file persistent
if ! grep -q '/swapfile' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' | tee -a /etc/fstab
    echo "Added swapfile to /etc/fstab."
fi

# Set swappiness value
sysctl vm.swappiness=10
echo "vm.swappiness=10" | tee -a /etc/sysctl.conf

# Verify swap
echo "Swap setup complete. Current swap status:"
free -h
