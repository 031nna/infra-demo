#!/bin/bash
set -eux

# Detect root device
ROOT_DEVICE=$(lsblk -o NAME,MOUNTPOINT | grep ' /$' | awk '{print $1}')

# Resize the partition
sudo growpart /dev/${ROOT_DEVICE%?} 1

# Resize the filesystem
sudo resize2fs /dev/${ROOT_DEVICE} || sudo xfs_growfs /  # Works for ext4 and xfs

echo "Filesystem resize complete!"
