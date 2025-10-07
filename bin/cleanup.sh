#!/bin/bash
set -euo pipefail


# Print initial disk usage
echo "Initial disk usage:"
df -h /

# Clean up Docker containers, images, volumes, and networks
echo "Cleaning up Docker..."

# Remove all unused Docker images
echo "Removing all unused docker images..."
docker image prune -a -f

# Remove all unused Docker volumes
echo "Removing all unused docker volumes..."
docker volume prune -f

# Remove all unused Docker networks
echo "Removing all unused docker networks..."
docker network prune -f

# Comprehensive cleanup including build cache and volumes
echo "Performing comprehensive docker cleanup..."
docker system prune -a --volumes -f

docker builder prune -a -f # Remove all unused build cache

# Rotate or truncate large Docker logs (>100M)
find /var/lib/docker/containers -name "*-json.log" -size +100M -exec truncate -s 0 {} \;


find /var -type f -size +100M -exec du -sh {} + | sort -hr | head -n 20

# Clean up APT cache
echo "Cleaning up APT cache..."
apt-get clean
journalctl --vacuum-time=3d # Remove old journal logs


# Check for large log files and truncate them if necessary
echo "Truncating large log files over 100M..."
LOG_DIR="/var/log"
find "$LOG_DIR" -type f -name "*.log" -size +100M -exec truncate -s 0 {} \;
rm -rf "$LOG_DIR"/*.gz "$LOG_DIR"/*.[0-9] # Remove old rotated logs

# Remove old kernel images
echo "Removing old kernel images..."
dpkg -l 'linux-image*' | awk '/^rc/ {print $2}' | xargs --no-run-if-empty dpkg --purge

# Remove orphaned packages
echo "Removing orphaned packages..."
apt-get autoremove -y
# Remove old package files
echo "Removing old package files..."
apt-get autoclean
# Remove old temporary files
echo "Removing old temporary files..."
find /tmp -type f -atime +10 -delete
# Remove old cache files
echo "Removing old cache files..."
find /var/cache -type f -atime +10 -delete
# Remove old backup files
echo "Removing old backup files..."
find /var/backups -type f -atime +10 -delete

for dir in /home/*/tmp; do
  echo "Removing old user temporary files..."
  [ -d "$dir" ] && find "$dir" -type f -mtime +30 -delete
done

# Only run if such directories exist
for dir in /home/*/.cache; do
  echo "Removing old user cache files..."
  [ -d "$dir" ] && find "$dir" -type f -mtime +30 -delete
done

# Print disk usage after cleanup
echo "Disk usage after cleanup:"
df -h /

# Check Docker disk usage
echo "Docker disk usage:"
du -sh /var/lib/docker

echo "Top disk usage after cleanup:"
du -h /var --max-depth=1 | sort -hr | head -n 10
