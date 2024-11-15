#!/usr/bin/env bash


# Check for root access
if [[ $EUID -ne 0 ]]; then
  echo -e "This script must be run as root. Please use 'sudo' or log in as root.\n"
  exit 1
fi


declare new_hostname
declare set_username
install_dir=$(cd "$(dirname "$0")" && pwd)
timestamp=$(date +"%m%d%H%M%S")
logfile="$install_dir/Fedora-Setup-Errors_$timestamp.log"


exec 3>&2
exec 2> "$logfile"


# Error handling and send to logfile
error() {
    local msg="$1"
    echo -e "\nError: $msg" | tee -a "$logfile"
    return 1
}


#================================================
#    SET USER AND HOSTNAME
#================================================


# Prompt and validate input for username or hostname
name_check() {
    local config_type="$1"  # 'username' or 'hostname'
    local current_value=""
    local new_value=""
    local confirm_value=""

    if [[ "$config_type" == "username" ]]; then
        current_value="$(logname)"
    elif [[ "$config_type" == "hostname" ]]; then
        current_value="$(hostname -s)"
    else
        error "Invalid config type specified."
    fi

    echo -e "\nCurrent $config_type is '$current_value'"

    # Ask if user wants to change the value
    read -rp "Do you want to change it? [Y/n] " 2>&3
    case "${REPLY,,}" in
        n)  new_value="$current_value"
            return
            ;;
        y)  # Loop until valid input is entered
            while true; do
                read -rp "Please choose new $config_type: " 2>&3 new_value
                if [[ ! "$new_value" =~ ^[A-Za-z0-9_-]+$ ]]; then
                    echo -e "\nInvalid format, please try again."
                    continue
                fi
                read -rp "Please confirm new $config_type: " 2>&3 confirm_value
                if [[ "$new_value" == "$confirm_value" ]]; then
                    break
                else
                    echo -e "\n$config_type(s) do not match, please try again."
                fi
            done
            ;;
        *)
            echo -e "\nInvalid choice, please try again."
            name_check "$config_type"  # Recursion replaced with a loop for safety
            return
            ;;
    esac

    # Process the input after it's validated
    if [[ "$config_type" == "username" ]]; then
        set_username="$new_value"
        add_user
    elif [[ "$config_type" == "hostname" ]]; then
        new_hostname="$new_value"
        new_host
    fi
}


# Add new user if requested
add_user() {
    echo "Creating new user '$set_username'..."
    if ! id "$set_username" &>/dev/null; then
        useradd -mG wheel -s /bin/bash "$set_username" || { error "Failed to add new user."; exit 1; }
        echo "Success!"
    else
        error "User '$set_username' already exists."
    fi
}


# Change hostname if requested
new_host() {
    echo "Setting hostname to '$new_hostname'..."
    if [[ $(hostname -s) != "$new_hostname" ]]; then
        hostnamectl set-hostname "$new_hostname" --pretty || error "Failed to set hostname."
        echo "Success!"
    else
        error "Hostname already set to $new_hostname\n."
    fi
}


name_check "username"
name_check "hostname"


#================================================
#    PACKAGE MANAGEMENT
#================================================


# Install apps from 'packages' file
install_apps() {
    echo -e "\nInstalling applications ...\n"
    if [[ -f "${install_dir}/packages" ]]; then
        source "${install_dir}/packages" || { error "'packages' script not found."; exit 1; }
    else
        error "'packages' file not found in $install_dir."
        exit 1
    fi
}


# Remove common Fedora bloatware
rm_bloatware() {
    echo -e "\nRemoving common bloatware ...\n"
    if [[ -f "${install_dir}/bloatware" ]]; then
        dnf remove "$(grep "^[^#]" bloatware)" || error "Couldn't load 'bloatware' file."
    else
        error "'bloatware' file not found in $install_dir."
    fi
}


install_apps
rm_bloatware


#================================================
#    SYSTEM CONFIGURATION
#================================================


# Copy config files to /etc
copy_etc() {
    echo -e "\nCopying config files to /etc/ ...\n"
    if [[ -d configs ]]; then
      cp -r configs/. /etc || error "Failed to copy configuration files."
    else
      error "'configs' directory not found in $install_dir."
    fi
}


# Update grub configuration
grub_config() {
    echo -e "\nUpdating grub configuration ...\n"
    # Backup grub file
    cp /etc/default/grub /etc/default/grub.bak_"$timestamp"

    # Determine efi or grub2
    if [[ -d /sys/firmware/efi ]]; then
      grub_file="/boot/efi/EFI/fedora/grub.cfg"
    else
      grub_file="/boot/grub2/grub.cfg"
    fi

    # Regenerate grub config
    grub2-mkconfig -o "$grub_file" || { error "Failed to update grub configuration."; exit 1; }
}


# Configure system hosts file
hosts_config() {
    echo -e "\nConfiguring /etc/hosts ...\n"
    if echo -e "127.0.0.1\tlocalhost $new_hostname" > /etc/hosts; then
      echo "done"
    else
      error "Could not set system 'hosts' file."
    fi
}


# Configure display manager
dm_config() {
    echo -e "\nConfiguring LXDM display manager ..."
    current_dm=$(readlink /etc/systemd/system/display-manager.service | awk -F/ '{print $NF}' | sed 's/.service//')

    # If lxdm is not installed, do nothing
    if ! command -v lxdm &>/dev/null; then
        error "'lxdm' package is not installed."
    else
        # If current dm is not lxdm, stop and disable it
        if [[ -n $current_dm ]]; then
            systemctl stop "$current_dm"
            systemctl disable "$current_dm"
        fi
        # Enable lxdm and set as default
        systemctl enable lxdm
        systemctl set-default graphical.target
    fi
    # Set autologin user
    if sed -i "s|<user>|${set_username}|g" /etc/lxdm/lxdm.conf 2>/dev/null; then
      echo "done"
    else
      error "Could not set user '$set_username' for lxdm."
    fi
}


# Configure local-sudo file
sudo_config() {
    echo -e "\nConfiguring sudo for $set_username ...\n"
    if sed -i "s|<user>|${set_username}|g" /etc/sudoers.d/local-sudo 2>/dev/null; then
      echo "done"
    else
      error "Could not configure /etc/sudoers.d/local-sudo."
    fi
}


# Configure sysctl parameters
sysctl_config() {
    echo -e "\nSetting kernel parameters ...\n"
    kernel_param="/etc/sysctl.d/99-sysctl.conf"

    if [[ -e $kernel_param ]]; then
        sysctl -p "$kernel_param"
    else
        error "File '99-sysctl.conf' not found."
    fi
}


# Harden the filesystem table
fstab_config() {
    echo -e "\nConfiguring /etc/fstab ...\n"
    cp /etc/fstab /etc/fstab.bak_"$timestamp"

    # Modify /etc/fstab using sed
    if [[ -f /etc/fstab ]]; then
        sed -i.bak \
        -e '/boot/ s=defaults=noatime=' \
        -e '/\/[[:space:]]/ s=defaults=noatime=' \
        -e '/home/ s=defaults=noatime,nodev,nosuid=' \
        -e '/var/ s=defaults=noatime,nodev,nosuid=' \
        -e 's/\S\+/0/5' \
        -e 's/\S\+/0/6' \
        /etc/fstab || error "Could not find /etc/fstab file."
    fi

    # Append additional mount entries to /etc/fstab
    {
        echo "/tmp  /var/tmp  none  nodev,nosuid,noexec,bind  0 0"
        echo "tmpfs /tmp    tmpfs nodev,nosuid,noexec 0 0"
        echo "tmpfs /dev/shm  tmpfs nodev,nosuid,noexec 0 0"
        echo "proc  /proc   proc  nodev,nosuid,noexec     0 0"
    } >> /etc/fstab || error "Could not edit /etc/fstab file."

    # Check if the configuration was successful
    if systemctl daemon-reload; then
        echo "done"
    else
        error "There wasd a problem loading /etc/fstab."
    fi
}


copy_etc
grub_config
hosts_config
dm_config
sudo_config
sysctl_config
fstab_config


#================================================
#    SET-UP USER FILES
#================================================


# Copy dotfiles to /home/*
copy_home() {
    echo -e "\nCopying dotfiles to /home/$set_username ...\n"
    if [[ -d dotfiles ]]; then
      cp -r dotfiles/. /home/"${set_username}" || error "Failed to copy user files to /home/."
    else
      error "Directory 'dotfiles' not found in $install_dir."
    fi
}


# Set owner and permissions for /home/*
home_config() {
    echo -e "\nSetting /home permissions for user '$set_username' ...\n"

    if [[ ! -d /home/"${set_username}" ]]; then
        error "Home directory /home/${set_username} does not exist."
    else
        if ! chown -R "${set_username}:${set_username}" /home/"${set_username}"; then
            error "Failed to change ownership for /home/${set_username}."
        fi
        if ! chmod -R 0750 /home/"${set_username}"; then
            error "Failed to set permissions for /home/${set_username}."
        fi
        echo "Permissions successfully set for /home/${set_username}."
    fi
}


# Load dconf settings
dconf_config() {
    echo -e "\nLoading dconf settings ...\n"
    dconf_dir="/home/${set_username}/.config/dconf/dconf-settings.ini"

    # Replace <user> with username
    if sed -i "s|<user>|${set_username}|g" "$dconf_dir" 2>/dev/null; then
        echo "User '$set_username' has been set for dconf."
    else
        error "Could not set user '$set_username' for dconf."
    fi

    # Load the dconf settings as the target user
    if sudo -u "$set_username" dconf load / < "$dconf_dir"; then
        echo "dconf settings loaded successfully."
    else
        error "Could not load dconf settings."
    fi
}


copy_home
home_config
dconf_config


#================================================
#    SYSTEM SECURITY
#================================================


dnf_security() {
    echo -e "\nEnabling DNF security updates ...\n"

    if ! command -v "dnf-automatic" &>/dev/null; then
        error "'dnf-automatic' package is not installed."
    fi

    # Enable update service
    if systemctl enable --now dnf-automatic.timer &>/dev/null; then
        echo "DNF security updates enabled successfully"
    else
        error "Failed to enable DNF security updates."
    fi
}


nordvpn_config() {
    echo -e "\nConfiguring NordVPN ...\n"

    if ! command -v nordvpn &>/dev/null; then
        error "'nordvpn' package is not installed."
    fi

    # Add user to nordvpn group
    if ! groups "$set_username" | grep -o nordvpn; then
        usermod -aG nordvpn "$set_username" || error "Could not add user to 'nordvpn'"
    fi

    # Enable and start nordvpnd service
    systemctl enable --now nordvpnd || error "NordVPN could not be enabled."

    # Switch to user to change settings
    su - "$set_username" bash -c "
        nordvpn set technology nordlynx
        nordvpn set cybersec on
        nordvpn set analytics off
    "
}


firejail_config() {
    echo -e "\nConfiguring firejail ...\n"

    if ! command -v "firejail" &>/dev/null; then
        error "'firejail' package is not installed."
    fi

    # Create firejail group
    if ! getent group firejail &>/dev/null; then
        groupadd firejail || error "Could not add group firejail"
    else
        echo "Group 'firejail' created."
    fi
    # Add user to firejail group
    if ! groups "$set_username" | grep -o firejail; then
        usermod -aG firejail "$set_username" || error "Could not add user to 'firejail'"
    else
        echo "User added to 'firejail'"
    fi

    # Set permissions for firejail executable
    if [[ ! -d /usr/bin/firejail ]]; then
        error "Directory /usr/bin/firejail does not exist."
    else
        if ! chown root:firejail /usr/bin/firejail; then
            error "Failed to set ownership for /usr/bin/firejail"
        fi
        if ! chmod 4750 /usr/bin/firejail; then
            error "Failed to set permissions for /usr/bin/firejail"
        fi
        echo "Permissions set for /usr/bin/firejail"
    fi

    # Load firejail profiles
    firecfg
}


# Set firewall defaults
firewalld_config() {
    echo -e "\nConfiguring Firewalld ...\n"

    if ! command -v firewalld &>/dev/null; then
        error "'firewalld' package is not installed."
    else
        firewall-cmd --set-default-zone=drop
        firewall-cmd --permanent --add-icmp-block-inversion
        firewall-cmd --reload
    fi
}


# Confirm seLinux is enforcing
selinux_config() {
    echo -e "\nConfirm SELinux is 'Enforcing' ...\n"
    selinux_check=$(getenforce)

    if [[ $selinux_check != "Enforcing" ]]; then
        echo -e "SELINUX=enforcing\nSELINUXTYPE=targeted" > /etc/selinux/config
    else
        error "SELinux could not be configured."
    fi
    echo "SELinux is set to 'Enforcing'."
}


dnf_security
nordvpn_config
firejail_config
firewalld_config
selinux_config


#================================================
#    SETUP COMPLETE
#================================================


# Install confirmation prompt
echo -e "\nSetup complete! Press any key to reboot..\n"
read -n 1 -rs


# Clean up installation files
rm -rf -- "$install_dir"/{main.zip,fedora-xfce-setup}


reboot