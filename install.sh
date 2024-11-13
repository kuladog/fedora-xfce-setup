#!/usr/bin/env bash


# Check for root access
if [[ $EUID -ne 0 ]]; then
  echo -e "This script must be run as root. Please use 'sudo' or log in as root.\n"
  exit 1
fi


declare new_hostname
declare set_username
install_dir=$(dirname "$0")
timestamp=$(date +"%m%d%H%M%S")
logfile="$install_dir/Fedora-Setup-Errors $timestamp.log"


# Redirect stderr to log file
exec 2> "$logfile"


# Send error messages to log file
log_error() {
    local msg="$1"
    echo -e "\nError: $msg" | tee -a "$logfile"
    return 1
}


#================================================
#    SET USER AND HOSTNAME
#================================================


# Add new user if needed
new_user() {
    echo "Creating user '$set_username'..."

    if ! id "$set_username" &>/dev/null; then
        useradd -mG wheel -s /bin/bash "$set_username" || { log_error "Failed to add new user."; exit 1 }
    fi
}


# Prompt to select username, and check if valid
check_user() {
    echo -e "Setup will configure system for user '$(logname)'"
    echo -n "Press 'y' to continue, or 'n' to set a new user: "
    read -r name

    case "${name,,}" in
        y)
            set_username="$(logname)"
            ;;
        n)
            echo "Please enter new username: "; read username1
            if [[ ! "$username1" =~ ^[a-zA-Z0-9_-]+$ ]]; then
                log_error "Invalid username format.\n"
                check_user
            fi
            echo "Please confirm new username: "; read username2
            
            if [[ $username1 = $username2 ]]; then
                set_username="$username1"
                new_user
            else
                echo -e "Usernames do not match, please try again.\n"
                check_user
            fi
            ;;
        *)
            echo -e "Invalid choice. Please try again.\n"
            check_user
            ;;
    esac
}


check_host() {
    echo -e "Current system hostname is '$(hostname -s)'"
    echo -n "Press 'y' to continue, or 'n' to set hostname: "
    read -r host

    case "${host,,}" in
        y)
            new_hostname="$(hostname -s)"
            ;;
        n)
            echo "Please enter new hostname: "; read new_hostname
            read -p "Set hostname to "$new_hostname"? [Y/n]: " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                hostnamectl set-hostname "$new_hostname" --pretty || log_error "Failed to set hostname."          
            else
                check_host
            ;;
        *)
            echo "Invalid choice. Please try again."
            check_host
            ;;
    esac
}


check_user
check_host


#================================================
#    PACKAGE MANAGEMENT
#================================================


# Install apps from packages script file
install_apps() {
    echo -e "\nInstalling applications ...\n"

    if [[ -f "$install_dir/packages" ]]; then
        source "$install_dir/packages" || { log_error "'packages' script not found."; exit 1; }
    else
        log_error "'packages' file not found in $install_dir."
        exit 1
    fi
}


# Remove common Fedora bloatware
rm_bloatware() {
    echo -e "\nRemoving common bloatware ...\n"

    if [[ -f "$install_dir/bloatware" ]]; then
        dnf remove $(grep "^[^#]" bloatware) || log_error "Couldn't load 'bloatware' file."
    else
        log_error "'bloatware' file not found in $install_dir."
    fi
}


install_apps
rm_bloatware


#================================================
#    SYSTEM CONFIGURATION
#================================================


# Copy config files to /etc
copy_etc() {
    echo -e "\nCopying config files ...\n"

    if [[ -d configs ]]; then
      cp -r configs/. /etc || log_error "Failed to copy files."
    else
      log_error "Directory 'configs' not found."
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

    # Regenerate grub configuration
    grub2-mkconfig -o "$grub_file" || { log_error "Failed to update grub config."; exit 1; }
}


# Configure /etc/hosts file
hosts_config() {
    echo -e "\nConfiguring /etc/hosts ...\n"

    echo -e "127.0.0.1\tlocalhost $new_hostname" > /etc/hosts
    if [[ $? -eq 0 ]]; then
      echo "done"
    else
      log_error "Could not set 'hosts' file."
    fi
}


# Configure display manager
dm_config() {
    echo -e "\nConfiguring LXDM Display Manager..."

    current_dm=$(readlink /etc/systemd/system/display-manager.service | awk -F/ '{print $NF}' | sed 's/.service//')

    # If 'lxdm' is not installed, do nothing
    if ! command -v lxdm &>/dev/null; then
        log_error "'lxdm' package is not installed."
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

    # Set autologin for selected user
    if sed -i "s|<user>|${set_username}|g" /etc/lxdm/lxdm.conf 2>/dev/null; then
      echo "done"
    else
      log_error "Could not set user for lxdm."
    fi
}


# Configure local-sudo file
sudo_config() {
    echo -e "\nConfiguring local-sudo ...\n"

    if sed -i "s|<user>|${set_username}|g" /etc/sudoers.d/local-sudo 2>/dev/null; then
      echo "done"
    else
      log_error "Could not set 'local-sudo'."
    fi
}


# Configure sysctl parameters
sysctl_config() {
    echo -e "\nSetting kernel parameters ...\n"

    kernel_params="/etc/sysctl.d/99-sysctl.conf"

    if [[ -e $kernel_params ]]; then
        sysctl -p "$kernel_params"
    else
        log_error "File '99-sysctl.conf' not found."
    fi
}


# Harden the filesystem table
fstab_config() {
    echo -e "\nConfiguring /etc/fstab ...\n"

    # Backup fstab
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
        /etc/fstab || log_error "Cannot find /etc/fstab."
    fi

    # Append additional mount entries to /etc/fstab
    {
        echo "/tmp  /var/tmp  none  nodev,nosuid,noexec,bind  0 0"
        echo "tmpfs /tmp    tmpfs nodev,nosuid,noexec 0 0"
        echo "tmpfs /dev/shm  tmpfs nodev,nosuid,noexec 0 0"
        echo "proc  /proc   proc  nodev,nosuid,noexec     0 0"
    } >> /etc/fstab || log_error "Could not edit /etc/fstab."

    # Check if the configuration was successful
    if systemctl daemon-reload; then
        echo "done"
    else
        log_error "Problem loading /etc/fstab."
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
    echo -e "\nCopying dotfiles to /home ...\n"

    if [[ -d dotfiles ]]; then
      cp -r dotfiles/. /home/"${set_username}" || log_error "Failed to copy files."
    else
      log_error "Directory 'dotfiles' not found."
    fi
}


# Set owner and permissions
home_config() {
    echo -e "\nSetting /home permissions ...\n"

    if chown -R "${set_username}":"${set_username}" /home/"${set_username}" && \
       chmod -R 750 /home/"${set_username}"; then
       echo "done"
    else
       log_error"Could not set ${HOME} permissions."
    fi
}


# Load dconf settings
dconf_config() {
    echo -e "\nLoading dconf settings ...\n"

    if sudo -u "$set_username" dconf load / < dotfiles/.config/dconf/dconf-settings.ini; then
        echo "done"
    else
        log_error "Could not load dconf settings."
    fi
}


copy_home
home_config
dconf_config


#================================================
#    SYSTEM SECURITY
#================================================


dnf_security() {
    echo -e "\nEnabling DNF security updates...\n"

    # Check if dnf-automatic package is installed
    if ! command -v "dnf-automatic" &>/dev/null; then
        log_error "'dnf-automatic' package is not installed."
    fi

    # Enable and start the dnf-automatic.timer service
    if systemctl enable --now dnf-automatic.timer &>/dev/null; then
        echo "DNF security updates enabled successfully"
    else
        log_error "Failed to enable DNF security updates."
    fi
}


nordvpn_config() {
    echo -e "\nConfiguring NordVPN ...\n"

    # Check if NordVPN package is installed
    if ! command -v nordvpn &>/dev/null; then
        log_error "'nordvpn' package is not installed."
    fi    

    # Add user to nordvpn group
    if ! groups "$set_username" | grep -o nordvpn; then
        usermod -aG nordvpn "$set_username" || log_error "Could not add user to 'nordvpn'"
    fi

    # Enable and start nordvpnd service
    systemctl enable --now nordvpnd || log_error "NordVPN could not be enabled."

    # Switch to user shell to execute commands as the user
    su - "$set_username" bash -c "
        nordvpn set technology nordlynx
        nordvpn set cybersec on
        nordvpn set analytics off
    "
}


# Set up firejail for user
firejail_config() {
    echo -e "\nConfiguring firejail ...\n"

    # Check if firejail package is installed
    if ! command -v "firejail" &>/dev/null; then
        log_error "'firejail' package is not installed."
    fi

    # Create firejail group if it doesn't exist
    if ! getent group firejail &>/dev/null; then
        groupadd firejail
    fi

    # Set permissions for firejail executable
    chown root:firejail /usr/bin/firejail && \
    chmod 4750 /usr/bin/firejail || log_error "Could not set firejail permissions'"

    # Add user to firejail group
    if ! groups "$set_username" | grep -o firejail; then
        usermod -aG firejail "$set_username" || log_error "Could not add user to 'firejail'"
    fi

    # Load firejail profiles
    firecfg
}


# Set firewall defaults
firewalld_config() {
    echo -e "\nConfiguring Firewalld ...\n"

    # Set default zone to "drop"
    firewall-cmd --set-default-zone=drop

    # Add rule to block ICMP block inversion
    firewall-cmd --permanent --add-icmp-block-inversion

    # Reload firewall configuration
    firewall-cmd --reload

    # List all firewall settings
    echo
    firewall-cmd --list-all
}


# Confirm seLinux is 'enforcing'
selinux_config() {
    echo -e "\nConfirm SELinux is 'Enforcing' ...\n"

    selinux_check=$(getenforce)

    if [[ $selinux_check != "Enforcing" ]]; then
        echo -e "SELINUX=enforcing\nSELINUXTYPE=targeted" > /etc/selinux/config
    else
        log_error "SELinux could not be configured."
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


clear


# Install confirmation prompt
echo -e "\nSetup complete! Press any key to reboot..\n"
read -n 1 -rs


# Clean up installation files
rm -rf -- "$install_dir"/{main.zip,fedora-xfce-setup}


reboot
