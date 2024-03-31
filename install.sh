#!/usr/bin/env bash


# Check for root access
if [[ $EUID -ne 0 ]]; then
  echo -e "Please run setup as 'root'\n"
  exit 1
fi


declare new_hostname
declare set_username
install_dir="$(dirname "$(pwd)")"
timestamp=$(date +"%Y%m%d%H%M%S")


# Log standard errors to file  
exec 2> "$install_dir/Fedora-Setup-Errors-$timestamp.log"


#================================================
#    SET USER AND HOSTNAME
#================================================


# Prompt to select username, and check if valid
check_user() {
    echo -e "Setup will configure system for user '$(logname)'"
    echo -n "Press 'y' to continue, or 'n' to set a new user: "
    read -r choice

    case "${choice,,}" in
        y)
            set_username="$(logname)"
            ;;
        n)
            read -rp "Please enter new username: " set_username
            if ! id "$set_username" &>/dev/null; then
                if useradd -mG wheel -s /bin/bash "$set_username" 2>/dev/null; then
                    echo -e "New user '$set_username' successfully added."
                else
                    echo -e "Error: Failed to add new user '$set_username'."
                    exit 1
                fi
            fi
            ;;
        *)
            echo "Invalid choice. Please try again."
            check_user
            ;;
    esac

    echo -e "Continuing setup for '$set_username'.."
}


# Set hostname if not done already
check_host() {
    if [[ $(hostname -s) = "fedora" ]]; then
      read -rp "Enter system hostname: " new_hostname

      if hostnamectl set-hostname "$new_hostname" --pretty; then
        echo -e "\nHostname set to $new_hostname"
      else
        echo -e "\nError: Failed to set hostname"
        exit 1
      fi
    fi
}

check_user
check_host


#================================================
#    INSTALL APPLICATIONS
#================================================


# Install apps from packages script file
install_apps() {
if [[ -f packages ]]; then
      source "$(dirname "$0")"/packages
else
    echo -e "Error: Could not find 'packages' script"
    exit 1
fi
}

install_apps


#================================================
#    SYSTEM CONFIGURATION
#================================================


# Copy config files to /etc
copy_etc() {
    echo -e "\nCopying config files ...\n"

    if [[ -d configs ]]; then
      cp -r configs/. /etc || echo "Failed to copy files."
    else
      echo -e "\nDirectory 'configs' not found."
    fi
}

copy_etc


# Update grub configuration
grub_config() {
    if [[ -d /sys/firmware/efi ]]; then
      grub_file="/boot/efi/EFI/fedora/grub.cfg"
    else
      grub_file="/boot/grub2/grub.cfg"
    fi

    if ! grub2-mkconfig -o "$grub_file"; then
      echo -e "Error: Failed to update grub config"
      exit 1
    fi
}

grub_config


# Configure /etc/hosts file
hosts_config() {
    echo -e "\nConfiguring /etc/hosts ...\n"

    echo -e "127.0.0.1\tlocalhost $new_hostname" > /etc/hosts
    if [[ $? -eq 0 ]]; then
      echo "done"
    else
      echo "Could not set 'hosts' file"
    fi
}

hosts_config


# Configure display manager
dm_config() {
    echo -e "\nConfiguring lxdm ..."

    if ! command -v "lxdm" &>/dev/null; then
      echo "Error: 'lxdm' package is not installed"
      return 1
    fi

    systemctl enable lxdm
    systemctl set-default graphical.target

    if sed -i "s|<user>|${set_username}|g" /etc/lxdm/lxdm.conf 2>/dev/null; then
      echo "done"
    else
      echo "Could not set 'lxdm' for user."
      return 1
    fi
}

dm_config


# Configure local-sudo file
sudo_config() {
    echo -e "\nConfiguring local-sudo ...\n"

    if sed -i "s|<user>|${set_username}|g" /etc/sudoers.d/local-sudo 2>/dev/null; then
      echo "done"
    else
      echo "Could not set 'local-sudo'"
      return 1
    fi
}

sudo_config


# Configure sysctl parameters
sysctl_config() {
    echo -e "\nSetting kernel parameters ...\n"

    kernel_params="/etc/sysctl.d/99-sysctl.conf"

    if [[ -e $kernel_params ]]; then
        sysctl -p "$kernel_params"
    else
        echo "Error: File '99-sysctl.conf' not found."
        return 1
    fi
}

sysctl_config


# Harden the filesystem table
fstab_config() {
    echo -e "\nConfiguring /etc/fstab ...\n"

    # Modify /etc/fstab using sed
    if [[ -f /etc/fstab ]]; then
        sed -i.bak \
        -e '/boot/ s=defaults=noatime=' \
        -e '/\/[[:space:]]/ s=defaults=noatime=' \
        -e '/home/ s=defaults=noatime,nodev,nosuid=' \
        -e '/var/ s=defaults=noatime,nodev,nosuid=' \
        -e 's/\S\+/0/5' \
        -e 's/\S\+/0/6' \
        /etc/fstab || echo "Error: Cannot read 'fstab' file."
    else
        echo "Error: '/etc/fstab' file not found."
        return 1
    fi

    # Append additional mount entries to /etc/fstab
    {
        echo "/tmp  /var/tmp  none  nodev,nosuid,noexec,bind  0 0"
        echo "tmpfs /tmp    tmpfs nodev,nosuid,noexec 0 0"
        echo "tmpfs /dev/shm  tmpfs nodev,nosuid,noexec 0 0"
        echo "proc  /proc   proc  nodev,nosuid,noexec     0 0"
    } >> /etc/fstab || echo "Error: Cannot read 'fstab' file."

    # Check if the configuration was successful
    if systemctl daemon-reload; then
        echo "done"
    else
        echo "Error: Problem setting 'fstab'"
        return 1
    fi
}

fstab_config


#================================================
#    SET-UP USER FILES
#================================================


# copy dotfiles to /home/*
copy_home() {
    echo -e "\nCopying dotfiles to /home ...\n"

    if [[ -d dotfiles ]]; then
      cp -r dotfiles/. /home/"${set_username}" || echo "Failed to copy files."
    else
      echo -e "\nDirectory 'dotfiles' not found."
    fi
}


# set owner and permissions
home_config() {
    echo -e "\nSetting /home permissions ...\n"

    chown -R "${set_username}":"${set_username}" /home/"${set_username}"
    chmod -R 750 /home/"${set_username}"
}


# load dconf settings
dconf_config() {
    echo -e "\nLoading dconf settings ...\n"

    if sudo -u "$set_username" dconf load / < dotfiles/.config/dconf/dconf-settings.ini; then
        echo "done"
    else
        echo "Could not load dconf settings."
        return 1
    fi
}


# Call user settings
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
        echo "Error: 'dnf-automatic' package is not installed"
        return 1
    fi

    # Enable and start the dnf-automatic.timer service
    if systemctl enable --now dnf-automatic.timer &>/dev/null; then
        echo "DNF security updates enabled successfully"
    else
        echo "Error: Failed to enable DNF security updates"
        return 1
    fi
}


nordvpn_config() {
    echo -e "\nConfiguring NordVPN ...\n"

    # Check if NordVPN package is installed
    if ! command -v "nordvpn" &>/dev/null; then
        echo "Error: 'nordvpn' package is not installed"
        return 1
    fi    

    # Add user to nordvpn group
    usermod -aG nordvpn "$set_username"
    
    # Enable and start nordvpnd service
    systemctl enable --now nordvpnd

    # Switch to user shell to execute commands as the user
    su - "$set_username" bash -c "
        nordvpn set technology nordlynx
        nordvpn set cybersec on
    "
}


firejail_config() {
    echo -e "\nConfiguring firejail ...\n"

    # Check if firejail package is installed
    if ! command -v "firejail" &>/dev/null; then
        echo "Error: 'firejail' package is not installed"
        return 1
    fi

    # Create firejail group if it doesn't exist
    if ! getent group firejail &>/dev/null; then
        groupadd firejail
    fi

    # Set permissions for firejail executable
    chown root:firejail /usr/bin/firejail
    chmod 4750 /usr/bin/firejail

    # Add user to firejail group
    usermod -aG firejail "$set_username"
    echo -e "User '$set_username' added to 'firejail' group\n"

    # Load firejail profiles
    firecfg
}


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


selinux_config() {
    echo -e "\nConfirm SELinux is 'Enforcing' ...\n"

    # Check SELinux status
    selinux_check=$(getenforce)
    sestatus

    if [[ $selinux_check != "Enforcing" ]]; then
        echo -e "\nConfiguring SELinux ...\n"
        
        # Update SELinux configuration
        echo -e "SELINUX=enforcing\nSELINUXTYPE=targeted" > /etc/selinux/config
        echo "done"
    else
        echo "SELinux OK!"
    fi
}


# Call security configs
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
echo -e "\nSetup complete! Any key to reboot..\n"
read -n 1 -rs


# Clean up installation files
rm -rf -- "$install_dir"/{main.zip,fedora-xfce-setup}


reboot
