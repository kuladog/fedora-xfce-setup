#! /usr/bin/env bash

set -e


# check for root access
if [[ $(id -u) != 0 ]]; then
    echo -e "Please run setup as 'root\n'"
    exit 1
fi


# set current user name
set_username=$(logname)


# set hostname if not already
if [[ $hostname = fedora ]]; then
  echo -e "\nChoose system hostname:"
  read -r new_hostname
  hostnamectl set-hostname "$new_hostname"
fi


#================================================
#    SYSTEM CONFIGURATION
#================================================


# install additional packages
source "$(dirname "$0")"/packages


# copy config files to /etc
echo -e "\nCopying config files ...\n"

if [[ -d configs ]]; then
  cp -r configs/. /etc
else
  echo -e "\nDirectory 'configs' not found."
fi


# update grub config
if [[ -d /sys/firmware/efi ]]; then
  grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
else
  grub2-mkconfig -o /boot/grub2/grub.cfg
fi


# configure /etc/hosts file
echo -e "\nConfiguring /etc/hosts ...\n"

echo -e "127.0.0.1\tlocalhost "$new_hostname"" > /etc/hosts
if [[ $? -eq 0 ]]; then
  echo "done"
else
  echo "Could not set 'hosts'"
fi


# configure local-sudo file
echo -e "\nConfiguring local-sudo ...\n"

sed -i "s|<user>|${set_username}|g" /etc/sudoers.d/local-sudo
if [[ $? = -eq ]]; then
  echo "done"
else
  echo "Could not set 'local-sudo'"
fi


# configure lxdm
lxdmcheck=$(dnf list lxdm &> /dev/null)

if [[ $lxdmcheck -eq 0 ]]; then
  echo -e "\nConfiguring lxdm ..."
  mv /etc/systemd/system/default.target /etc/systemd/system/default.target.bak
  sed -i "s|<user>|${set_username}|g" /etc/lxdm/lxdm.conf
fi


# configure sysctl
echo -e "\nSetting kernel parameters ...\n"

sysctlconf="/etc/sysctl.d/99-sysctl.conf"
if [[ -e $sysctlconf ]]; then
  sysctl -p "$sysctlconf"
else
  echo "File '99-sysctl.conf' not found."
fi
   

# harden filesystem table
echo -e "\nConfiguring /etc/fstab ...\n"

sed -i.bak \
-e '/boot/ s=defaults=noatime=' \
-e '/\/[[:space:]]/ s=defaults=noatime=' \
-e '/home/ s=defaults=noatime,nodev,nosuid=' \
-e '/var/ s=defaults=noatime,nodev,nosuid=' \
-e 's/\S\+/0/5' \
-e 's/\S\+/0/6' \
/etc/fstab

{
echo "/tmp	/var/tmp	none	nodev,nosuid,noexec,bind  0 0"
echo "tmpfs	/tmp		tmpfs	nodev,nosuid,noexec	0 0"
echo "tmpfs	/dev/shm	tmpfs	nodev,nosuid,noexec	0 0"
echo "proc	/proc		proc	nodev,nosuid,noexec     0 0"
} >> /etc/fstab

if [[ $? -eq 0 ]]; then
  systemctl daemon-reload
  echo "done"
else
  echo "Problem setting 'fstab'"
fi


#================================================
#    DOTFILES SET-UP
#================================================


# copy dotfiles to /home/*
echo -e "\nCopying dotfiles to /home ...\n"

if [[ -d dotfiles ]]; then
  cp -r dotfiles/. /home/"${set_username}"
else
  echo -e "\nDirectory 'dotfiles' not found."
fi


# firefox preferences
echo -e "\nConfiguring Firefox browser ...\n"

profile="/home/"${set_username}"/.mozilla/firefox/*default-release/"
if [[ -d $profile ]]; then
  cp dotfiles/.mozilla/user.js "$profile"
fi


# load dconf settings
echo -e "\nLoading gsettings ...\n"

su - "$set_username" bash -c exit dconf load / < dotfiles/.config/dconf/dconf-settings.ini
if [[ $? -eq 0 ]]; then
  echo "done"
else
  echo "Could not load settings."
fi


# set owner and permissions
echo -e "\nSetting /home permissions ...\n"

chown -R "${set_username}":"${set_username}" /home/"${set_username}"
chmod -R 750 /home/"${set_username}"


#================================================
#    SYSTEM SECURITY
#================================================


# automate security patches
echo -e "\nEnable DNF security updates ...\n"

dnfcheck=$(dnf list dnf-automatic &> /dev/null)
if [[ $dnfcheck -eq 0 ]]; then
  systemctl enable --now dnf-automatic.timer
else
  echo "Could not enable 'dnf-automatic'"
fi


# configure firejail
echo -e "\nConfiguring firejail ...\n"

fjcheck=$(dnf list firejail &> /dev/null)
if [[ $fjcheck -eq 0 ]]; then
  groupadd firejail
  chown root:firejail /usr/bin/firejail
  chmod 4750 /usr/bin/firejail
  usermod -aG firejail "$set_username"
  firecfg
else
  echo "Firejail not installed"
fi


# configure nordvpn
echo -e "\nConfiguring NordVPN ...\n"

nordcheck=$(dnf list nordvpn &> /dev/null)
if [[ $nordcheck -eq 0 ]]; then
  usermod -aG nordvpn "$set_username"
  systemctl enable --now nordvpnd
  su - "$set_username" bash -c exit
  nordvpn set technology nordlynx
  nordvpn set cybersec on
else
  echo "NordVPN not installed"
fi


# configure firewalld
echo -e "\nConfiguring Firewalld ...\n"

firewall-cmd --set-default-zone=drop
firewall-cmd --permanent --add-icmp-block-inversion
firewall-cmd --reload
echo
firewall-cmd --list-all


# confirm selinux is enforcing
echo -e "\nConfirm SELinux is 'Enforcing' ...\n"

selinux=$(getenforce)
sestatus
if [[ $selinux != Enforcing ]]; then
  echo "Configuring SELinux ...\n"
  echo -e "SELINUX=enforcing\nSELINUXTYPE=targeted" > /etc/selinux/config
  echo "done"
else
  echo "SELinux OK!"
fi


#================================================
#    SETUP COMPLETE
#================================================


# clean-up && reboot
 echo -e "\nSetup complete! Any key to reboot..\n"
read -n 1 -rs
 
 rm -rf -- "$(pwd)"

 reboot

