#!/usr/bin/env bash


set -e


# check for root access
if [[ $(id -u) != 0 ]]; then
    echo "Please run setup as 'root'"
    exit 1
fi


# install additional packages
source packages


#================================================
#    SYSTEM CONFIGURATION
#================================================


clear


# set hostname if not already
if [[ $HOSTNAME = fedora ]]; then
  echo -e "\nChoose system hostname:"
  read HOST
  hostnamectl set-hostname "$HOST"
fi


# copy config files to /etc
echo -e "\nCopying config files ..."

if [[ -d configs ]]; then
  cp -ri configs/. /etc
else
  echo -e "\nDirectory not found."
fi


# update grub config
if [[ -d /sys/firmware/efi ]]; then
  grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
else
  grub2-mkconfig -o /boot/grub2/grub.cfg
fi


# configure /etc/hosts file
echo -e "\nConfiguring /etc/hosts ..."

echo -e "127.0.0.1\tlocalhost ""$HOST""" > /etc/hosts
if [[ $? -eq 0 ]]; then
  echo "done"
else
  echo "Could not set 'hosts'"
fi


# configure local-sudo file
echo -e "\nConfiguring local-sudo ..."

sed -i "s|<user>|${USERNAME}|g" /etc/sudoers.d/local-sudo
if [[ $? = 0 ]]; then
  echo "done"
else
  echo "Could not set 'local-sudo'"
fi


# configure lxdm
lxdmcheck=$(dnf list lxdm &> /dev/null)

if [[ $lxdmcheck -eq 0 ]]; then
  echo -e "\nConfiguring lxdm ..."
  mv /etc/systemd/system/default.target /etc/systemd/system/default.target.bak
  sed -i "s|<user>|${USERNAME}|g" /etc/lxdm/lxdm.conf
fi


# configure sysctl
echo -e "\nSetting kernel parameters ..."

sysctlconf="/etc/sysctl.d/99-sysctl.conf"
if [[ -e $sysctlconf ]]; then
  sysctl -p "$sysctlconf"
else
  echo "File '99-sysctl.conf' not found."
fi
   

# harden filesystem table
echo -e "\nConfiguring /etc/fstab ..."

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
echo -e "\nCopying dotfiles to /home ..."

if [[ -d dotfiles ]]; then
  cp -ri dotfiles/. /home/"${USERNAME}"
else
  echo -e "\nDirectory 'dotfiles' not found."
fi


# firefox preferences
echo -e "\nConfiguring Firefox browser ..."

profile="/home/"${USERNAME}"/.mozilla/firefox/*default-release/"
if [[ -d $profile ]]; then
  cp dotfiles/.mozilla/user.js "$profile"
fi


# load dconf settings
echo -e "\nLoading Gnome settings ..."

su - "$USERNAME" bash -c exit dconf load -f /org/ < dotfiles/.config/dconf/xfce-dconf
if [[ $? -eq 0 ]]; then
  echo "done"
else
  echo "Could not load settings."
fi


# set owner and permissions
echo -e "\nSetting /home permissions ..."

chown -R "${USERNAME}":"${USERNAME}" /home/"${USERNAME}"
chmod -R 750 /home/"${USERNAME}"


#================================================
#    SYSTEM SECURITY
#================================================


# automate security patches
echo -e "\nEnable DNF security updates ..."

dnfcheck=$(dnf list dnf-automatic &> /dev/null)
if [[ $dnfcheck -eq 0 ]]; then
  systemctl enable --now dnf-automatic.timer
else
  echo "Could not enable 'dnf-automatic'"
fi


# configure firejail
echo -e "\nConfiguring firejail ..."

fjcheck=$(dnf list firejail &> /dev/null)
if [[ $fjcheck -eq 0 ]]; then
  groupadd firejail
  chown root:firejail /usr/bin/firejail
  chmod 4750 /usr/bin/firejail
  usermod -aG firejail "$USERNAME"
  firecfg
else
  echo "Firejail not installed"
fi


# configure nordvpn
echo -e "\nConfiguring NordVPN ..."

nordcheck=$(dnf list nordvpn &> /dev/null)
if [[ $nordcheck -eq 0 ]]; then
  usermod -aG nordvpn "$USERNAME"
  systemctl enable --now nordvpnd
  su - "$USERNAME" bash -c exit
  nordvpn set technology nordlynx
  nordvpn set cybersec on
else
  echo "NordVPN not installed"
fi


# configure firewalld
echo -e "\nConfiguring Firewalld ..."

echo "Set default zone to 'DROP' ..."
firewall-cmd --set-default-zone=drop

echo -e "\nSet ICMP block inversion ..."
firewall-cmd --permanent --add-icmp-block-inversion

echo -e "\nReloading firewalld ..."
firewall-cmd --reload
echo
firewall-cmd --list-all


# confirm selinux is enforcing
echo -e "\nConfirm SELinux is 'Enforcing' ...\n"

selinux=$(getenforce)
sestatus
if [[ $selinux != Enforcing ]]; then
  echo "Configuring SELinux ..."
  echo -e "SELINUX=enforcing\nSELINUXTYPE=targeted" > /etc/selinux/config
  echo "done"
else
  echo "SELinux OK!"
fi


#================================================
#    SETUP COMPLETE
#================================================


# clean-up && reboot
good-bye {
  sudo -e "\nSetup complete! Any key to reboot.."
  read -n1 -rs

  rm -rf -- "$(pwd)"

  reboot
}
good-bye
