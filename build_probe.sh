#!/bin/bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Helper functions
print_task() {
    echo -e "\n${CYAN}${BOLD}[TASK]${NC} ${BOLD}$1${NC}"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${BLUE}→${NC} $1"
}

print_choice() {
    echo -e "  ${MAGENTA}$1)${NC} $2"
}

spinner() {
    local pid=$1
    local msg=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    echo -n "  "
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %10 ))
        printf "\r  ${CYAN}${spin:$i:1}${NC} $msg"
        sleep 0.1
    done
    printf "\r"
}

# Check privileges first
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}${BOLD}✗ Error:${NC} This script must be run with ${BOLD}sudo${NC} privileges\n"
    echo -e "${BLUE}→${NC} Please run: ${CYAN}sudo $0${NC}\n"
    exit 1
fi

# ASCII Art
clear
echo -e "${CYAN}${BOLD}"
cat << "EOF"
 ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
 ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
 ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
 ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
 ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
 ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
                                           
  Fuzzer Environment Setup Script          
EOF
echo -e "${NC}"

print_task "Checking Privileges"
print_success "Running with root privileges"

print_task "Select Setup Mode"
echo ""
print_choice "1" "Full setup (all components)"
print_choice "2" "Setup folder only (config files only)"
print_choice "3" "Exit"
echo ""

while true; do
    read -p "  Select mode [1-3]: " setup_mode
    if [[ $setup_mode =~ ^[1-3]$ ]]; then
        case $setup_mode in
            1)
                SETUP_MODE="full"
                print_success "Full setup mode selected"
                ;;
            2)
                SETUP_MODE="setup_only"
                print_success "Setup folder only mode selected"
                ;;
            3)
                print_warning "Setup cancelled by user"
                exit 0
                ;;
        esac
        break
    else
        print_error "Invalid input. Please select 1-3"
    fi
done

# Skip to setup folder generation if setup_only mode
if [ "$SETUP_MODE" = "setup_only" ]; then
    AUTO_INSTALL="no"
else
    print_task "All installing new ones?"
    echo ""
    print_info "If you select 'y', all components will be installed fresh without prompts."
    print_info "If you select 'n', you will be prompted to choose existing resources."
    echo ""
    read -p "  Install all new? (y/n): " -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        AUTO_INSTALL="yes"
        print_success "Auto-install mode: All components will be built fresh"
    else
        AUTO_INSTALL="no"
        print_success "Interactive mode: You will choose existing resources"
    fi
fi

# Base Directory - Script location
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$SCRIPT_DIR"
cd "$BASE_DIR"

# Log Directory
LOG_DIR="$BASE_DIR/build_probe_log"
mkdir -p "$LOG_DIR"

print_task "Base Directory"
print_success "Using: ${CYAN}$BASE_DIR${NC}"
print_info "Logs: ${CYAN}$LOG_DIR${NC}"

# Skip to setup generation if setup_only mode
if [ "$SETUP_MODE" = "setup_only" ]; then
    print_info "Skipping to setup folder generation..."
fi

# Install Dependencies
if [ "$SETUP_MODE" != "setup_only" ]; then
print_task "Install Required Packages"
print_info "Updating package list..."
apt update > /dev/null 2>&1 &
spinner $! "Updating package database..."
print_success "Package list updated"

print_info "Installing dependencies (this may take a few minutes)..."
DEBIAN_FRONTEND=noninteractive apt install -y -qq \
    build-essential libncurses-dev bison flex libssl-dev libelf-dev \
    dwarves libdw-dev libdwarf-dev zlib1g-dev libiberty-dev bc \
    fakeroot cpio kmod rsync curl wget tar ssh ca-certificates \
    clang llvm lld gawk make gcc git vim python3 python3-pip \
    debootstrap qemu-system-x86 qemu-utils qemu-kvm \
    libnl-3-dev libnl-genl-3-dev linux-headers-$(uname -r) > /dev/null 2>&1 &
spinner $! "Installing packages..."

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    print_success "All dependencies installed"
else
    print_error "Failed to install some dependencies"
    exit 1
fi
fi  # End of SETUP_MODE != setup_only


# Kernel Selection
if [ "$SETUP_MODE" != "setup_only" ]; then
print_task "Select Linux Kernel"

# Search recursively for linux-* directories
LINUX_DIRS=($(find "$BASE_DIR" -type d -name "linux-*" 2>/dev/null | sort))

if [ ${#LINUX_DIRS[@]} -eq 0 ]; then
    print_error "No Linux kernel directories found in $BASE_DIR"
    print_info "Looking for directories matching 'linux-*'"
    exit 1
fi

echo ""
print_info "Found ${#LINUX_DIRS[@]} kernel(s):"
for i in "${!LINUX_DIRS[@]}"; do
    # Show relative path from BASE_DIR
    rel_path="${LINUX_DIRS[$i]#$BASE_DIR/}"
    print_choice "$(($i+1))" "$rel_path"
done
print_choice "$(( ${#LINUX_DIRS[@]} + 1 ))" "${YELLOW}Skip this step${NC}"
echo ""

while true; do
    read -p "  Select kernel number [1-$(( ${#LINUX_DIRS[@]} + 1 ))]: " kernel_choice
    if [[ $kernel_choice =~ ^[0-9]+$ ]] && [ "$kernel_choice" -ge 1 ] && [ "$kernel_choice" -le $(( ${#LINUX_DIRS[@]} + 1 )) ]; then
        if [ "$kernel_choice" -le ${#LINUX_DIRS[@]} ]; then
            KERNEL_DIR="${LINUX_DIRS[$(($kernel_choice-1))]}"
            KERNEL_VERSION="${KERNEL_DIR##*/}"
            print_success "Selected: ${KERNEL_DIR#$BASE_DIR/}"
        else
            print_warning "Skipped kernel selection"
            KERNEL_DIR=""
            KERNEL_VERSION=""
        fi
        break
    else
        print_error "Invalid input. Please select 1-$(( ${#LINUX_DIRS[@]} + 1 ))"
    fi
done


# QEMU Image Selection
print_task "Select or Build QEMU Image"

if [ "$AUTO_INSTALL" = "yes" ]; then
    BUILD_IMAGE=true
    print_info "Auto-install mode: Will build new image"
else
    # Find existing image files (search system-wide)
    print_info "Searching for existing QEMU images..."
    IMAGE_FILES=($(find / -type f -name "*.img" -path "*/image/*" 2>/dev/null | grep -v -E "/(proc|sys|dev|run)" | sort))

    echo ""
    if [ ${#IMAGE_FILES[@]} -gt 0 ]; then
        print_info "Found ${#IMAGE_FILES[@]} existing image(s):"
        for i in "${!IMAGE_FILES[@]}"; do
            img_path="${IMAGE_FILES[$i]}"
            img_size=$(du -h "$img_path" | cut -f1)
            print_choice "$(($i+1))" "$img_path (${img_size})"
        done
        print_choice "$(( ${#IMAGE_FILES[@]} + 1 ))" "Build new image"
        print_choice "$(( ${#IMAGE_FILES[@]} + 2 ))" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-$(( ${#IMAGE_FILES[@]} + 2 ))]: " img_choice
            if [[ $img_choice =~ ^[0-9]+$ ]] && [ "$img_choice" -ge 1 ] && [ "$img_choice" -le $(( ${#IMAGE_FILES[@]} + 2 )) ]; then
                if [ "$img_choice" -le ${#IMAGE_FILES[@]} ]; then
                    IMAGE_FILE="${IMAGE_FILES[$(($img_choice-1))]}"
                    IMAGE_DIR="$(dirname "$IMAGE_FILE")"
                    print_success "Using existing image: $IMAGE_FILE"
                    BUILD_IMAGE=false
                    break
                elif [ "$img_choice" -eq $(( ${#IMAGE_FILES[@]} + 1 )) ]; then
                    BUILD_IMAGE=true
                    print_success "Will build new image"
                    break
                else
                    BUILD_IMAGE=false
                    print_warning "Skipped QEMU image step"
                    break
                fi
            else
                print_error "Invalid input"
            fi
        done
    else
        print_info "No existing images found"
        echo ""
        print_choice "1" "Build new image"
        print_choice "2" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-2]: " img_choice
            if [[ $img_choice =~ ^[1-2]$ ]]; then
                if [ "$img_choice" -eq 1 ]; then
                    BUILD_IMAGE=true
                    print_success "Will build new image"
                else
                    BUILD_IMAGE=false
                    print_warning "Skipped QEMU image step"
                fi
                break
            else
                print_error "Invalid input. Please select 1-2"
            fi
        done
    fi
fi

if [ "$BUILD_IMAGE" = true ]; then
    IMAGE_DIR="$BASE_DIR/image"
    mkdir -p "$IMAGE_DIR"
    cd "$IMAGE_DIR"
    
    print_success "Image directory: $IMAGE_DIR"
    print_info "Downloading create-image.sh from syzkaller repository..."
    wget -q https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh 2>/dev/null &
    spinner $! "Downloading script..."
    
    if [ $? -eq 0 ]; then
        chmod +x create-image.sh
        print_success "create-image.sh downloaded"
    else
        print_error "Failed to download create-image.sh"
        exit 1
    fi
    
    print_info "Building QEMU image (this may take 10-15 minutes)..."
    ./create-image.sh > "$LOG_DIR/create-image.log" 2>&1 &
    spinner $! "Building image (logs: $LOG_DIR/create-image.log)..."
    
    if [ $? -eq 0 ]; then
        print_success "QEMU image created successfully"
        IMAGE_FILE=$(find "$IMAGE_DIR" -maxdepth 1 -name "*.img" 2>/dev/null | head -1)
    else
        print_error "Image creation failed. Check $LOG_DIR/create-image.log"
        exit 1
    fi
    cd "$BASE_DIR"
fi

# Find SSH key
SSHKEY_FILE=$(find "$IMAGE_DIR" -maxdepth 1 -name "*.id_rsa" -o -name "*_rsa" 2>/dev/null | head -1)
if [ -z "$SSHKEY_FILE" ]; then
    print_warning "No SSH key found in $IMAGE_DIR"
    SSHKEY_FILE="$IMAGE_DIR/bullseye.id_rsa"
else
    print_success "SSH key: ${SSHKEY_FILE##*/}"
fi


# Go Installation
print_task "Install Go (if needed)"

if [ "$AUTO_INSTALL" = "yes" ]; then
    INSTALL_GO=true
    print_info "Auto-install mode: Will install new Go"
else
    # Check existing Go installations (search system-wide)
    print_info "Searching for existing Go installations..."
    GO_DIRS=($(find / -maxdepth 4 -type d \( -name "go" -o -name "goroot" \) 2>/dev/null | grep -v -E "/(proc|sys|dev|run)" | sort))

    if [ ${#GO_DIRS[@]} -gt 0 ]; then
        echo ""
        print_info "Found ${#GO_DIRS[@]} existing Go installation(s):"
        for i in "${!GO_DIRS[@]}"; do
            go_path="${GO_DIRS[$i]}"
            if [ -f "$go_path/bin/go" ]; then
                go_ver=$("$go_path/bin/go" version 2>/dev/null | awk '{print $3}')
                print_choice "$(($i+1))" "$go_path ($go_ver)"
            else
                print_choice "$(($i+1))" "$go_path"
            fi
        done
        print_choice "$(( ${#GO_DIRS[@]} + 1 ))" "Download and install new Go"
        print_choice "$(( ${#GO_DIRS[@]} + 2 ))" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-$(( ${#GO_DIRS[@]} + 2 ))]: " go_choice
            if [[ $go_choice =~ ^[0-9]+$ ]] && [ "$go_choice" -ge 1 ] && [ "$go_choice" -le $(( ${#GO_DIRS[@]} + 2 )) ]; then
                if [ "$go_choice" -le ${#GO_DIRS[@]} ]; then
                    GOROOT="${GO_DIRS[$(($go_choice-1))]}"
                    print_success "Using existing Go: $GOROOT"
                    INSTALL_GO=false
                    break
                elif [ "$go_choice" -eq $(( ${#GO_DIRS[@]} + 1 )) ]; then
                    INSTALL_GO=true
                    print_success "Will install new Go"
                    break
                else
                    INSTALL_GO=false
                    print_warning "Skipped Go installation"
                    break
                fi
            else
                print_error "Invalid input"
            fi
        done
    else
        print_info "No existing Go installation found"
        echo ""
        print_choice "1" "Download and install new Go"
        print_choice "2" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-2]: " go_choice
            if [[ $go_choice =~ ^[1-2]$ ]]; then
                if [ "$go_choice" -eq 1 ]; then
                    INSTALL_GO=true
                    print_success "Will install new Go"
                else
                    INSTALL_GO=false
                    print_warning "Skipped Go installation"
                fi
                break
            else
                print_error "Invalid input. Please select 1-2"
            fi
        done
    fi
fi

if [ "$INSTALL_GO" = true ]; then
    cd "$BASE_DIR"
    print_info "Downloading Go 1.23.6..."
    wget -q https://dl.google.com/go/go1.23.6.linux-amd64.tar.gz 2>/dev/null &
    spinner $! "Downloading Go..."
    
    if [ $? -eq 0 ]; then
        print_success "Go archive downloaded"
    else
        print_error "Failed to download Go"
        exit 1
    fi
    
    print_info "Extracting Go..."
    tar -xf go1.23.6.linux-amd64.tar.gz &
    spinner $! "Extracting..."
    
    if [ $? -eq 0 ]; then
        print_success "Go extracted"
        mv go goroot
        GOROOT="$BASE_DIR/goroot"
    else
        print_error "Failed to extract Go"
        exit 1
    fi
fi

mkdir -p "$BASE_DIR/gopath"
export GOPATH="$BASE_DIR/gopath"
export GOROOT="$GOROOT"
export PATH="$GOPATH/bin:$GOROOT/bin:$PATH"

print_success "Go environment configured"
print_info "GOROOT: ${CYAN}$GOROOT${NC}"
print_info "GOPATH: ${CYAN}$GOPATH${NC}"


# Syzkaller Build
print_task "Install or Build Syzkaller"

if [ "$AUTO_INSTALL" = "yes" ]; then
    BUILD_SYZ=true
    CLONE_SYZ=true
    print_info "Auto-install mode: Will clone new syzkaller"
else
    # Check existing syzkaller installations (search system-wide)
    print_info "Searching for existing Syzkaller installations..."
    SYZ_DIRS=($(find / -maxdepth 4 -type d -name "syzkaller*" 2>/dev/null | grep -v -E "/(proc|sys|dev|run)" | sort))

    if [ ${#SYZ_DIRS[@]} -gt 0 ]; then
        echo ""
        print_info "Found ${#SYZ_DIRS[@]} existing syzkaller installation(s):"
        for i in "${!SYZ_DIRS[@]}"; do
            syz_path="${SYZ_DIRS[$i]}"
            if [ -f "$syz_path/bin/syz-manager" ]; then
                print_choice "$(($i+1))" "$syz_path (built)"
            else
                print_choice "$(($i+1))" "$syz_path (not built)"
            fi
        done
        print_choice "$(( ${#SYZ_DIRS[@]} + 1 ))" "Clone new syzkaller"
        print_choice "$(( ${#SYZ_DIRS[@]} + 2 ))" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-$(( ${#SYZ_DIRS[@]} + 2 ))]: " syz_choice
            if [[ $syz_choice =~ ^[0-9]+$ ]] && [ "$syz_choice" -ge 1 ] && [ "$syz_choice" -le $(( ${#SYZ_DIRS[@]} + 2 )) ]; then
                if [ "$syz_choice" -le ${#SYZ_DIRS[@]} ]; then
                    PROBE_DIR="${SYZ_DIRS[$(($syz_choice-1))]}"
                    if [ ! -f "$PROBE_DIR/bin/syz-manager" ]; then
                        print_warning "syz-manager not found, will rebuild"
                        BUILD_SYZ=true
                    else
                        print_success "Using existing syzkaller: $PROBE_DIR"
                        BUILD_SYZ=false
                    fi
                    break
                elif [ "$syz_choice" -eq $(( ${#SYZ_DIRS[@]} + 1 )) ]; then
                    BUILD_SYZ=true
                    CLONE_SYZ=true
                    print_success "Will clone new syzkaller"
                    break
                else
                    BUILD_SYZ=false
                    CLONE_SYZ=false
                    print_warning "Skipped Syzkaller installation"
                    break
                fi
            else
                print_error "Invalid input"
            fi
        done
    else
        print_info "No existing syzkaller found"
        echo ""
        print_choice "1" "Clone new syzkaller"
        print_choice "2" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-2]: " syz_choice
            if [[ $syz_choice =~ ^[1-2]$ ]]; then
                if [ "$syz_choice" -eq 1 ]; then
                    BUILD_SYZ=true
                    CLONE_SYZ=true
                    print_success "Will clone new syzkaller"
                else
                    BUILD_SYZ=false
                    CLONE_SYZ=false
                    print_warning "Skipped Syzkaller installation"
                fi
                break
            else
                print_error "Invalid input. Please select 1-2"
            fi
        done
    fi
fi

if [ "$CLONE_SYZ" = true ]; then
    cd "$BASE_DIR"
    print_info "Cloning syzkaller from GitHub..."
    git clone https://github.com/google/syzkaller > /dev/null 2>&1 &
    spinner $! "Cloning repository..."
    
    if [ $? -eq 0 ]; then
        print_success "Syzkaller cloned"
        PROBE_DIR="$BASE_DIR/syzkaller"
    else
        print_error "Failed to clone syzkaller"
        exit 1
    fi
fi

# Syzkaller Build (separate step)
if [ -n "$PROBE_DIR" ] && [ -d "$PROBE_DIR" ]; then
    print_task "Build Syzkaller"

    if [ -f "$PROBE_DIR/bin/syz-manager" ]; then
        print_info "syz-manager already exists in $PROBE_DIR/bin/"
        echo ""
        print_choice "1" "Use existing build"
        print_choice "2" "Rebuild syzkaller"
        print_choice "3" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-3]: " build_choice
            if [[ $build_choice =~ ^[1-3]$ ]]; then
                case $build_choice in
                    1)
                        print_success "Using existing syzkaller build"
                        BUILD_SYZ=false
                        ;;
                    2)
                        BUILD_SYZ=true
                        print_success "Will rebuild syzkaller"
                        ;;
                    3)
                        BUILD_SYZ=false
                        print_warning "Skipped Syzkaller build"
                        ;;
                esac
                break
            else
                print_error "Invalid input. Please select 1-3"
            fi
        done
    else
        echo ""
        print_choice "1" "Build syzkaller"
        print_choice "2" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-2]: " build_choice
            if [[ $build_choice =~ ^[1-2]$ ]]; then
                if [ "$build_choice" -eq 1 ]; then
                    BUILD_SYZ=true
                    print_success "Will build syzkaller"
                else
                    BUILD_SYZ=false
                    print_warning "Skipped Syzkaller build"
                fi
                break
            else
                print_error "Invalid input. Please select 1-2"
            fi
        done
    fi

    if [ "$BUILD_SYZ" = true ]; then
        cd "$PROBE_DIR"
        print_info "Building syzkaller (this may take several minutes)..."
        make > "$LOG_DIR/syzkaller-build.log" 2>&1 &
        spinner $! "Building (logs: $LOG_DIR/syzkaller-build.log)..."

        if [ $? -eq 0 ]; then
            print_success "Syzkaller built successfully"
        else
            print_error "Syzkaller build failed. Check $LOG_DIR/syzkaller-build.log"
            exit 1
        fi
    fi
fi

cd "$BASE_DIR"


# BusyBox and RootFS
print_task "Build or Use Existing RootFS"

if [ "$AUTO_INSTALL" = "yes" ]; then
    BUILD_ROOTFS=true
    print_info "Auto-install mode: Will build new rootfs with BusyBox"
else
    # Check existing rootfs (search system-wide)
    print_info "Searching for existing RootFS files..."
    ROOTFS_FILES=($(find / -maxdepth 5 -type f -name "rootfs.cpio" 2>/dev/null | grep -v -E "/(proc|sys|dev|run)" | sort))

    if [ ${#ROOTFS_FILES[@]} -gt 0 ]; then
        echo ""
        print_info "Found ${#ROOTFS_FILES[@]} existing rootfs file(s):"
        for i in "${!ROOTFS_FILES[@]}"; do
            rootfs_path="${ROOTFS_FILES[$i]}"
            rootfs_size=$(du -h "$rootfs_path" | cut -f1)
            print_choice "$(($i+1))" "$rootfs_path (${rootfs_size})"
        done
        print_choice "$(( ${#ROOTFS_FILES[@]} + 1 ))" "Build new rootfs with BusyBox"
        print_choice "$(( ${#ROOTFS_FILES[@]} + 2 ))" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-$(( ${#ROOTFS_FILES[@]} + 2 ))]: " rootfs_choice
            if [[ $rootfs_choice =~ ^[0-9]+$ ]] && [ "$rootfs_choice" -ge 1 ] && [ "$rootfs_choice" -le $(( ${#ROOTFS_FILES[@]} + 2 )) ]; then
                if [ "$rootfs_choice" -le ${#ROOTFS_FILES[@]} ]; then
                    ROOTFS_PATH="${ROOTFS_FILES[$(($rootfs_choice-1))]}"
                    print_success "Using existing rootfs: $ROOTFS_PATH"
                    BUILD_ROOTFS=false
                    break
                elif [ "$rootfs_choice" -eq $(( ${#ROOTFS_FILES[@]} + 1 )) ]; then
                    BUILD_ROOTFS=true
                    print_success "Will build new rootfs"
                    break
                else
                    BUILD_ROOTFS=false
                    print_warning "Skipped RootFS step"
                    break
                fi
            else
                print_error "Invalid input"
            fi
        done
    else
        print_info "No existing rootfs found"
        echo ""
        print_choice "1" "Build new rootfs with BusyBox"
        print_choice "2" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-2]: " rootfs_choice
            if [[ $rootfs_choice =~ ^[1-2]$ ]]; then
                if [ "$rootfs_choice" -eq 1 ]; then
                    BUILD_ROOTFS=true
                    print_success "Will build new rootfs"
                else
                    BUILD_ROOTFS=false
                    print_warning "Skipped RootFS step"
                fi
                break
            else
                print_error "Invalid input. Please select 1-2"
            fi
        done
    fi
fi

if [ "$BUILD_ROOTFS" = true ]; then
    print_task "Download and Build BusyBox"
    
    cd "$BASE_DIR"
    BUSYBOX_URL="https://busybox.net/downloads/busybox-1.37.0.tar.bz2"
    BUSYBOX_FILE="busybox-1.37.0.tar.bz2"
    
    for attempt in 1 2 3; do
        print_info "Downloading BusyBox (attempt $attempt/3)..."
        wget --no-check-certificate -q "$BUSYBOX_URL" -O "$BUSYBOX_FILE" 2>/dev/null &
        spinner $! "Downloading..."
        wait $!
        
        if [ $? -eq 0 ]; then
            print_success "BusyBox downloaded successfully"
            break
        else
            if [ $attempt -lt 3 ]; then
                print_warning "Download failed, retrying..."
                sleep 2
            else
                print_error "Failed to download BusyBox after 3 attempts"
                exit 1
            fi
        fi
    done
    
    print_info "Extracting BusyBox..."
    tar -xf "$BUSYBOX_FILE" &
    spinner $! "Extracting..."
    
    if [ $? -eq 0 ]; then
        print_success "BusyBox extracted"
    else
        print_error "Failed to extract BusyBox"
        exit 1
    fi
    
    cd busybox-1.37.0
    
    print_info "Configuring BusyBox..."
    make defconfig > /dev/null 2>&1 &
    spinner $! "Creating configuration..."
    
    sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
    sed -i 's/CONFIG_INETD=y/# CONFIG_INETD is not set/' .config
    sed -i 's/CONFIG_TC=y/# CONFIG_TC is not set/' .config
    
    print_success "BusyBox configured (static binary)"
    
    print_info "Building BusyBox (this may take a while)..."
    make CONFIG_PREFIX=../result install -j$(nproc) > /dev/null 2>&1 &
    spinner $! "Building with $(nproc) cores..."
    
    if [ $? -eq 0 ]; then
        print_success "BusyBox built and installed"
    else
        print_error "BusyBox build failed"
        exit 1
    fi
    
    print_task "Create RootFS Structure"
    
    cd ../result/
    mkdir -p var dev etc lib proc tmp sys
    
    cat << 'EOF' > ./init
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev

exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo "7 4 1 7" > /proc/sys/kernel/printk

cp /proc/kallsyms \"$LOG_DIR/kallsyms\"

setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0 -f
EOF
    
    chmod 755 ./init
    print_success "init script created"
    
    print_info "Creating CPIO archive..."
    find . | cpio -o --format=newc > ../rootfs.cpio 2>/dev/null &
    spinner $! "Creating archive..."
    
    if [ $? -eq 0 ]; then
        print_success "rootfs.cpio created"
    else
        print_error "Failed to create CPIO archive"
        exit 1
    fi
    
    cd ../
    mkdir -p rootfs
    mv ./rootfs.cpio ./rootfs/
    cd ./rootfs
    
    print_info "Extracting and repacking rootfs..."
    cpio -id < rootfs.cpio > /dev/null 2>&1 &
    spinner $! "Extracting..."
    
    find . | cpio -o --format=newc > ../rootfs.cpio 2>/dev/null &
    spinner $! "Repacking..."
    
    if [ $? -eq 0 ]; then
        print_success "Final rootfs.cpio created"
        ROOTFS_PATH="$BASE_DIR/rootfs.cpio"
    else
        print_error "Failed to create final CPIO archive"
        exit 1
    fi
    
    cd "$BASE_DIR"
fi


# Build Validation
print_task "Validate Components"

echo ""
print_choice "1" "Validate all components"
print_choice "2" "${YELLOW}Skip validation${NC}"
echo ""

while true; do
    read -p "  Select option [1-2]: " validate_choice
    if [[ $validate_choice =~ ^[1-2]$ ]]; then
        if [ "$validate_choice" -eq 1 ]; then
            DO_VALIDATE=true
        else
            DO_VALIDATE=false
            print_warning "Skipped validation"
        fi
        break
    else
        print_error "Invalid input. Please select 1-2"
    fi
done

if [ "$DO_VALIDATE" = true ]; then
    # Kernel validation (skip if not selected)
    if [ -n "$KERNEL_VERSION" ]; then
        BZIMAGE_PATH="$BASE_DIR/$KERNEL_VERSION/arch/x86/boot/bzImage"
        if [ ! -f "$BZIMAGE_PATH" ]; then
            print_warning "Kernel not built: $BZIMAGE_PATH"
        else
            print_success "Kernel image: $BZIMAGE_PATH"
        fi
    else
        print_warning "Kernel: skipped"
        BZIMAGE_PATH=""
    fi

    # Syzkaller validation (skip if not selected)
    if [ -n "$PROBE_DIR" ] && [ -d "$PROBE_DIR" ]; then
        if [ ! -f "$PROBE_DIR/bin/syz-manager" ]; then
            print_warning "syz-manager not found in $PROBE_DIR/bin/"
        else
            print_success "syz-manager: $PROBE_DIR/bin/syz-manager"
        fi
    else
        print_warning "Syzkaller: skipped"
    fi

    # Image validation (skip if not selected)
    if [ -n "$IMAGE_FILE" ] && [ -f "$IMAGE_FILE" ]; then
        print_success "Image file: ${IMAGE_FILE}"
    else
        print_warning "Image: skipped or not found"
    fi

    # SSH key validation
    if [ -n "$SSHKEY_FILE" ] && [ -f "$SSHKEY_FILE" ]; then
        print_success "SSH key: ${SSHKEY_FILE}"
    else
        print_warning "SSH key: not found (will use default path)"
        SSHKEY_FILE="${IMAGE_DIR:-$BASE_DIR/image}/bullseye.id_rsa"
    fi
fi
fi  # End of SETUP_MODE != setup_only (components section)

# Fuzzing Configuration (always show for setup_only mode too)
print_task "Configure Fuzzing Parameters"

CPU_CORES=$(nproc 2>/dev/null || lscpu | grep "^CPU(s):" | head -1 | awk '{print $2}')
TOTAL_MEM_MB=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')

# Fallback if /proc/meminfo fails
if [ -z "$TOTAL_MEM_MB" ] || [ "$TOTAL_MEM_MB" -eq 0 ]; then
    TOTAL_MEM_MB=$(free -m | awk 'NR==2{print $2}')
fi

# If still empty, use a safe default
if [ -z "$TOTAL_MEM_MB" ] || [ "$TOTAL_MEM_MB" -eq 0 ]; then
    TOTAL_MEM_MB=16384
    print_warning "Could not detect system memory, using default: 16GB"
fi

echo ""
print_info "Available CPU cores: ${CYAN}${CPU_CORES}${NC}"
TOTAL_MEM_GB=$(echo "scale=1; $TOTAL_MEM_MB / 1024" | bc)
print_info "Available Memory: ${CYAN}${TOTAL_MEM_MB} MB${NC} (${CYAN}${TOTAL_MEM_GB} GB${NC})"
echo ""
print_choice "1" "Aggressive (90% CPU, 90% RAM)"
print_choice "2" "Balanced  (80% CPU, 80% RAM)"
print_choice "3" "Stable    (60% CPU, 60% RAM)"
print_choice "4" "${YELLOW}Skip this step${NC}"
echo ""

while true; do
    read -p "  Select level [1-4]: " fuzz_level
    if [[ $fuzz_level =~ ^[1-4]$ ]]; then
        if [ "$fuzz_level" -eq 4 ]; then
            print_warning "Skipped fuzzing configuration"
            SKIP_FUZZ_CONFIG=true
        else
            SKIP_FUZZ_CONFIG=false
        fi
        break
    else
        print_error "Invalid input. Please select 1-4"
    fi
done

TOTAL_CORES=$CPU_CORES

if [ "$SKIP_FUZZ_CONFIG" = true ]; then
    # Use default balanced settings when skipped
    PROCS=4
    VM_COUNT=2
    VM_CPU=2
    VM_MEM=2048
    LEVEL_NAME="Default (Skipped)"
else
    case $fuzz_level in
        1)
            PROCS=$(( (TOTAL_CORES * 9 / 10) > 2 ? (TOTAL_CORES * 9 / 10) : 2 ))
            VM_COUNT=$(( (PROCS / 2) > 1 ? (PROCS / 2) : 1 ))
            VM_CPU=$(( (TOTAL_CORES / VM_COUNT) > 1 ? (TOTAL_CORES / VM_COUNT) : 2 ))
            TOTAL_VM_MEM=$(( TOTAL_MEM_MB * 9 / 10 ))
            VM_MEM=$(( TOTAL_VM_MEM / VM_COUNT ))
            LEVEL_NAME="Aggressive"
            ;;
        2)
            PROCS=$(( (TOTAL_CORES * 8 / 10) > 2 ? (TOTAL_CORES * 8 / 10) : 2 ))
            VM_COUNT=$(( (PROCS / 3) > 1 ? (PROCS / 3) : 2 ))
            VM_CPU=$(( (TOTAL_CORES / VM_COUNT) > 1 ? (TOTAL_CORES / VM_COUNT) : 2 ))
            TOTAL_VM_MEM=$(( TOTAL_MEM_MB * 8 / 10 ))
            VM_MEM=$(( TOTAL_VM_MEM / VM_COUNT ))
            LEVEL_NAME="Balanced"
            ;;
        3)
            PROCS=$(( (TOTAL_CORES * 6 / 10) > 2 ? (TOTAL_CORES * 6 / 10) : 2 ))
            VM_COUNT=$(( (PROCS / 4) > 1 ? (PROCS / 4) : 1 ))
            VM_CPU=$(( (TOTAL_CORES / VM_COUNT) > 1 ? (TOTAL_CORES / VM_COUNT) : 2 ))
            TOTAL_VM_MEM=$(( TOTAL_MEM_MB * 6 / 10 ))
            VM_MEM=$(( TOTAL_VM_MEM / VM_COUNT ))
            LEVEL_NAME="Stable"
            ;;
    esac
fi

PROCS=$(( PROCS > 2 ? PROCS : 2 ))
VM_COUNT=$(( VM_COUNT > 1 ? VM_COUNT : 1 ))
VM_CPU=$(( VM_CPU > 1 ? VM_CPU : 1 ))
VM_MEM=$(( VM_MEM > 1024 ? VM_MEM : 1024 ))

echo ""
print_success "Configuration: ${CYAN}${LEVEL_NAME}${NC}"
print_info "Processes: ${CYAN}${PROCS}${NC}"
print_info "VM Count: ${CYAN}${VM_COUNT}${NC}"
print_info "CPU per VM: ${CYAN}${VM_CPU} cores${NC}"
VM_MEM_GB=$(echo "scale=2; $VM_MEM / 1024" | bc)
TOTAL_VM_MEM_GB=$(echo "scale=2; $VM_MEM * $VM_COUNT / 1024" | bc)
print_info "Memory per VM: ${CYAN}${VM_MEM} MB${NC} (${CYAN}${VM_MEM_GB} GB${NC}) - Total: ${CYAN}$(( VM_MEM * VM_COUNT )) MB${NC} (${CYAN}${TOTAL_VM_MEM_GB} GB${NC})"

# Final Review (only for full setup mode)
if [ "$SETUP_MODE" != "setup_only" ]; then
    print_task "Review Configuration"
    echo ""
    print_info "Base Directory: ${CYAN}$BASE_DIR${NC}"
    print_info "Kernel: ${CYAN}$KERNEL_VERSION${NC}"
    print_info "Probe Directory: ${CYAN}$PROBE_DIR${NC}"
    print_info "Image: ${CYAN}$IMAGE_FILE${NC}"
    print_info "RootFS: ${CYAN}$ROOTFS_PATH${NC}"
    echo ""
    print_info "Fuzzing Level: ${CYAN}$LEVEL_NAME${NC}"
    print_info "Processes: ${CYAN}$PROCS${NC}"
    print_info "VMs: ${CYAN}$VM_COUNT${NC} x ${VM_CPU} cores x ${VM_MEM} MB"
    echo ""

    read -p "  Proceed with configuration? (y/n): " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Setup cancelled by user"
        exit 0
    fi
fi


# Generate Configuration
print_task "Generate Configuration Files (Setup Folder)"

# Check if PROBE_DIR is set, if not ask user
if [ -z "$PROBE_DIR" ] || [ ! -d "$PROBE_DIR" ]; then
    print_warning "Syzkaller directory not set"
    echo ""
    print_info "Please specify syzkaller directory for setup files:"

    # Search for existing syzkaller directories
    SYZ_SEARCH=($(find "$BASE_DIR" -maxdepth 2 -type d -name "syzkaller*" 2>/dev/null | sort))

    if [ ${#SYZ_SEARCH[@]} -gt 0 ]; then
        for i in "${!SYZ_SEARCH[@]}"; do
            print_choice "$(($i+1))" "${SYZ_SEARCH[$i]}"
        done
        print_choice "$(( ${#SYZ_SEARCH[@]} + 1 ))" "Enter custom path"
        print_choice "$(( ${#SYZ_SEARCH[@]} + 2 ))" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-$(( ${#SYZ_SEARCH[@]} + 2 ))]: " dir_choice
            if [[ $dir_choice =~ ^[0-9]+$ ]] && [ "$dir_choice" -ge 1 ] && [ "$dir_choice" -le $(( ${#SYZ_SEARCH[@]} + 2 )) ]; then
                if [ "$dir_choice" -le ${#SYZ_SEARCH[@]} ]; then
                    PROBE_DIR="${SYZ_SEARCH[$(($dir_choice-1))]}"
                    print_success "Using: $PROBE_DIR"
                    break
                elif [ "$dir_choice" -eq $(( ${#SYZ_SEARCH[@]} + 1 )) ]; then
                    read -p "  Enter syzkaller path: " PROBE_DIR
                    if [ -d "$PROBE_DIR" ]; then
                        print_success "Using: $PROBE_DIR"
                    else
                        mkdir -p "$PROBE_DIR"
                        print_success "Created: $PROBE_DIR"
                    fi
                    break
                else
                    GENERATE_SETUP=false
                    print_warning "Skipped setup folder generation"
                    break
                fi
            else
                print_error "Invalid input"
            fi
        done
    else
        print_choice "1" "Enter custom path"
        print_choice "2" "${YELLOW}Skip this step${NC}"
        echo ""

        while true; do
            read -p "  Select option [1-2]: " dir_choice
            if [[ $dir_choice =~ ^[1-2]$ ]]; then
                if [ "$dir_choice" -eq 1 ]; then
                    read -p "  Enter syzkaller path: " PROBE_DIR
                    if [ -d "$PROBE_DIR" ]; then
                        print_success "Using: $PROBE_DIR"
                    else
                        mkdir -p "$PROBE_DIR"
                        print_success "Created: $PROBE_DIR"
                    fi
                else
                    GENERATE_SETUP=false
                    print_warning "Skipped setup folder generation"
                fi
                break
            else
                print_error "Invalid input. Please select 1-2"
            fi
        done
    fi
fi

if [ "$GENERATE_SETUP" != false ]; then
    echo ""
    print_info "This will create setup folder with config and start script"
    print_choice "1" "Generate configuration files"
    print_choice "2" "${YELLOW}Skip this step${NC}"
    echo ""

    while true; do
        read -p "  Select option [1-2]: " setup_choice
        if [[ $setup_choice =~ ^[1-2]$ ]]; then
            if [ "$setup_choice" -eq 1 ]; then
                GENERATE_SETUP=true
                print_success "Will generate configuration files"
            else
                GENERATE_SETUP=false
                print_warning "Skipped setup folder generation"
            fi
            break
        else
            print_error "Invalid input. Please select 1-2"
        fi
    done
fi

if [ "$GENERATE_SETUP" = true ]; then
    WORKDIR="$PROBE_DIR/workdir"
    SETUP_DIR="$PROBE_DIR/setup"
    mkdir -p "$WORKDIR" "$SETUP_DIR"

    CFG_FILE="$SETUP_DIR/probe.cfg"

    cat > "$CFG_FILE" << EOF
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "$WORKDIR",
    "kernel_obj": "$BASE_DIR/$KERNEL_VERSION",
    "image": "$IMAGE_FILE",
    "sshkey": "$SSHKEY_FILE",
    "syzkaller": "$PROBE_DIR",
    "procs": $PROCS,
    "type": "qemu",
    "sandbox": "none",
    "reproduce": true,
    "cover": true,

    "vm": {
        "count": $VM_COUNT,
        "cpu": $VM_CPU,
        "mem": $VM_MEM,
        "kernel": "$BZIMAGE_PATH",
        "cmdline": "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0 panic_on_warn=1 oops=panic panic=86400 ftrace_dump_on_oops=orig_cpu"
    }
}
EOF

    if [ $? -eq 0 ]; then
        print_success "Config file: ${CYAN}$CFG_FILE${NC}"
    else
        print_error "Failed to create configuration"
        exit 1
    fi

    PROBE_SH="$SETUP_DIR/probe.sh"
    cat > "$PROBE_SH" << EOF
#!/bin/bash
sudo pkill -9 syz-manager 2>/dev/null
echo "Starting PROBE fuzzer..."
$PROBE_DIR/bin/syz-manager -config $CFG_FILE
EOF

    chmod +x "$PROBE_SH"
    print_success "Start script: ${CYAN}$PROBE_SH${NC}"
fi


# Summary
print_task "Setup Complete"
echo ""
print_success "All components configured successfully!"
echo ""
print_info "Installation Paths:"
echo -e "  ${BLUE}→${NC} Base Directory: ${CYAN}$BASE_DIR${NC}"
[ -n "$KERNEL_VERSION" ] && echo -e "  ${BLUE}→${NC} Kernel: ${CYAN}$BASE_DIR/$KERNEL_VERSION${NC}"
[ -n "$IMAGE_DIR" ] && echo -e "  ${BLUE}→${NC} Image: ${CYAN}$IMAGE_DIR${NC}"
[ -n "$GOROOT" ] && echo -e "  ${BLUE}→${NC} Go: ${CYAN}$GOROOT${NC}"
[ -n "$PROBE_DIR" ] && echo -e "  ${BLUE}→${NC} Syzkaller: ${CYAN}$PROBE_DIR${NC}"
[ -n "$ROOTFS_PATH" ] && echo -e "  ${BLUE}→${NC} RootFS: ${CYAN}$ROOTFS_PATH${NC}"
[ -n "$CFG_FILE" ] && echo -e "  ${BLUE}→${NC} Config: ${CYAN}$CFG_FILE${NC}"
echo ""
if [ "$GENERATE_SETUP" = true ]; then
    VM_MEM_GB=$(echo "scale=2; $VM_MEM / 1024" | bc)
    print_info "Fuzzing Configuration:"
    echo -e "  ${BLUE}→${NC} Level: ${CYAN}$LEVEL_NAME${NC}"
    [ -n "$KERNEL_VERSION" ] && echo -e "  ${BLUE}→${NC} Kernel: ${CYAN}$KERNEL_VERSION${NC}"
    [ -n "$IMAGE_FILE" ] && echo -e "  ${BLUE}→${NC} Image: ${CYAN}${IMAGE_FILE##*/}${NC}"
    echo -e "  ${BLUE}→${NC} Resources: ${CYAN}$PROCS procs, $VM_COUNT VMs x $VM_CPU cores x ${VM_MEM}MB (${VM_MEM_GB}GB)${NC}"
fi
if [ "$GENERATE_SETUP" = true ]; then
    echo ""
    print_info "Commands:"
    echo -e "  ${BLUE}→${NC} Start fuzzing:"
    echo -e "    ${CYAN}cd $SETUP_DIR && ./probe.sh${NC}"
    echo -e "  ${BLUE}→${NC} Monitor:"
    echo -e "    ${CYAN}http://localhost:56741${NC}"
fi
echo ""

exit 0
