# SyzRefine: Enhancing Kernel Fuzzing via LLM-powered Program Generation

## Main Components

1. Target Syscall Identification 
1. LM-powered Program Generation 

## Setup
1. Dependencies
    ```
    sudo apt-get update
    sudo apt-get install -y make git gcc flex bison libelf-dev libssl-dev bc qemu-system-x86 build-essential debootstrap
    ```

2. Install Go language support before compiling SyzMini.

    ```
    wget https://dl.google.com/go/go1.22.1.linux-amd64.tar.gz
    tar -xf go1.22.1.linux-amd64.tar.gz
    export GOROOT=`pwd`/go
    export PATH=$GOROOT/bin:$PATH
    ``` 

3. Also, SyzRefine requires [**KVM**](https://help.ubuntu.com/community/KVM/Installation)  enabled.

4. Build kernel (taking v5.15 as example)

    ``` 
    **  Checkout Linux Kernel source
    git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
    cd linux
    git checkout v5.15

    ** Generate default configs
    make defconfig

    **  Enable required config options
    # Coverage collection.
    CONFIG_KCOV=y
    # Debug info for symbolization.
    CONFIG_DEBUG_INFO_DWARF4=y
    # Memory bug detector
    CONFIG_KASAN=y
    CONFIG_KASAN_INLINE=y
    # Required for Debian Stretch and later
    CONFIG_CONFIGFS_FS=y
    CONFIG_SECURITYFS=y

    ** make olddefconfig

    ** Build the Kernel
    make -j`nproc`
    ``` 

5. Image

    ``` 
    ** Install debootstrap
    sudo apt install debootstrap

    ** Create Debian Bullseye Linux image
    mkdir image
    cd image/
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
    chmod +x create-image.sh
    ./create-image.sh
    ``` 

6. Build SyzRefine

    ```
    ** Clone SyzMini and compile the fuzzer. Make sure Go is installed.
    cd SyzRefine
    make
    ```

7. Run SyzRefine (take v515 as example)

    ```
    cd SyzRefine/bin 
    ./syz-manager -config your.cfg -llm_url llm_api_url -llm_mode llm_model_name -llm_token llm_token 
    ```

    The `syz-manager` process will wind up VMs and start fuzzing in them.
    The `-config` command line option gives the location of the configuration file, which is described [here](configuration.md).
    The `-llm_url` represents base_url to api address or local hosted LLM.
    The `-llm_model_name` represents model name, used with third party api or local LLM.
    The `-llm_token` represents api_key for third party api service.
    Found crashes, statistics and other information is exposed on the HTTP address specified in the manager config.
