# Getting started with OP-TEE and Vuln

## Prerequisites

Source:

- [official doc](https://optee.readthedocs.io/en/latest/building/prerequisites.html)

### Start an **Ubuntu 24.04** VM or docker environment

### Install dependencies

Inside the VM install these dependencies:

```bash
  apt update && apt upgrade -y

  apt install -y \
      adb \
      acpica-tools \
      autoconf \
      automake \
      bc \
      bison \
      build-essential \
      ccache \
      cpio \
      cscope \
      curl \
      device-tree-compiler \
      e2tools \
      expect \
      fastboot \
      flex \
      ftp-upload \
      gdisk \
      git \
      libattr1-dev \
      libcap-ng-dev \
      libfdt-dev \
      libftdi-dev \
      libglib2.0-dev \
      libgmp3-dev \
      libhidapi-dev \
      libmpc-dev \
      libncurses5-dev \
      libpixman-1-dev \
      libslirp-dev \
      libssl-dev \
      libtool \
      libusb-1.0-0-dev \
      make \
      mtools \
      netcat \
      ninja-build \
      python3-cryptography \
      python3-pip \
      python3-pyelftools \
      python3-serial \
      python-is-python3 \
      rsync \
      swig \
      unzip \
      uuid-dev \
      wget \
      xdg-utils \
      xterm \
      xz-utils \
      zlib1g-dev
```

### Install repo from source

[repo](https://gerrit.googlesource.com/git-repo)  is a python script built on
top of git to manage multiple git repositories at the same time.

```bash
# Install Repo and make it executable
curl https://storage.googleapis.com/git-repo-downloads/repo > /bin/repo && chmod a+x /bin/repo
```

### Clone OP-TEE repository

```bash
mkdir ./optee && cd ./optee
# Clone OP-TEE repo in ./optee
repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml && repo sync -j10
```

### Compile everything

```bash
cd ./build
make -j$(nproc) toolchains
make -j$(nproc) check
```

_NOTE_: The very first time it takes a long time

## Developing trusted applications

The fastest way of doing so is moving into `./optee/optee-examples`, starting
to modify one of the existing examples. This demo overwrites `aes`.

When you are ready to test move in `./optee/build` and issue:

```bash
# Compile + Start QEMU
make run
```

Alternatively, you might start only the emulated environment issuing:

```bash
make run-only
```

In either scenario, a QEMU virtual machine is started at the end. It spawns
three tabs titled: QEMU, Normal World, and Secure World. Initially, neither the
Normal World and Secure World are running. To start them, move in the QEMU tab,
where there is a prompt. Send the `c`(ontinue) command:

```bash
(qemu) c
```

After completing the boot process, Normal World prompts for the username
`root`. optee examples are already installed. The binary names are in the
format `optee_examples_<name_of_the_example>`

Additional (not requested) details on the trusted application development can
be found
[here](https://kickstartembedded.com/2022/11/13/op-tee-part-4-writing-your-first-trusted-application/).

## Getting start with evil

1. overwrite `aes` directory with the one provided by this repository.
2. Disable buffer overflow countermeasures, by applying
   [this](./patches/0001-disable-ASLR-and-stack-canary.patch) patch.

```bash
cd ./optee/optee_os
git ../../patches/apply 0001-disable-ASLR-and-stack-protector.patch
```

3. Compile OPTEE-OS and TAs

``` bash
cd ../build
make
```

4. Within the Normal World shell you should have the executable `evil`

## evil usage

The application stores a password that will be later used to obtain a secret,
printed in the secure serial console. evil contains the vulnerable command
`vuln` which exploits a buffer overflow in the TA via ROP. This command prints
in the secure serial the secret.


1. Setting a password

```bash
evil setpw
```

2. Retrieve the secret

```bash
evil get
```

3. Get the secret (without the password) using the `vuln` command

```bash
evil vuln
```

## On the attack success

The attack may still fail, since OPTEE-OS might use a different load address
from the default one. In this case, you can try to restart the VMs with `make
run-only`; eventually the default one is picked. You can also modify the
application to try the attack with both load base.
The address of functions and `SECRET` that are assumed in `aes/host/rop1.h` may
change when the TA is compiled. This is extremely likely, if the source is
modified somehow. This will likely result in a crash in the TA due to a
translation fault.

