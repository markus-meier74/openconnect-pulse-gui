# openconnect-pulse-gui

This script provides a wrapper around [OpenConnect](https://www.infradead.org/openconnect/) which allows a user to log on to an Ivanti (formerly Pulse) Secure VPN server using a WebKitGTK browser window. It is compatible with Microsoft Entra multi-factor authentication.

## Requirements

The script requires Python 3. The following packages are also required:

 - PyGObject
 - WebKit2 (API Version 4.1)
 - OpenConnect

Instruction for specific distros can be found below.

### Debian/Ubuntu

    sudo apt install python3-gi gir1.2-webkit2-4.1 openconnect

### Fedora

    sudo yum install python-gi webkit2gtk3 openconnect

### Arch

    sudo pacman -S python-gobject webkit2gtk openconnect

### openSUSE

    sudo zypper in python3-gobject typelib-1_0-WebKit2-4_1 openconnect

### Gentoo

An ebuild for your personal Gentoo overlay is provided in the gentoo subdirectory.
For instructions how to create your personal overlay, check out this [Gentoo Wiki Article](https://wiki.gentoo.org/wiki/Creating_an_ebuild_repository).

## Installation

This repo can be downloaded with `git clone https://github.com/markus-meier74/openconnect-pulse-gui.git` or via the GitHub webpage.

Installation is easiest by creating a virtual Python environment, such as with venv.
The following instructions assume that the Git repo was cloned to `${HOME}/scripts/vpn/openconnect-pulse-gui`.

    mkdir -p ${HOME}/scripts/vpn/venv
    python -m venv --system-site-packages ${HOME}/scripts/vpn/venv
    source ${HOME}/scripts/vpn/venv/bin/activate
    cd ${HOME}/scripts/vpn/openconnect-pulse-gui
    pip install .
    deactivate

# Configuring sudo

OpenConnect requires root privileges to configure the network interfaces for VPN. The `openconnect-pulse-gui` script embeds a web browser and should definitely not be run as root. The script will try to execute openconnect with sudo. The user requires access to the `openconnect` command via sudo which can be configured by creating a plain text file `/etc/sudoers.d/openconnect` with a content like this:

    # Allow all users that are in the "users" group to run openconnect as root without asking for a password
    %users ALL=(root:root) NOEXEC, NOPASSWD: /usr/bin/openconnect

Note that the packages for some distributions (including openSUSE) put the OpenConnect binary in `/usr/sbin/openconnect`, so you may need to make the corresponding change.  You may also need to change `%users` to a suitable group or username, as some distributions don't automatically add users to the `users` group.

The `/etc/sudoers.d/openconnect` file should be owned by root:root and have permissions 440:

    chown root:root /etc/sudoers.d/openconnect
    chmod 440 /etc/sudoers.d/openconnect

The privileges can be tailored to your needs as described in the sudo manual.

## Usage

Activate the virtual environment that has `openconnect-pulse-gui` installed. The `openconnect-pulse-gui` script should now be in your `$PATH`.

The only required required argument is the sign-in link / server URL.  Other arguments can be found by using `python openconnect-pulse-gui.py -h`.

## Troubleshooting

### "Permission denied" errors from WebKit2

If WebKit2 throws errors such as `KMS: DRM_IOCTL_MODE_CREATE_DUMB failed: Permission denied`,
disable Shared DMA buffer rendering by setting the environmental variable `WEBKIT_DISABLE_DMABUF_RENDERER=1`.

Here is an example Bash script:

    #!/bin/bash
    . "${HOME}/scripts/vpn/venv/bin/activate"
    WEBKIT_DISABLE_DMABUF_RENDERER=1 openconnect-pulse-gui "vpn.cc.umanitoba.ca"
    deactivate

### DNS servers not updated

If you are using NetworkManager, you may find that `openconnect-pulse-gui` fails to update the DNS servers in `/etc/resolv.conf`.  This may be because your distribution has configured NetworkManager to enforce a policy that all changes to `/etc/resolv.conf` must go through NetworkManager itself.  In this case, you can force `/etc/resolv.conf` to update by running `sudo netconfig update -f`.  To avoid having to do this each time you run `openconnect-pulse-gui`, you could find the `NETCONFIG_DNS_POLICY` setting in `/etc/sysconfig/network/config` and change it to the following: `NETCONFIG_DNS_POLICY='STATIC_FALLBACK * NetworkManager'`.  (Alternatively, you could switch from NetworkManager to another network configuration framework, such as the traditional `ifup` family of scripts or [Wicked](https://en.opensuse.org/Portal:Wicked).)

## Login process

Anybody wishing to recreate this functionality either manually or using another library can do so with the following steps:

1. Send the user to the sign-in URL. This will either give them the ability to log in directly or redirect them to an external authentication server.
2. Wait for a `Set-Cookie` header that contains the `DSID` cookie. This is the authentication cookie used by Pulse Secure.
3. Pass the cookie to `openconnect` using `--protocol nc` and `-C 'DSID=<cookie-value>'`. Note that some workflows may work with `--protocol pulse`, but at this time SAML-based logins do not.

This script was tested and works with Ivanti Secure with Microsoft Entra multi-factor authentication at the University of Manitoba.
