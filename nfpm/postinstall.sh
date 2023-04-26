#!/bin/sh

cleanInstall() {
    if [ -x "/usr/bin/deb-systemd-helper" ]; then
        deb-systemd-helper purge athenz-sia.service >/dev/null
        deb-systemd-helper unmask athenz-sia.service >/dev/null
    elif [ -x "/usr/bin/systemctl" ]; then
        systemctl daemon-reload ||:
        systemctl unmask athenz-sia.service ||:
        systemctl preset athenz-sia.service ||:
        systemctl enable athenz-sia.service ||:
    fi
}

upgrade() {
    printf "\033[32m Upgrading athenz-sia\033[0m\n"
    if [ -x "/usr/bin/systemctl" ]; then
        systemctl restart athenz-sia.service ||:
    fi
}

# Step 2, check if this is a clean install or an upgrade
action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  # Alpine linux does not pass args, and deb passes $1=configure
  action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
    # deb passes $1=configure $2=<current version>
    action="upgrade"
fi

case "$action" in
  "1" | "install")
    cleanInstall
    ;;
  "2" | "upgrade")
    upgrade
    ;;
  *)
    # $1 == version being installed
    printf "\033[32m Alpine\033[0m"
    cleanInstall
    ;;
esac

exit 0
