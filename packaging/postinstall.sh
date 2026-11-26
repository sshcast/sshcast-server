#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

if command -v deb-systemd-helper >/dev/null 2>&1; then
    deb-systemd-helper unmask sshcast-server.socket sshcast-server.service >/dev/null 2>&1 || true
    if deb-systemd-helper --quiet was-enabled sshcast-server.socket >/dev/null 2>&1; then
        deb-systemd-helper enable sshcast-server.socket >/dev/null 2>&1 || true
    else
        deb-systemd-helper update-state sshcast-server.socket >/dev/null 2>&1 || true
    fi
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet sshcast-server.service; then
        systemctl try-restart sshcast-server.service >/dev/null 2>&1 || true
    fi
fi
