#!/system/bin/sh
# Installer hook run by KernelSU/Magisk. Called after the module files
# have been extracted to $MODPATH. Anything we write to $MODPATH persists
# into /data/adb/modules/<id>/ after the installer finishes.

SKIPUNZIP=0
ui_print "- VPN Hide (Zygisk native) v0.1.0"
ui_print "- Installing to $MODPATH"

# Make the native library readable/executable by zygote
set_perm "$MODPATH/zygisk/arm64-v8a.so" 0 0 0755

# Seed an empty targets.txt file on first install. Users add package
# names (one per line, '#' for comments) via:
#   adb shell su -c 'nano /data/adb/modules/vpnhide_zygisk/targets.txt'
if [ ! -f "$MODPATH/targets.txt" ]; then
    cat > "$MODPATH/targets.txt" <<'EOF'
# vpnhide-zygisk target allowlist
# One package name per line. Lines starting with '#' are comments.
# Example:
#   ru.plazius.shokoladnica
#   com.example.someapp
EOF
fi

set_perm "$MODPATH/targets.txt" 0 0 0644

ui_print "- Installed. Edit /data/adb/modules/vpnhide_zygisk/targets.txt"
ui_print "  and reboot (or force-stop the target app) to take effect."
