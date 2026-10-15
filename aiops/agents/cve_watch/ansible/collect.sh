#!/bin/sh
# cve-watch collector -- STRICTLY READ-ONLY.
# Only reads package databases, /proc and /etc; never writes, installs or restarts anything.
# Runs through Ansible's `raw` module (no files copied to the host, no Python required).
# Output: sections separated by "@@@SECTION <NAME>" lines, parsed by hostfacts.py.

export LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export PATH

sec() { echo "@@@SECTION $1"; }

sec META
echo "uid=$(id -u)"
echo "kernel=$(uname -r)"
echo "arch=$(uname -m)"

sec OS_RELEASE
cat /etc/os-release 2>/dev/null

if command -v dpkg-query >/dev/null 2>&1; then
    PKGMGR=dpkg
    sec PKG_DPKG
    # status \t binary \t source \t version \t source_version
    dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${source:Package}\t${Version}\t${source:Version}\n' 2>/dev/null \
        | awk -F'\t' '$1 ~ /^ii/'
elif command -v rpm >/dev/null 2>&1; then
    PKGMGR=rpm
    sec PKG_RPM
    # name \t epoch \t version \t release \t arch \t sourcerpm
    rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null \
        | grep -v '^gpg-pubkey'
else
    PKGMGR=none
fi

sec LISTEN
if command -v ss >/dev/null 2>&1; then
    ss -Htulnp 2>/dev/null || ss -tulnp 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>/dev/null
fi

# Executables and shared libraries mapped by running processes: comm \t path
sec PROC_FILES
for p in /proc/[0-9]*; do
    comm=$(cat "$p/comm" 2>/dev/null) || continue
    {
        readlink "$p/exe" 2>/dev/null
        awk '$6 ~ /\.so/ {print $6}' "$p/maps" 2>/dev/null
    } | sed 's/ (deleted)$//' | while read -r f; do
        [ -n "$f" ] && printf '%s\t%s\n' "$comm" "$f"
    done
done | sort -u

# Which package owns each file above (path and its /usr-merge twin are both queried).
sec FILE_OWNERS
files=$(for p in /proc/[0-9]*; do
            readlink "$p/exe" 2>/dev/null
            awk '$6 ~ /\.so/ {print $6}' "$p/maps" 2>/dev/null
        done | sed 's/ (deleted)$//' | sort -u)
if [ "$PKGMGR" = dpkg ]; then
    for f in $files; do
        echo "$f"
        case "$f" in
            /usr/*) echo "${f#/usr}" ;;
            *) echo "/usr$f" ;;
        esac
    done | sort -u | xargs -r dpkg-query -S 2>/dev/null
elif [ "$PKGMGR" = rpm ]; then
    for f in $files; do
        o=$(rpm -qf --qf '%{NAME}\n' "$f" 2>/dev/null | head -n1)
        case "$o" in *"not owned"*|"") ;; *) printf '%s: %s\n' "$o" "$f" ;; esac
    done
fi

sec MODULES
cut -d' ' -f1 /proc/modules 2>/dev/null

sec SERVICES
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}'
fi

sec END
exit 0
