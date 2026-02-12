#!/usr/bin/env sh
# axon | AU
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }

USERS='axon:123
enya:123
coop:123
webb:123'

is_freebsd() { [ "$(uname -s)" = "FreeBSD" ]; }

have() { command -v "$1" >/dev/null 2>&1; }

ensure_sudo_linux() {
  if have sudo; then return 0; fi

  if have apt-get; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y sudo
  elif have dnf; then
    dnf install -y sudo
  elif have yum; then
    yum install -y sudo
  elif have apk; then
    apk add --no-cache sudo shadow
  else
    echo "No supported package manager found to install sudo." >&2
    exit 1
  fi
}

ensure_sudo_freebsd() {
  if have sudo; then return 0; fi
  if have pkg; then
    pkg update -f
    pkg install -y sudo
  else
    echo "pkg not found on FreeBSD; install sudo manually." >&2
    exit 1
  fi
}

ensure_admin_group_linux() {
  if getent group sudo >/dev/null 2>&1; then
    echo sudo
  elif getent group wheel >/dev/null 2>&1; then
    echo wheel
  else
    if have addgroup; then
      addgroup wheel >/dev/null 2>&1 || true
    else
      groupadd wheel >/dev/null 2>&1 || true
    fi
    echo wheel
  fi
}

ensure_admin_group_freebsd() {
  pw groupshow wheel >/dev/null 2>&1 || pw groupadd wheel >/dev/null 2>&1 || true
  echo wheel
}

ensure_sudoers_group() {
  grp="$1"
  if [ -d /etc/sudoers.d ]; then
    f="/etc/sudoers.d/00-${grp}-nopasswd"
    if [ ! -f "$f" ]; then
      printf '%%%s ALL=(ALL) ALL\n' "$grp" > "$f"
      chmod 440 "$f" || true
    fi
  else
    if ! grep -qE "^[%]${grp}[[:space:]]+ALL=" /etc/sudoers 2>/dev/null; then
      printf '\n%%%s ALL=(ALL) ALL\n' "$grp" >> /etc/sudoers
    fi
  fi
}

create_or_update_user_linux() {
  u="$1"; p="$2"; shell="${3:-/bin/bash}"

  if id "$u" >/dev/null 2>&1; then
    :
  else
    if have adduser; then
      adduser -D -h "/home/$u" -s "$shell" "$u" 2>/dev/null \
        || adduser --disabled-password --gecos "" --home "/home/$u" --shell "$shell" "$u"
    else
      useradd -m -d "/home/$u" -s "$shell" "$u"
    fi
  fi

  if have chpasswd; then
    printf '%s:%s\n' "$u" "$p" | chpasswd
  else
    echo "chpasswd not found; cannot set password on Linux." >&2
    exit 1
  fi
}

create_or_update_user_freebsd() {
  u="$1"; p="$2"; shell="${3:-/bin/sh}"

  if pw usershow "$u" >/dev/null 2>&1; then
    :
  else
    pw useradd "$u" -m -d "/home/$u" -s "$shell"
  fi

  printf '%s\n' "$p" | pw usermod "$u" -h 0
}

add_to_group_linux() {
  u="$1"; grp="$2"
  if have usermod; then
    usermod -aG "$grp" "$u"
  else
    addgroup "$u" "$grp" >/dev/null 2>&1 || true
  fi
}

add_to_group_freebsd() {
  u="$1"; grp="$2"
  pw groupmod "$grp" -m "$u" >/dev/null 2>&1 || true
}

if is_freebsd; then
  ensure_sudo_freebsd
  ADMIN_GRP="$(ensure_admin_group_freebsd)"
  ensure_sudoers_group "$ADMIN_GRP"

  echo "$USERS" | while IFS=: read -r u p; do
    [ -n "${u:-}" ] || continue
    create_or_update_user_freebsd "$u" "$p" "/bin/sh"
    add_to_group_freebsd "$u" "$ADMIN_GRP"
  done
else
  ensure_sudo_linux
  ADMIN_GRP="$(ensure_admin_group_linux)"
  ensure_sudoers_group "$ADMIN_GRP"

  echo "$USERS" | while IFS=: read -r u p; do
    [ -n "${u:-}" ] || continue
    shbin="/bin/bash"
    [ -x /bin/ash ] && shbin="/bin/ash"
    [ -x /bin/sh ] && shbin="${shbin}"
    create_or_update_user_linux "$u" "$p" "$shbin"
    add_to_group_linux "$u" "$ADMIN_GRP"
  done
fi

echo "Done. Admin group: $ADMIN_GRP"
