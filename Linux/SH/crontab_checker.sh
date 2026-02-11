#!/bin/bash
set -u

print_section() {
  echo
  echo "===== $1 ====="
}

strip_comments_blank() {
  # remove full-line comments and blank lines
  sed -e 's/\r$//' -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d'
}

# --- 1) Per-user crontab via crontab(1) ---
print_section "Per-user crontab entries via crontab -l"

while IFS=: read -r user _; do
  crontab_content=$(sudo -n -u "$user" crontab -l 2>/dev/null | strip_comments_blank || true)

  if [ -n "$crontab_content" ]; then
    echo "Username: $user"
    echo "Crontab:"
    echo "$crontab_content"
    echo "------------------------"
  fi
done < /etc/passwd

# --- 2) Spool-based crontabs (/var/spool/cron*) ---
print_section "Spool-based user crontabs (/var/spool/cron*)"

spool_dirs=(
  /var/spool/cron/crontabs
  /var/spool/cron
)

found_any_spool=0
for d in "${spool_dirs[@]}"; do
  [ -d "$d" ] || continue

  # Skip Debian's /var/spool/cron if it only contains "crontabs" dir
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"

    # Avoid double-printing Debian/Ubuntu when iterating /var/spool/cron
    if [ "$d" = "/var/spool/cron" ] && [ "$base" = "crontabs" ]; then
      continue
    fi

    content=$(strip_comments_blank < "$f" 2>/dev/null || true)
    if [ -n "$content" ]; then
      found_any_spool=1
      echo "Spool file: $f"
      echo "As user: $base"
      echo "Crontab:"
      echo "$content"
      echo "------------------------"
    fi
  done
done

[ "$found_any_spool" -eq 0 ] && echo "No non-empty spool crontabs found (or insufficient permissions)."

# --- 3) System-wide cron ---
print_section "System-wide cron"

if [ -f /etc/crontab ]; then
  content=$(strip_comments_blank < /etc/crontab || true)
  if [ -n "$content" ]; then
    echo "/etc/crontab:"
    echo "$content"
    echo "------------------------"
  fi
fi

if [ -d /etc/cron.d ]; then
  for f in /etc/cron.d/*; do
    [ -f "$f" ] || continue
    content=$(strip_comments_blank < "$f" 2>/dev/null || true)
    if [ -n "$content" ]; then
      echo "$f:"
      echo "$content"
      echo "------------------------"
    fi
  done
fi

for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$dir" ] || continue
  echo "$dir (files executed by run-parts):"
  ls -1 "$dir" 2>/dev/null | sed 's/^/  - /'
  echo "------------------------"
done