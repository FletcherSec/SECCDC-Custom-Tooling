#!/usr/bin/env bash
set -euo pipefail

HOURS=24
MINS="10"
OUT=""
CMD=""
BASE=""
WEBHOOK="${WEBHOOK:-}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ME="$(id -un)"
HOST="$(hostname -f 2>/dev/null || hostname)"
REPORT_CONTENT=""
IS_TTY=0
[ -t 1 ] && IS_TTY=1

usage() {
        printf "usage: %s --init|--check [--hours N|--mins N] [--out FILE] [--webhook URL]\n" "$(basename "$0")"
        exit 2
}

case "${1:-}" in
        --init|--check) CMD="$1"; shift ;;
        *) usage ;;
esac
while [ $# -gt 0 ]; do
        case "$1" in
                --hours) HOURS="${2:-24}"; shift 2 ;;
                --mins) MINS="${2:-}"; shift 2 ;;
                --out) OUT="${2:-}"; shift 2 ;;
                --webhook) WEBHOOK="${2:-}"; shift 2 ;;
                *) usage ;;
        esac
done
[ -z "$MINS" ] && MINS=$((HOURS*60))

if [ "$(id -u)" -eq 0 ]; then
        BASE="/var/lib/hostguard"
else
        BASE="$HOME/.bigbrother"
fi
mkdir -p "$BASE"/{snap,loot,tmp}

BL_FILES="$BASE/snap/baseline-files.txt"
BL_HASH="$BASE/snap/baseline-hashes.txt"
BL_ETCPASS="$BASE/snap/etc-passwd"
BL_ETCGROUP="$BASE/snap/etc-group"
BL_SSHD="$BASE/snap/sshd_config"
BL_SUDO="$BASE/snap/sudoers-all.txt"
BL_KEYS="$BASE/snap/authorized_keys-all.txt"
BL_LISTEN="$BASE/snap/listen-ss.txt"
BL_GETCAP="$BASE/snap/getcap.txt"
BL_CRON="$BASE/snap/cron-all.txt"
BL_SUIDMETA="$BASE/snap/suidsgid.tsv"
BL_TIMERS_MAP="$BASE/snap/systemd-timers-map.tsv"
BL_TIMERS_STATE="$BASE/snap/systemd-timers-state.tsv"
BL_LSMOD="$BASE/snap/lsmod.txt"

# -------- colored reporting (TTY only) ----------
_emit_console() {
        local s="$1"
        if [ "$IS_TTY" -eq 1 ]; then
                case "$s" in
                        ALERT\ *) printf "\033[1;31m%s\033[0m\n" "$s" ;;
                        ATTN\ *)  printf "\033[1;33m%s\033[0m\n" "$s" ;;
                        OK\ *)    printf "\033[1;32m%s\033[0m\n" "$s" ;;
                        *)        printf "%s\n" "$s" ;;
                esac
        else
                printf "%s\n" "$s"
        fi
}
report() {
        local line="$1"
        _emit_console "$line"
        if [ -n "$OUT" ]; then printf "%s\n" "$line" >> "$OUT"; fi
        REPORT_CONTENT+="$line"$'\n'
}
ALERT_FLAG=0
alert() { ALERT_FLAG=1; report "ALERT  $1"; }

json_escape() { sed -e 's/\r//g' -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g'; }

post_discord_text() {
        [ -z "$WEBHOOK" ] && return 0
        local body="$1" max=1900 len start=0 chunk esc payload code
        len=${#body}
        while [ $start -lt $len ]; do
                chunk="${body:$start:$max}"
                esc="$(printf "%s" "$chunk" | json_escape)"
                payload="$(printf '{"content":"%s"}' "$esc")"
                code=$(curl -sS -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -d "$payload" "$WEBHOOK" || echo "000")
                [ "$code" = "204" ] || [ "$code" = "200" ] || { printf "[ERROR] discord http %s\n" "$code" >&2; break; }
                start=$((start+max))
                sleep 1
        done
}
post_discord_file() {
        [ -z "$WEBHOOK" ] && return 0
        local path="$1" code
        code=$(curl -sS -o /dev/null -w "%{http_code}" -F "file1=@${path}" -F "payload_json={\"content\":\"${HOST}: hostguard report ${TS}\"}" "$WEBHOOK" || echo "000")
        [ "$code" = "200" ] || [ "$code" = "204" ] || printf "[ERROR] discord file http %s\n" "$code" >&2
}

collect_sudoers() {
        { [ -f /etc/sudoers ] && cat /etc/sudoers; } 2>/dev/null || true
        { [ -d /etc/sudoers.d ] && find /etc/sudoers.d -maxdepth 1 -type f -print -exec sed -n '1,200p' {} \; ; } 2>/dev/null || true
}
collect_authkeys() {
        getent passwd | awk -F: '{print $1":"$6}' | while read -r u; do
                name="${u%%:*}"; home="${u#*:}"
                for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
                        [ -f "$f" ] && { echo "### $name $f"; sed -n '1,200p' "$f"; }
                done
        done 2>/dev/null || true
}
collect_cron() {
        crontab -l 2>/dev/null || true
        for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] && { echo "### $f"; sed -n '1,200p' "$f"; }; done 2>/dev/null || true
}
collect_listen() { ss -lntup 2>/dev/null || true; }
collect_getcap() { getcap -r / 2>/dev/null || true; }

pkg_verify() {
        if command -v rpm >/dev/null 2>&1; then
                rpm -Va --nodigest --nosignature 2>/dev/null || true
        elif command -v debsums >/dev/null 2>&1; then
                debsums -s 2>/dev/null || true
        else
                echo ""
        fi
}

find_recent() { find /etc /usr/bin /usr/sbin -xdev -type f -mmin "-$MINS" 2>/dev/null; }

list_suid_meta() {
        find / -xdev -type f -perm /6000 2>/dev/null | while read -r f; do
                [ -e "$f" ] || continue
                md="$(stat -c '%a' "$f" 2>/dev/null || echo '-')"
                uu="$(stat -c '%u' "$f" 2>/dev/null || echo '-')"
                gg="$(stat -c '%g' "$f" 2>/dev/null || echo '-')"
                sh="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
                printf "%s\t%s\t%s\t%s\t%s\n" "$f" "$md" "$uu" "$gg" "$sh"
        done | sort -k1,1
}

timers_map() { systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $(NF-0)"\t"$(NF-1)}' | sort -u; }
timers_state() { systemctl list-unit-files --type=timer --no-legend 2>/dev/null | awk '{print $1"\t"$2}' | sort -u; }

baseline_paths() { { find /etc -xdev -type f 2>/dev/null; find /usr/bin /usr/sbin -xdev -type f 2>/dev/null; } | sort -u; }
hash_paths() { sha256sum "$@" 2>/dev/null | awk '{print $2"\t"$1}'; }

# PATH hygiene: resolve symlinks; check others-write bit only
writable_path_findings() {
        local p i real oct o perms
        IFS=':' read -r -a p <<< "${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
        for i in "${p[@]}"; do
                [ -e "$i" ] || continue
                real="$(readlink -f "$i" 2>/dev/null || echo "$i")"
                [ -d "$real" ] || continue
                oct="$(stat -Lc '%a' "$real" 2>/dev/null || echo '')"
                [ -n "$oct" ] || continue
                o="${oct: -1}"
                perms="$(stat -Lc '%A' "$real" 2>/dev/null || echo '')"
                if [ $((o & 2)) -ne 0 ]; then echo "ATTN  PATH dir world-writable: $real ($perms)"; fi
                case "$real" in /home/*|/tmp/*|/var/tmp/*|/dev/shm/*) echo "ATTN  PATH dir risky: $real ($perms)";; esac
        done | sort -u
}

new_execs_in_writable_window() {
        find /tmp /dev/shm /var/tmp /home -xdev -type f -mmin "-$MINS" -perm -111 2>/dev/null
}

immutable_files() {
        command -v lsattr >/dev/null 2>&1 || return 0
        lsattr -aR /etc /usr/bin /usr/sbin /home /opt /var 2>/dev/null \
        | awk '$1 ~ /i/ {print $2}' \
        | grep -Ev '^(/etc/(apt|systemd|network|ssh|pki|dbus|initramfs|vmware|apparmor|audit|polkit|udev|modprobe|alternatives|logcheck)|/usr/(share|lib|include|src)|/var/(cache|lib|log|backups))' \
        | grep -v '^$' \
        | while read -r p; do [ -n "$p" ] && [ ! -d "$p" ] && printf "%s\n" "$p"; done
}

suspicious_sudoers_lines() { collect_sudoers | awk 'tolower($0) ~ /nopasswd|!authenticate/'; }
suspicious_cron_lines() { collect_cron | awk 'tolower($0) ~ /(curl|wget|nc[^k]|bash -i|\/dev\/tcp|python -c)/'; }
lsmod_now() { command -v lsmod >/dev/null 2>&1 || { echo ""; return; }; lsmod | awk 'NR>1{print $1}' | sort; }

init_baseline() {
        : > "$BL_FILES"; : > "$BL_HASH"
        baseline_paths > "$BL_FILES"
        split -l 2000 "$BL_FILES" "$BASE/tmp/chunks." || true
        for c in "$BASE"/tmp/chunks.*; do
                [ -f "$c" ] || continue
                mapfile -t arr < "$c"
                [ "${#arr[@]}" -gt 0 ] && hash_paths "${arr[@]}" >> "$BL_HASH" || true
        done
        rm -f "$BASE"/tmp/chunks.* 2>/dev/null || true

        cp /etc/passwd "$BL_ETCPASS" 2>/dev/null || true
        cp /etc/group "$BL_ETCGROUP" 2>/dev/null || true
        [ -f /etc/ssh/sshd_config ] && cp /etc/ssh/sshd_config "$BL_SSHD" || true
        collect_sudoers > "$BL_SUDO"
        collect_authkeys > "$BL_KEYS"
        collect_listen > "$BL_LISTEN"
        collect_getcap > "$BL_GETCAP"
        collect_cron > "$BL_CRON"
        list_suid_meta > "$BL_SUIDMETA"
        timers_map > "$BL_TIMERS_MAP"
        timers_state > "$BL_TIMERS_STATE"
        lsmod_now > "$BL_LSMOD" 2>/dev/null || true

        report "[INFO] baseline created at $TS in $BASE/snap"
        post_discord_text "${HOST}: baseline created ${TS}"
}

delta_hashes() {
        tmp_now="$BASE/tmp/now-hashes.txt"
        tmp_cmp="$BASE/tmp/cmp.txt"
        : > "$tmp_now"
        mapfile -t paths < "$BL_FILES"
        chunk=2000
        for ((i=0; i<${#paths[@]}; i+=chunk)); do
                part=("${paths[@]:i:chunk}")
                hash_paths "${part[@]}" >> "$tmp_now" || true
        done
        now_list="$BASE/tmp/now-list.txt"
        baseline_paths > "$now_list"
        comm -13 <(cut -f1 "$BL_HASH" | sort) <(sort "$now_list") > "$BASE/tmp/new-files.txt" || true
        join -t $'\t' -a1 -a2 -e MISSING -o 1.1,1.2,2.2 -j1 <(sort -k1,1 "$BL_HASH") <(sort -k1,1 "$tmp_now") > "$tmp_cmp" || true
        echo "$tmp_cmp"
}

diff_simple() {
        A="$1"; B="$2"; title="$3"
        if [ -s "$A" ] || [ -s "$B" ]; then
                local d; d="$(diff -u "$A" "$B" || true)"
                if [ -n "$d" ]; then
                        report "### $title"
                        printf "%s\n" "$d" | while IFS= read -r l; do report "$l"; done
                        alert "$title changed"
                        report ""
                else
                        report "OK  $title unchanged"
                        report ""
                fi
        fi
}

check_now() {
        [ -n "$OUT" ] && : > "$OUT"

        report "== hostguard report: $TS =="
        report "host: $HOST"
        report "user: $ME"
        report ""

        report "## BASELINE DELTAS"
        now_passwd="$BASE/tmp/etc-passwd.now"; cp /etc/passwd "$now_passwd" 2>/dev/null || true
        now_group="$BASE/tmp/etc-group.now"; cp /etc/group "$now_group" 2>/dev/null || true
        now_sshd="$BASE/tmp/sshd_config.now"; [ -f /etc/ssh/sshd_config ] && cp /etc/ssh/sshd_config "$now_sshd" || :
        now_sudo="$BASE/tmp/sudoers-all.now"; collect_sudoers > "$now_sudo"
        now_keys="$BASE/tmp/authorized_keys-all.now"; collect_authkeys > "$now_keys"
        now_listen="$BASE/tmp/listen-ss.now"; collect_listen > "$now_listen"
        now_getcap="$BASE/tmp/getcap.now"; collect_getcap > "$now_getcap"
        now_cron="$BASE/tmp/cron-all.now"; collect_cron > "$now_cron"

        diff_simple "$BL_ETCPASS" "$now_passwd" "DIFF /etc/passwd"
        diff_simple "$BL_ETCGROUP" "$now_group" "DIFF /etc/group"
        [ -f "$BL_SSHD" ] && [ -f "$now_sshd" ] && diff_simple "$BL_SSHD" "$now_sshd" "DIFF sshd_config" || true
        diff_simple "$BL_SUDO" "$now_sudo" "DIFF sudoers"
        diff_simple "$BL_KEYS" "$now_keys" "DIFF authorized_keys"
        diff_simple "$BL_LISTEN" "$now_listen" "DIFF listening sockets (ss)"
        diff_simple "$BL_GETCAP" "$now_getcap" "DIFF file capabilities"
        diff_simple "$BL_CRON" "$now_cron" "DIFF cron"

        report "### DIFF systemd timers (units/activations/status)"
        now_tmap="$BASE/tmp/systemd-timers-map.now.tsv"; timers_map > "$now_tmap"
        now_tstate="$BASE/tmp/systemd-timers-state.now.tsv"; timers_state > "$now_tstate"
        d="$(diff -u "$BL_TIMERS_MAP" "$now_tmap" || true)"
        if [ -n "$d" ]; then printf "%s\n" "$d" | while IFS= read -r l; do report "$l"; done; alert "systemd timers map changed"; else report "OK  timers units→activates unchanged"; fi
        d="$(diff -u "$BL_TIMERS_STATE" "$now_tstate" || true)"
        if [ -n "$d" ]; then printf "%s\n" "$d" | while IFS= read -r l; do report "$l"; done; alert "systemd timers enabled/disabled changed"; else report "OK  timers enabled/disabled unchanged"; fi
        report ""

        cmpfile="$(delta_hashes)"
        modified=$(awk -F'\t' '$2!=$3 && $3!="MISSING" {print $1"  "$2" -> "$3}' "$cmpfile" || true)
        deleted=$(awk -F'\t' '$3=="MISSING" {print $1}' "$cmpfile" || true)

        if [ -n "$modified" ]; then
                report "### MODIFIED FILES (baseline vs now)"
                report "$modified"
                alert "binary/config modifications since baseline"
                report ""
        else
                report "OK  No modified files vs baseline"
                report ""
        fi
        if [ -n "$deleted" ]; then
                report "### DELETED FILES (were in baseline)"
                report "$deleted"
                alert "files deleted since baseline"
                report ""
        else
                report "OK  No deletions vs baseline"
                report ""
        fi
        if [ -s "$BASE/tmp/new-files.txt" ]; then
                report "### NEW FILES (not in baseline)"
                report "$(sed -n '1,500p' "$BASE/tmp/new-files.txt")"
                alert "new files since baseline"
                report ""
        else
                report "OK  No new files vs baseline"
                report ""
        fi

        report "## HEURISTICS"
        report "### RECENT CHANGES (<= ${MINS}m) in /etc /usr/bin /usr/sbin"
        _rc="$(find_recent | sed -n '1,500p')"
        if [ -n "$_rc" ]; then while read -r l; do report "ATTN  $l"; done <<<"$_rc"; else report "OK  No recent changes in monitored dirs"; fi
        report ""

        report "### NEW/CHANGED/REMOVED SUID/SGID BINARIES (vs baseline)"
        now_suid="$BASE/tmp/suidsgid.now.tsv"; list_suid_meta > "$now_suid"
        join -t $'\t' -a1 -a2 -e MISSING -j1 <(sort -k1,1 "$BL_SUIDMETA") <(sort -k1,1 "$now_suid") > "$BASE/tmp/suid.joined" || true
        _suid_out="$(
                awk -F'\t' '
                {
                        path=$1; bl=sprintf("%s|%s|%s|%s",$2,$3,$4,$5); nw=sprintf("%s|%s|%s|%s",$6,$7,$8,$9)
                        if($2=="MISSING"){ printf("ATTN  ADDED  %s  mode=%s uid=%s gid=%s sha=%s\n",path,$6,$7,$8,$9) }
                        else if($6=="MISSING"){ printf("ATTN  REMOVED  %s  was mode=%s uid=%s gid=%s sha=%s\n",path,$2,$3,$4,$5) }
                        else if(bl!=nw){ printf("ATTN  CHANGED  %s  %s -> %s\n",path,bl,nw) }
                }' "$BASE/tmp/suid.joined"
        )"
        if [ -n "$_suid_out" ]; then
                while read -r l; do report "$l"; done <<< "$_suid_out"
                alert "SUID/SGID deltas"
        else
                report "OK  No SUID/SGID deltas"
        fi
        report ""

        report "### WORLD-WRITABLE FILES (excluding tmp/run/dev/proc/sys/log)"
        _ww="$(find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path /var/log -o -path /var/tmp -o -path /tmp \) -prune -o -perm -0002 -type f -print 2>/dev/null | sed -n '1,500p')"
        if [ -n "$_ww" ]; then while read -r l; do report "ATTN  $l"; done <<<"$_ww"; else report "OK  No world-writable files outside exclusions"; fi
        report ""

        report "### PROCESSES EXECUTING FROM WRITABLE DIRS (/tmp,/dev/shm,/var/tmp,/home)"
        _proc=""
        mapfile -t P < <(ps -eo pid,comm --no-headers 2>/dev/null || true)
        for line in "${P[@]}"; do
                pid="$(awk '{print $1}' <<<"$line")"
                exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
                [ -z "$exe" ] && continue
                case "$exe" in
                        /tmp/*|/dev/shm/*|/var/tmp/*|/home/*) _proc="${_proc}ATTN  ${pid}  ${exe}"$'\n' ;;
                esac
        done
        if [ -n "$_proc" ]; then while read -r l; do [ -n "$l" ] && report "$l"; done <<<"$_proc"; else report "OK  No processes executing from writable dirs"; fi
        report ""

        report "### PACKAGE VERIFICATION (rpm -Va / debsums -s)"
        _pkg="$(pkg_verify | sed -n '1,1000p')"
        if [ -n "$_pkg" ]; then while read -r l; do report "ATTN  $l"; done <<<"$_pkg"; alert "package verification mismatches"; else report "OK  Packages match vendor manifests"; fi
        report ""

        report "### PATH hygiene (world-writable / risky dirs)"
        _wp="$(writable_path_findings | sed -n '1,200p')"
        if [ -n "${_wp}" ]; then while read -r l; do report "$l"; done <<< "${_wp}"; else report "OK  No risky PATH entries"; fi
        report ""

        report "### New executables in writable dirs (<= ${MINS}m)"
        _newexec="$(new_execs_in_writable_window | sed -n '1,200p')"
        if [ -n "${_newexec}" ]; then while read -r l; do report "ATTN  $l"; done <<< "${_newexec}"; alert "new executable(s) in writable dirs"; else report "OK  No new executables in writable dirs"; fi
        report ""

        report "### Immutable files (lsattr +i) in monitored trees"
        _immut="$(immutable_files | sed -n '1,200p')"
        if [ -n "${_immut}" ]; then while read -r l; do report "ATTN  $l"; done <<< "${_immut}"; alert "unexpected immutable files"; else report "OK  No unexpected immutable files"; fi
        report ""

        report "### Suspicious sudoers lines (NOPASSWD/!authenticate)"
        _ssudo="$(suspicious_sudoers_lines | sed -n '1,200p')"
        if [ -n "${_ssudo}" ]; then while read -r l; do report "ATTN  $l"; done <<< "${_ssudo}"; alert "suspicious sudoers policy"; else report "OK  No suspicious sudoers entries"; fi
        report ""

        report "### Suspicious crontab lines (curl/wget/nc/bash -i/dev/tcp/python -c)"
        _scron="$(suspicious_cron_lines | sed -n '1,200p')"
        if [ -n "${_scron}" ]; then while read -r l; do report "ATTN  $l"; done <<< "${_scron}"; alert "suspicious cron entries"; else report "OK  No suspicious cron entries"; fi
        report ""

        if [ -s "$BL_LSMOD" ]; then
                now_lsm="$BASE/tmp/lsmod.now"; lsmod_now > "$now_lsm" 2>/dev/null || true
                d="$(diff -u "$BL_LSMOD" "$now_lsm" || true)"
                if [ -n "$d" ]; then
                        report "### DIFF kernel modules (names)"
                        printf "%s\n" "$d" | while IFS= read -r l; do report "$l"; done
                        alert "kernel modules changed"
                        report ""
                else
                        report "OK  Kernel module set unchanged"
                        report ""
                fi
        fi

        # Discord summary + body
        mods_ct=$(printf "%s" "${modified:-}" | grep -c . || true)
        dels_ct=$(printf "%s" "${deleted:-}"  | grep -c . || true)
        news_ct=$(wc -l < "$BASE/tmp/new-files.txt" 2>/dev/null || echo 0)
        suid_ct=$(awk '($2=="MISSING"||$6=="MISSING"||$2$3$4$5 != $6$7$8$9){c++} END{print c+0}' "$BASE/tmp/suid.joined" 2>/dev/null || echo 0)
        status_emoji=$([ "$ALERT_FLAG" -eq 0 ] && echo "✅" || echo "🚨")
        summary="${status_emoji} ${HOST} hostguard ${TS} — mods:${mods_ct} new:${news_ct} del:${dels_ct} suidΔ:${suid_ct} window:${MINS}m"
        post_discord_text "$summary"

        if [ -n "$OUT" ] && [ -s "$OUT" ]; then
                post_discord_file "$OUT"
        else
                post_discord_text "$REPORT_CONTENT"
        fi
}

if [ "$CMD" = "--init" ]; then
        [ -n "$OUT" ] && : > "$OUT"
        init_baseline
elif [ "$CMD" = "--check" ]; then
        check_now
fi
