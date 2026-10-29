#!/usr/bin/env bash
# =============================================================================
# Read-only Linux live-response triage collector (RFC 3227 order of volatility)
#   sudo ./linux_triage.sh /mnt/usb/IR-2026-1027 "X. West" IR-2026-1027
# Outputs host.json, processes.json, network.json, scheduled_tasks.json (cron + systemd timers),
# services.json, autoruns.json (shell rc, authorized_keys, ld.so.preload), events.json (auth/sudo),
# raw/ (copies of logs), collection.log, SHA256SUMS. Makes no changes to the system.
# Author: Xiome West | License: MIT
# =============================================================================
set -uo pipefail
OUTROOT="${1:?usage: $0 <output_root> [examiner] [case_id]}"; EXAMINER="${2:-$USER}"; CASE="${3:-UNSPECIFIED}"
HOST=$(hostname -f 2>/dev/null || hostname); OUT="$OUTROOT/$HOST"; mkdir -p "$OUT/raw"
log(){ echo "$(date -u +%FT%TZ)  $*" >> "$OUT/collection.log"; }
log "Case $CASE | examiner $EXAMINER | host $HOST | start"

# 1. Volatile: processes (with exe hash and deleted-binary flag) and sockets
python3 - "$OUT" <<'PY'
import hashlib, json, os, pwd, sys
out = sys.argv[1]; procs = []
for pid in filter(str.isdigit, os.listdir('/proc')):
    try:
        st = open(f'/proc/{pid}/stat').read().split(')')[-1].split()
        cmd = open(f'/proc/{pid}/cmdline','rb').read().replace(b'\0', b' ').decode(errors='replace').strip()
        exe = os.readlink(f'/proc/{pid}/exe') if os.path.exists(f'/proc/{pid}/exe') else ''
        uid = os.stat(f'/proc/{pid}').st_uid
        sha = ''
        try: sha = hashlib.sha256(open(f'/proc/{pid}/exe','rb').read()).hexdigest()
        except Exception: pass
        procs.append({"ProcessId": int(pid), "ParentProcessId": int(st[1]), "Path": exe, "CommandLine": cmd,
                      "User": pwd.getpwuid(uid).pw_name, "SHA256": sha, "DeletedBinary": exe.endswith('(deleted)')})
    except Exception:
        continue
json.dump(procs, open(f'{out}/processes.json','w'), indent=1)
PY
log "processes saved"
ss -tunapH 2>/dev/null | awk '{split($5,l,":"); split($6,r,":"); match($0,/pid=[0-9]+/); print l[1]"|"l[length(l)]"|"r[1]"|"r[length(r)]"|"$2"|"substr($0,RSTART+4,RLENGTH-4)}' \
 | python3 -c "import sys,json;print(json.dumps([dict(zip(['LocalAddress','LocalPort','RemoteAddress','RemotePort','State','OwningProcess'],l.strip().split('|'))) for l in sys.stdin],indent=1))" > "$OUT/network.json"
log "network saved"

# 2. Host context
python3 -c "import json,socket,platform,datetime;print(json.dumps({'hostname':socket.getfqdn(),'os':' '.join(platform.uname()[0:3]),
'collected_utc':datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),'collected_by':'$EXAMINER ($CASE)','timezone':'$(cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null)'}))" > "$OUT/host.json"

# 3. Persistence
{ for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$f" ] && grep -vE '^\s*(#|$)' "$f" | sed "s|^|$f\t|"; done
  systemctl list-timers --all --no-legend 2>/dev/null | sed 's|^|systemd-timer\t|'; } \
 | python3 -c "import sys,json;print(json.dumps([{'TaskName':l.split('\t')[0],'Action':l.split('\t',1)[1].strip(),'Author':''} for l in sys.stdin if '\t' in l],indent=1))" > "$OUT/scheduled_tasks.json"
systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1"|"$2}' \
 | python3 -c "import sys,json,subprocess;print(json.dumps([{'Name':n,'StartMode':m,'PathName':subprocess.run(['systemctl','show','-p','ExecStart','--value',n],capture_output=True,text=True).stdout.strip()[:300]} for n,m in (l.strip().split('|') for l in sys.stdin)],indent=1))" > "$OUT/services.json"
{ for f in /etc/ld.so.preload /etc/profile /etc/bash.bashrc /root/.bashrc /home/*/.bashrc /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /etc/rc.local; do
    [ -f "$f" ] && echo -e "$f\t$(sha256sum "$f" | cut -d' ' -f1)\t$(stat -c %y "$f")"; done; } \
 | python3 -c "import sys,json;print(json.dumps([dict(zip(['Location','Value','Name'],l.rstrip().split('\t'))) for l in sys.stdin],indent=1))" > "$OUT/autoruns.json"
log "persistence saved"

# 4. Logs (copied raw + normalized auth events)
for f in /var/log/auth.log* /var/log/secure* /var/log/syslog /var/log/messages /var/log/audit/audit.log; do [ -f "$f" ] && cp -p "$f" "$OUT/raw/"; done
journalctl -o short-iso --since "-72h" _COMM=sshd _COMM=sudo _COMM=useradd _COMM=usermod 2>/dev/null > "$OUT/raw/journal_auth.txt"
echo "[]" > "$OUT/events.json"    # Linux auth events: analyze raw/ with Project 01 triage.py
find / -xdev \( -path /proc -o -path /sys \) -prune -o -type f -newermt "-3 days" \( -path '/tmp/*' -o -path '/dev/shm/*' -o -path '/var/tmp/*' -o -path '/etc/*' -o -path '/usr/bin/*' -o -path '/usr/local/bin/*' \) -print 2>/dev/null \
  | head -5000 | while read -r f; do echo -e "$(stat -c '%y' "$f")\t$(sha256sum "$f" | cut -d' ' -f1)\t$f"; done > "$OUT/raw/recent_files.tsv"
log "logs and recent files saved"

# 5. Integrity manifest
( cd "$OUT" && sha256sum *.json > SHA256SUMS && find raw -type f -exec sha256sum {} + > raw/SHA256SUMS )
log "SHA256SUMS written | end"
echo "[+] Triage package: $OUT"
