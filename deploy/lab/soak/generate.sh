#!/usr/bin/env bash
# deploy/lab/soak/generate.sh — synthetic, benign host activity for the
# soak test (runs ON THE GUEST, started by `nn-lab.sh soak start`).
#
# Steady, moderate load that touches every sensor without tripping a
# response rule: execs of standard-path binaries, file create/modify/
# rename/delete in an unwatched scratch dir plus reads of a watched
# system file, TCP requests to a local HTTP listener, UDP datagrams to
# localhost, DNS lookups of a fixed set of names. Rates per second are
# tunable through SOAK_* env vars. Stops when $SOAK_DIR/stop exists.
set -u
SOAK_DIR=${SOAK_DIR:-$HOME/soak}
SCRATCH=${SOAK_SCRATCH:-/var/tmp/nn-soak}
EXEC_PER_S=${SOAK_EXEC_PER_S:-20}
FILE_PER_S=${SOAK_FILE_PER_S:-10}
TCP_PER_S=${SOAK_TCP_PER_S:-5}
UDP_PER_S=${SOAK_UDP_PER_S:-5}
DNS_PER_S=${SOAK_DNS_PER_S:-1}
HTTP_PORT=${SOAK_HTTP_PORT:-18080}
UDP_PORT=${SOAK_UDP_PORT:-18081}
mkdir -p "$SOAK_DIR" "$SCRATCH"
echo "$$" > "$SOAK_DIR/generate.pid"

# local HTTP listener (python3 is on every guest template)
( cd "$SCRATCH" && exec python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
HTTP_PID=$!
# local UDP sink
( exec python3 -c "
import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',$UDP_PORT))
while True: s.recv(65535)
" >/dev/null 2>&1 ) &
UDP_PID=$!
trap 'kill $HTTP_PID $UDP_PID 2>/dev/null; rm -f "$SOAK_DIR/generate.pid"; exit 0' EXIT INT TERM

iter=0
names=(localhost example.com example.org example.net)
while [ ! -e "$SOAK_DIR/stop" ]; do
    t0=$(date +%s%N)
    # execs: standard-path binaries only (R001/R003/R017 must stay quiet)
    for _ in $(seq 1 "$EXEC_PER_S"); do /bin/true; done
    # files: create / append / rename / delete in the scratch dir, one read of a watched file
    for i in $(seq 1 "$FILE_PER_S"); do
        f="$SCRATCH/f.$iter.$i"
        printf 'soak %s\n' "$iter" > "$f"; printf 'more\n' >> "$f"; mv "$f" "$f.r"; rm -f "$f.r"
    done
    cat /etc/passwd > /dev/null
    # tcp: short HTTP requests to the local listener
    for _ in $(seq 1 "$TCP_PER_S"); do curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$HTTP_PORT/" || true; done
    # udp: datagrams to the local sink
    for _ in $(seq 1 "$UDP_PER_S"); do printf 'soak' > "/dev/udp/127.0.0.1/$UDP_PORT" 2>/dev/null || true; done
    # dns: a fixed, small set (slirp resolver on the lab guest)
    for i in $(seq 1 "$DNS_PER_S"); do getent hosts "${names[$(( (iter + i) % ${#names[@]} ))]}" >/dev/null 2>&1 || true; done
    iter=$((iter + 1))
    echo "$iter" > "$SOAK_DIR/generate.iter"
    # pace to ~1 s per iteration
    el=$(( ($(date +%s%N) - t0) / 1000000 ))
    [ "$el" -lt 1000 ] && sleep "0.$(printf '%03d' $((1000 - el)))"
done
