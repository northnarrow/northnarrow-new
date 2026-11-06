#!/usr/bin/env bash
# Lot 283a — benign corpus: a database server. PostgreSQL installed from the
# distribution (its own cluster created and started by the package), a
# second cluster made with pg_createcluster (initdb), pgbench -i and a 60 s
# run, pg_dump and pg_restore into a new database; then the host's own
# upkeep: an apt upgrade of the upgradable packages outside the kernel,
# boot, libc and systemd set (at most 15), unattended-upgrade in dry-run,
# the logrotate service, and a cron job (postgres's crontab and a
# /etc/cron.d drop-in) seen running once. Lab guests only; see
# corpus-lib.sh and docs/validation/BENIGN_CORPUS.md.
# usage: db-server.sh
set -u
here=${BASH_SOURCE[0]%/*}
[[ $here == "${BASH_SOURCE[0]}" ]] && here=.
# shellcheck source=corpus-lib.sh
. "$here/corpus-lib.sh"
corpus_init db
CRON=/etc/cron.d/nn-corpus-db

corpus_cleanup() {
    sudo rm -f "$CRON"
    sudo crontab -u postgres -r 2>/dev/null
    local v
    v=$(ls /usr/lib/postgresql 2>/dev/null | sort -n | tail -1)
    [[ -n $v ]] && sudo pg_dropcluster --stop "$v" nncorpus 2>/dev/null
    sudo -u postgres dropdb --if-exists nncorpus_restore 2>/dev/null
    sudo -u postgres dropdb --if-exists nncorpus 2>/dev/null
    sudo rm -rf "$W"
    sudo rmdir /srv/nn-corpus 2>/dev/null
    if [[ " $INSTALLED " == *" postgresql "* ]]; then
        sudo systemctl stop postgresql >/dev/null 2>&1
        corpus_purge
        sudo rm -rf /var/lib/postgresql /etc/postgresql /etc/postgresql-common /var/log/postgresql
    else
        corpus_purge
    fi
    sudo rm -f /var/tmp/nn-corpus-cron.stamp
    true
}

echo "== prepare (not measured)"
sudo apt-get update -qq >/dev/null 2>&1
# the install is measured: only what it needs before is prepared
pg_new=0
dpkg-query -W -f='${db:Status-Abbrev}' postgresql 2>/dev/null | grep -q '^ii' || pg_new=1

echo "== measure"
corpus_settle
corpus_mark
if ((pg_new)); then
    step "db apt-get install postgresql" 900 -- sudo apt-get install -y -qq postgresql postgresql-contrib
    if dpkg-query -W -f='${db:Status-Abbrev}' postgresql 2>/dev/null | grep -q '^ii'; then
        INSTALLED="$INSTALLED postgresql postgresql-contrib"
        echo "$INSTALLED" > "$STATE"
    fi
fi
V=$(ls /usr/lib/postgresql 2>/dev/null | sort -n | tail -1)
PGB=/usr/lib/postgresql/$V/bin
step "db pg_createcluster (initdb) + start" 300 -- sudo pg_createcluster "$V" nncorpus -p 5444 --start
step "db createdb" 60 -- sudo -u postgres createdb -p 5444 nncorpus
step "db pgbench -i -s 20" 600 -- sudo -u postgres "$PGB/pgbench" -p 5444 -i -q -s 20 nncorpus
step "db pgbench 60 s, 4 clients" 180 -- sudo -u postgres "$PGB/pgbench" -p 5444 -c 4 -j 2 -T 60 nncorpus
sudo install -d -o postgres -g postgres "$W/pg"
step "db pg_dump -Fc" 300 -- sudo -u postgres pg_dump -p 5444 -Fc -f "$W/pg/nncorpus.dump" nncorpus
step "db createdb + pg_restore" 600 -- sudo -u postgres bash -c "createdb -p 5444 nncorpus_restore && pg_restore -p 5444 -d nncorpus_restore $W/pg/nncorpus.dump"
step "db vacuumdb --analyze" 300 -- sudo -u postgres vacuumdb -p 5444 --analyze nncorpus_restore
up=$(apt list --upgradable 2>/dev/null | awk -F/ 'NR > 1 {print $1}' |
    grep -vE '^(linux|systemd|libsystemd|udev|libudev|libc6|libc-|libc6-|grub|shim|openssh|cloud-init|snapd|dbus|libpam|initramfs|ubuntu-|base-files|apparmor|libapparmor|kmod|util-linux|mount)' | head -15 | tr '\n' ' ')
if [[ -n $up ]]; then
    # shellcheck disable=SC2086
    echo "  upgradable outside the excluded set: $up"
    step "db apt-get install --only-upgrade ($(wc -w <<< "$up") packages)" 900 -- sudo apt-get install -y -qq --only-upgrade $up
else
    echo "  (no upgradable package outside the excluded set)"
fi
# a dpkg trigger's update-initramfs, whatever was upgradable (lot 283b):
# its hooks run from forks of mkinitramfs
step "db apt-get install --reinstall initramfs-tools (update-initramfs trigger)" 900 -- sudo apt-get install -y -qq --reinstall initramfs-tools
if command -v unattended-upgrade >/dev/null; then
    step "db unattended-upgrade --dry-run" 600 -- sudo unattended-upgrade --dry-run
fi
step "db logrotate.service" 300 -- sudo systemctl start logrotate.service
# a cron job: postgres's crontab (crontab(1)), then a drop-in as an
# operator installs one; each seen running once
step "db crontab -u postgres (vacuumdb every minute)" 60 -- bash -c "echo '* * * * * vacuumdb -p 5444 -q nncorpus_restore' | sudo crontab -u postgres -"
step "db /etc/cron.d drop-in (install -m 644)" 60 -- bash -c "printf '* * * * * root touch /var/tmp/nn-corpus-cron.stamp\n' > $W/cron && sudo install -m 644 -o root -g root $W/cron $CRON"
step "db the cron job runs (≤ 130 s)" 140 -- bash -c 'until [ -e /var/tmp/nn-corpus-cron.stamp ]; do sleep 5; done'
corpus_finish
