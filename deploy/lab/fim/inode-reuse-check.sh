#!/bin/bash
# Review 57 regression check (`nn-lab.sh fim-reuse-check`), run in a lab
# guest with the agent running.
#
# A file dropped in a watched directory is enrolled in WATCHED_PATHS by
# its inode (BUG-022). Once it is deleted the filesystem reuses the inode
# number for an unrelated file: a write to that file must not reach the
# FIM rules under the deleted path (it used to, and FIM-007 killed the
# writer, e.g. a compiler).
set -u
W=/etc/cron.d/nn-reuse-check
fail=0
journal() { sudo journalctl --namespace=northnarrow -u northnarrow-agent --no-pager --since "$1" | grep -v "process spawn detected"; }

mark=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
# The drop is a rename into the watched directory: the event fires once the
# file is complete, so the drain always enrolls its inode (a create event
# can be handled before the file exists, and then nothing is enrolled).
# FIM-007 kills the moving process; the file stays.
sudo sh -c "echo '# nn reuse check' > /var/tmp/.nn-reuse-src" && sudo sh -c "mv /var/tmp/.nn-reuse-src $W" 2>/dev/null
sleep 2
ino=$(sudo stat -c %i "$W" 2>/dev/null)
dev=$(sudo stat -c %d "$W" 2>/dev/null)
[[ -n $ino ]] || { echo "FAIL  could not create $W"; exit 1; }
sudo rm -f "$W"
sleep 2
# Same filesystem as /etc on the lab guests. Files go straight into /tmp,
# as a compiler's temporaries do: ext4 allocates in the parent directory's
# block group, and a fresh subdirectory would land in another one.
pfx="/tmp/nn-reuse-$$"
hit=""
for i in $(seq 1 2000); do
    f="$pfx-$i"
    sudo sh -c ": > '$f'"
    if [[ $(sudo stat -c %i "$f") == "$ino" && $(sudo stat -c %d "$f") == "$dev" ]]; then
        hit=$f
        break
    fi
done
cleanup() { sudo sh -c "rm -f $pfx-*"; }
if [[ -z $hit ]]; then
    echo "SKIP  inode $ino not reused within 2000 files"
    cleanup
    exit 0
fi
echo "      inode $ino of the deleted $W is now $hit"
sudo sh -c "echo appended >> '$hit'"
sleep 3
out=$(sudo cat "$hit" 2>/dev/null)
cleanup
if journal "$mark" | grep -q "path=$W op=Modified"; then
    echo "FAIL  the write to $hit reached the FIM rules as a modification of the deleted $W"
    fail=1
elif [[ $out != "appended" ]]; then
    echo "FAIL  the append to $hit did not complete (writer killed?)"
    fail=1
else
    echo "PASS  the write to the reused inode was not attributed to the deleted watched file"
fi
exit $fail
