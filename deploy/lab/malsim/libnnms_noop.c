/* Lab PR 226 (benign, deploy/lab/malsim/exec-check.sh, MS-32): a shared
 * object whose constructor does nothing. Preloaded into a service from
 * /tmp, it shows whether the exec policy refuses the exec (LD_PRELOAD into
 * a staging path) and records the executable mapping when the string
 * check is side-stepped (`//tmp/...`). It never touches anything. */
__attribute__((constructor)) static void nn_ms_noop(void) {}
