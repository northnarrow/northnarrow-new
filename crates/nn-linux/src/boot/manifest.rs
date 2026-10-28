//! The sensors' attach points the boot's capability manifest lists (lab PR
//! 218), noted by the eBPF loader and the sensors as they attach (Wave 4
//! restructure, R09b, lab PR 254: cut verbatim from the agent's
//! `boot::manifest`, which re-exports them and signs the manifest).

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// One sensor and where it is attached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorEntry {
    pub sensor: String,
    pub attach: String,
}

static SENSORS: Mutex<Vec<SensorEntry>> = Mutex::new(Vec::new());

/// `sensor` is attached at `attach` (a later note for the same sensor
/// replaces it: the file-open sensor moves from the tracepoint to LSM
/// `file_open` once its observer is armed).
pub fn note_sensor(sensor: &str, attach: &str) {
    let mut s = SENSORS.lock();
    match s.iter_mut().find(|e| e.sensor == sensor) {
        Some(e) => e.attach = attach.to_string(),
        None => s.push(SensorEntry {
            sensor: sensor.to_string(),
            attach: attach.to_string(),
        }),
    }
}

/// The sensors noted so far.
pub fn sensors() -> Vec<SensorEntry> {
    SENSORS.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_later_note_moves_a_sensor() {
        note_sensor("test_sensor_x", "tracepoint:syscalls/sys_enter_openat");
        note_sensor("test_sensor_x", "lsm:file_open");
        let s: Vec<_> = sensors()
            .into_iter()
            .filter(|e| e.sensor == "test_sensor_x")
            .collect();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].attach, "lsm:file_open");
    }
}
