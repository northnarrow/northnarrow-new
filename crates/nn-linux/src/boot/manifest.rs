//! The sensors' attach points the boot's capability manifest lists (lab PR
//! 218), noted by the eBPF loader and the sensors as they attach (Wave 4
//! restructure, R09b, lab PR 254: cut verbatim from the agent's
//! `boot::manifest`, which re-exports them and signs the manifest).

use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// One sensor and where it is attached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorEntry {
    pub sensor: String,
    pub attach: String,
}

/// The attach points of one eBPF object's sensors (R11c, lab PR 264: the
/// multiplexer that loads the object makes it, the loader and the sensors
/// note into it as they attach, the start's FIM phase notes the file-open
/// sensor's move and the run phase's manifest lists them; it was a
/// process-wide `SENSORS` with free `note_sensor` / `sensors`).
#[derive(Clone, Debug, Default)]
pub struct AttachPoints(Arc<Mutex<Vec<SensorEntry>>>);

impl AttachPoints {
    /// None noted yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// `sensor` is attached at `attach` (a later note for the same sensor
    /// replaces it: the file-open sensor moves from the tracepoint to LSM
    /// `file_open` once its observer is armed).
    pub fn note(&self, sensor: &str, attach: &str) {
        let mut s = self.0.lock();
        match s.iter_mut().find(|e| e.sensor == sensor) {
            Some(e) => e.attach = attach.to_string(),
            None => s.push(SensorEntry {
                sensor: sensor.to_string(),
                attach: attach.to_string(),
            }),
        }
    }

    /// The sensors noted so far, in the order first noted.
    pub fn list(&self) -> Vec<SensorEntry> {
        self.0.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A later note moves a sensor; the object's own list holds only what
    /// was noted into it (R11c: no other test's sensors to filter out).
    #[test]
    fn a_later_note_moves_a_sensor() {
        let points = AttachPoints::new();
        points.note("exec", "lsm:bprm_check_security");
        points.note("file_open", "tracepoint:syscalls/sys_enter_openat");
        points.clone().note("file_open", "lsm:file_open");
        assert_eq!(
            points.list(),
            [
                SensorEntry {
                    sensor: "exec".to_string(),
                    attach: "lsm:bprm_check_security".to_string(),
                },
                SensorEntry {
                    sensor: "file_open".to_string(),
                    attach: "lsm:file_open".to_string(),
                },
            ]
        );
        assert!(
            AttachPoints::new().list().is_empty(),
            "another object's own"
        );
    }
}
