//! Versioned progress/control protocol. Never emits paths, URLs or credentials.
use super::ProgressEvent;
use std::{
    collections::HashMap,
    io::{BufRead, Write},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

pub(super) fn controls(
    enabled: bool,
    events: mpsc::Sender<ProgressEvent>,
) -> watch::Receiver<bool> {
    let (tx, rx) = watch::channel(false);
    if enabled {
        // A plain thread avoids Tokio's uncancellable blocking-stdin shutdown.
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            let mut bytes = Vec::new();
            loop {
                bytes.clear();
                // Bound control records; discard overlong lines without parsing.
                let result = std::io::Read::take(std::io::Read::by_ref(&mut reader), 257)
                    .read_until(b'\n', &mut bytes);
                if !matches!(result, Ok(n) if n > 0) {
                    break;
                }
                if bytes.len() > 256 {
                    if bytes.last() != Some(&b'\n') {
                        reader.skip_until(b'\n').ok();
                    }
                    continue;
                }
                if let Some(kib) = parse_download_limit(&bytes) {
                    msixvc::bandwidth::set_limit_kib(kib);
                } else if let Some(paused) = parse_control(&bytes) {
                    if *tx.borrow() == paused {
                        continue;
                    }
                    if tx.send(paused).is_err() {
                        return;
                    }
                    if events
                        .blocking_send(ProgressEvent::Paused { paused })
                        .is_err()
                    {
                        return;
                    }
                }
            }
            // Losing the controller must never leave a live download parked.
            if *tx.borrow() {
                tx.send(false).ok();
                events
                    .blocking_send(ProgressEvent::Paused { paused: false })
                    .ok();
            }
        });
    } else {
        drop(tx);
    }
    rx
}

fn parse_download_limit(bytes: &[u8]) -> Option<u32> {
    if bytes.len()>256 {return None;}
    let value:serde_json::Value=serde_json::from_slice(bytes).ok()?;
    if value["schema"]!=1 || value["command"]!="set-download-limit" {return None;}
    let kib=value["kibPerSecond"].as_u64()?;
    (kib<=1_048_576).then_some(kib as u32)
}
#[cfg(test)]
#[test]
fn streaming_bandwidth_controls_validate_units_and_never_interpret_pause_as_a_limit() {
    for kib in [0,1,512,1_048_576] {assert_eq!(parse_download_limit(format!(r#"{{"schema":1,"command":"set-download-limit","kibPerSecond":{kib}}}"#).as_bytes()),Some(kib));}
    for raw in [r#"{"schema":1,"command":"pause"}"#,r#"{"schema":2,"command":"set-download-limit","kibPerSecond":1}"#,r#"{"schema":1,"command":"set-download-limit","kibPerSecond":-1}"#,r#"{"schema":1,"command":"set-download-limit","kibPerSecond":1.5}"#,r#"{"schema":1,"command":"set-download-limit","kibPerSecond":1048577}"#] {assert_eq!(parse_download_limit(raw.as_bytes()),None);}
}
fn parse_control(bytes: &[u8]) -> Option<bool> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value["schema"] != 1 {
        return None;
    }
    match value["command"].as_str()? {
        "pause" => Some(true),
        "resume" => Some(false),
        _ => None,
    }
}

#[derive(Default)]
struct State {
    completed: u64,
    total: Option<u64>,
    phase: &'static str,
    paused: bool,
    files: HashMap<usize, (u64, u64)>,
}

impl State {
    fn apply(&mut self, event: ProgressEvent) -> bool {
        match event {
            ProgressEvent::Started { id, total, .. } => {
                self.files.insert(id, (0, total));
            }
            ProgressEvent::Advanced { id, delta } => {
                if self.phase == "downloading" {
                    if let Some((position, total)) = self.files.get_mut(&id) {
                        let next = position.saturating_add(delta).min(*total);
                        self.completed = self.completed.saturating_add(next - *position);
                        *position = next;
                    }
                }
            }
            ProgressEvent::Finished { id } => {
                if let Some((position, total)) = self.files.remove(&id) {
                    // A full progress channel can coalesce the last byte update.
                    self.completed = self.completed.saturating_add(total - position);
                }
            }
            ProgressEvent::UpdateRemaining { total, .. } => {
                self.phase = "downloading";
                self.total = Some(total);
                self.completed = 0;
                return true;
            }
            ProgressEvent::UpdateStatus { name } => {
                self.phase = if name == "Finalizing" {
                    "finalizing"
                } else {
                    "metadata"
                };
                return true;
            }
            ProgressEvent::Paused { paused } => {
                self.paused = paused;
                return true;
            }
            ProgressEvent::Completed { success } => {
                self.phase = if success { "complete" } else { "failed" };
                return true;
            }
        }
        false
    }

    fn record(&self, sequence: u64, rate: u64) -> serde_json::Value {
        serde_json::json!({
            "schema": 1, "event": "progress", "sequence": sequence,
            "phase": self.phase, "paused": self.paused,
            "canPause": self.phase == "downloading",
            "completedBytes": self.completed, "totalBytes": self.total,
            "bytesPerSecond": rate,
        })
    }
}

pub(super) async fn report(mut events: mpsc::Receiver<ProgressEvent>) {
    let mut state = State {
        phase: "initializing",
        ..Default::default()
    };
    let mut sequence = 0;
    let mut last = Instant::now();
    let mut previous = 0;
    emit(&state, sequence, 0);
    while let Some(event) = events.recv().await {
        let transition = state.apply(event);
        let elapsed = last.elapsed();
        if transition || elapsed >= Duration::from_millis(200) {
            let rate = if state.paused {
                0
            } else {
                (state.completed.saturating_sub(previous) as f64 / elapsed.as_secs_f64().max(0.001))
                    as u64
            };
            sequence += 1;
            emit(&state, sequence, rate);
            last = Instant::now();
            previous = state.completed;
        }
        if matches!(state.phase, "complete" | "failed") {
            break;
        }
    }
}

fn emit(state: &State, sequence: u64, rate: u64) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // Explicit prefix isolates the protocol from any ordinary CLI log output.
    writeln!(out, "NEXUS_PROGRESS {}", state.record(sequence, rate)).ok();
    out.flush().ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_progress_counts_files_once_and_reconciles_coalesced_tail() {
        let mut state = State::default();
        state.apply(ProgressEvent::UpdateRemaining {
            name: "Downloading".into(),
            total: 100,
        });
        state.apply(ProgressEvent::Started {
            id: 1,
            name: "private path".into(),
            total: 100,
        });
        state.apply(ProgressEvent::Advanced {
            id: usize::MAX,
            delta: 9999,
        });
        state.apply(ProgressEvent::Advanced { id: 1, delta: 30 });
        assert_eq!(state.completed, 30);
        state.apply(ProgressEvent::Finished { id: 1 });
        state.apply(ProgressEvent::Finished { id: 1 });
        assert_eq!(state.completed, 100);
        assert!(!state.record(1, 2).to_string().contains("private path"));
    }
    #[test]
    fn streaming_progress_preserves_real_failure_and_control_contract() {
        assert_eq!(
            parse_control(br#"{"schema":1,"command":"pause"}"#),
            Some(true)
        );
        assert_eq!(
            parse_control(br#"{"schema":1,"command":"resume"}"#),
            Some(false)
        );
        assert_eq!(parse_control(br#"{"schema":2,"command":"pause"}"#), None);
        let mut state = State {
            completed: 30,
            total: Some(100),
            ..Default::default()
        };
        state.apply(ProgressEvent::Completed { success: false });
        assert_eq!(state.record(2, 0)["phase"], "failed");
        assert_eq!(state.completed, 30);
    }
}
