//! Fixed synthetic input on this invocation's directly owned VM. Observed
//! scanout and cold bytes are evidence; actions never stand for human consent.
use crate::{
    build,
    qmp::{Key, Qmp},
};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
pub(super) const TEXT: &str = "hello workspace";
#[derive(Debug, Clone, Copy, Serialize)]
enum Action {
    Move {
        dx: i16,
        dy: i16,
    },
    Button(bool),
    Byte(u8),
    Enter(bool),
    Escape(bool),
    Right(bool),
    Backspace(bool),
    ReleasedShutdownConfirm,
    ReleasedRestartConfirm,
    AwaitPowerReady {
        restart: bool,
        require_release: bool,
    },
    Capture {
        index: u32,
        label: &'static str,
    },
    AwaitView {
        pane: u8,
        status: &'static str,
        name: &'static str,
        row: i8,
        root_rights: Option<bool>,
    },
    AwaitLabel {
        x: u16,
        y: u16,
        label: &'static str,
    },
    RememberRootBinding,
    AwaitRootBindingUnchanged,
    AwaitRootBindingChanged,
}
#[derive(Debug, Clone, Copy, Serialize)]
struct Step {
    at_ms: u64,
    action: Action,
}
pub(super) struct Scenario {
    steps: Vec<Step>,
    next: usize,
    observed: Vec<serde_json::Value>,
    decoder: PathBuf,
    delay_ms: u64,
    waiting: Option<(u64, u64, u8)>,
    gate_capture: u32,
    a1: bool,
    large: bool,
    large_finite: bool,
    legacy: bool,
    shutdown: bool,
    own: bool,
    reader: bool,
    restart: bool,
    reopened: bool,
    root_binding: Option<String>,
    power_pacing: Option<PowerPacing>,
}
struct PowerPacing {
    serial: PathBuf,
    build: String,
    nonce: Option<u64>,
}
struct Plan {
    steps: Vec<Step>,
    at: u64,
    x: i16,
    y: i16,
    capture: u32,
}
impl Plan {
    fn step(&mut self, a: Action) {
        self.steps.push(Step {
            at_ms: self.at,
            action: a,
        });
    }
    fn wait(&mut self, ms: u64) {
        self.at += ms;
    }
    fn capture(&mut self, label: &'static str) {
        self.step(Action::Capture {
            index: self.capture,
            label,
        });
        self.capture += 1;
        self.wait(100);
    }
    fn move_to(&mut self, x: i16, y: i16) {
        while self.x != x || self.y != y {
            let dx = (x - self.x).clamp(-64, 64);
            let dy = (y - self.y).clamp(-64, 64);
            self.step(Action::Move { dx, dy });
            self.x += dx;
            self.y += dy;
            self.wait(120);
        }
    }
    fn click(&mut self, x: i16, y: i16) {
        self.move_to(x, y);
        self.step(Action::Button(true));
        self.wait(200);
        self.step(Action::Button(false));
        self.wait(200);
    }
    fn text(&mut self, text: &str) {
        for b in text.bytes() {
            self.step(Action::Byte(b));
            self.wait(200);
            self.capture("after-single-PS2-character");
        }
    }
    fn enter(&mut self) {
        self.step(Action::Enter(true));
        self.wait(150);
        self.step(Action::Enter(false));
        self.wait(150);
    }
    fn escape(&mut self) {
        self.step(Action::Escape(true));
        self.wait(150);
        self.step(Action::Escape(false));
        self.wait(150);
    }
    fn replace_last_scalar(&mut self) {
        // Editor::open places the caret at EOF. A body click focuses the
        // surface; it currently performs no pixel-to-caret mapping. Right is
        // an explicit released EOF no-op, then Backspace/Z replaces the end.
        self.step(Action::Right(true));
        self.wait(150);
        self.step(Action::Right(false));
        self.wait(150);
        self.step(Action::Backspace(true));
        self.wait(150);
        self.step(Action::Backspace(false));
        self.wait(150);
        self.text("Z");
    }
    fn await_label(&mut self, x: u16, y: u16, label: &'static str) {
        assert!(!label.is_empty() && label.len() <= 60 && label.is_ascii());
        assert!(usize::from(x) + (label.len() + 1) * 6 <= 640 && y + 7 <= 480);
        self.step(Action::AwaitLabel { x, y, label });
        self.wait(100);
    }
    fn inspector_stats(&mut self) {
        self.await_label(322, 454, "Sampled resource data");
    }
    fn editor_nodes(&mut self, count: usize) {
        let names = [
            "Editor",
            "File actions",
            "Open",
            "Save",
            "Save As",
            "Close",
            "Document",
            "Saved",
            "File name",
        ];
        for (index, name) in names.iter().enumerate().take(count + 1).skip(1) {
            self.click(387, 292); // Next, through the current Inspector view.
            self.await_label(322, 347 + (index % 6) as u16 * 18, name);
        }
    }
    fn request_semantic_review(&mut self) {
        self.text("a");
        self.await_label(322, 346, "Press Root Controls/Esc to review access");
        self.escape();
        self.await_label(2, 11, "Approve exact Inspector semantic access");
        self.await_label(420, 31, "Editor1");
        self.await_label(284, 41, "READ1 ACTION0 TEXT0 CONFIRM0");
    }
    fn a1_extension(&mut self) {
        // Focus is a separate edge from the attention request. The initial
        // pointer is retained from files-basic rather than guessed anew.
        self.click(610, 454);
        self.inspector_stats();
        self.request_semantic_review();
        self.click(440, 75);
        self.await_label(322, 347, "Editor");
        self.editor_nodes(8);
        self.text("n");
        self.await_label(321, 344, "note1");
        self.text("t"); // TEXT is unavailable under this READ-only scope.
        self.await_label(321, 344, "note1");
        self.capture("A1-READ-name-after-unavailable-TEXT-intent");
        self.text("x");
        self.inspector_stats();

        self.request_semantic_review();
        self.click(220, 75);
        self.await_label(284, 41, "READ1 ACTION0 TEXT1 CONFIRM0");
        self.click(440, 75);
        self.await_label(322, 347, "Editor");
        self.editor_nodes(6);
        self.text("t");
        self.await_label(321, 344, TEXT);
        self.capture("A1-exact-current-document-TEXT-range");
        self.text("x");
        self.inspector_stats();

        self.request_semantic_review();
        self.click(60, 75);
        self.await_label(420, 31, "Editor2");
        self.click(60, 75);
        self.await_label(420, 31, "Root protected");
        self.click(330, 75);
        self.await_label(284, 41, "READ1 ACTION1 TEXT0 CONFIRM1");
        self.click(440, 75);
        self.await_label(322, 347, "Protected Root controls and dialogs");
        self.click(220, 5); // An ordinary intent opens the actual Root picker.
        self.await_picker("Root file chooser:", "folder1", false);
        self.text("j");
        self.await_label(322, 365, "Root toolbar; Expand reads its page");
        self.text("j");
        self.await_label(322, 383, "Current Root dialog; Expand reads its page");
        self.text("e");
        self.await_label(322, 347, "Protected Root controls and dialogs");
        self.click(60, 75);
        self.await_picker("Root file chooser:", "note1", false);
        for (index, name) in [
            "Current Root dialog; Expand reads its page",
            "Current dialog title; Name reads full text",
            "Root status; Name reads the full UTF8 text",
            "Selected file name; Name reads full UTF8",
        ]
        .into_iter()
        .enumerate()
        {
            self.text("j");
            self.await_label(322, 365 + index as u16 * 18, name);
        }
        self.text("n");
        self.await_label(321, 344, "note1");
        self.text("r"); // Clear the range and obtain a fresh complete page.
        self.await_label(322, 347, "Protected Root controls and dialogs");
        for _ in 0..13 {
            self.text("j");
            self.wait(500);
        }
        self.await_label(322, 365, "Select or confirm;");
        self.await_label(322, 373, "Protected: ordinary Activate denied");
        self.step(Action::RememberRootBinding);
        self.wait(100);
        self.text("a"); // Ordinary Activate cannot create a private ticket.
        self.step(Action::AwaitRootBindingUnchanged);
        self.wait(100);
        self.await_picker("Root file chooser:", "note1", false);
        self.capture("A1-ordinary-protected-Activate-left-binding-unchanged");
        self.click(567, 312);
        self.await_picker("Confirm Open:", "note1", false);
        self.await_label(322, 347, "Protected Root controls and dialogs");
        self.capture("A1-first-dedicated-Confirm-armed-new-challenge");
        self.click(567, 312);
        self.await_view(1, "Saved", "note1", -1);
        self.capture("A1-second-distinct-Confirm-and-native-regrant-observation");
        self.click(610, 454);
        self.await_label(322, 347, "Protected Root controls and dialogs");
        self.text("x");
        self.inspector_stats();
        self.capture("A1-final-revoked-scope-returned-to-stats");
    }
    fn await_view(&mut self, pane: u8, status: &'static str, name: &'static str, row: i8) {
        self.step(Action::AwaitView {
            pane,
            status,
            name,
            row,
            root_rights: None,
        });
        self.wait(100);
    }
    fn await_picker(&mut self, title: &'static str, name: &'static str, writable: bool) {
        self.step(Action::AwaitView {
            pane: 2,
            status: title,
            name,
            row: -1,
            root_rights: Some(writable),
        });
        self.wait(100);
    }
    fn original(&mut self, private: bool) {
        self.click(220, 5);
        // The actual8x12 compositor cursor at220,5 covers long Root titles at
        // y11. Move without clicking; preserve exact unmasked glyph gates.
        self.move_to(100, 85);
        self.await_label(2, 11, "Root file chooser:");
        self.text("v");
        self.await_label(2, 11, "Original EVRO-USERS-VOL01 / local1 Notes");
        self.await_label(2, 31, "Notes");
        if private {
            self.text("v");
            self.await_label(2, 11, "Original EVRO-USERS-VOL01 / local2 Private:");
            self.await_label(2, 31, "Private");
        }
        self.await_label(152, 71, "READ ONLY");
    }
    fn original_select(&mut self, private: bool) {
        self.click(400, 75);
        self.await_label(
            2,
            11,
            if private {
                "Confirm L3 override:"
            } else {
                "Confirm original EVRO-USERS-VOL01 / local1 Notes"
            },
        );
        self.await_label(152, 71, "READ ONLY");
    }
    fn original_open(&mut self, private: bool) {
        self.original(private);
        self.original_select(private);
        self.capture("legacy-exact-original-scope-before-distinct-confirm");
        self.click(400, 75);
        self.await_view(1, "Saved", if private { "Private" } else { "Notes" }, -1);
        self.capture("legacy-native-read-and-client-digest-verification");
    }
    fn private_refusal(&mut self) {
        self.original(true);
        self.click(400, 75);
        // The initial Private title has a colon after this prefix. Refusal has
        // a space and DANGER glyphs; avoid the title's exact50-character clip.
        self.await_label(2, 11, "Original EVRO-USERS-VOL01 / local2 Private");
        self.capture("legacy-ordinary-Private-policy-refusal");
        self.escape();
        self.await_label(2, 11, "Evrosion workspace");
    }
    fn exact_revoke(&mut self, private: bool) {
        self.click(400, 145); // Actual Editor1 focus, separate from Root attention.
        self.click(610, 5);
        // Also keep the cursor out of the captured title/recipient/nonce ROI;
        // cursor disappearance must never stand in for a changed challenge.
        self.move_to(100, 85);
        let title = if private {
            "Revoke original Private READ; copied bytes remain"
        } else {
            "Revoke original Notes READ; copied bytes remain"
        };
        self.await_label(2, 11, title);
        self.await_label(306, 11, "D=4556524f2d55534552532d564f4c3031");
        self.step(Action::RememberRootBinding);
        self.click(400, 75);
        // Revoke retains its title. Observe the new presented challenge/nonce
        // before sending the second released physical confirmation.
        self.step(Action::AwaitRootBindingChanged);
        self.await_label(2, 11, title);
        self.capture("legacy-exact-revoke-challenge-before-distinct-confirm");
        self.click(400, 75);
        self.await_label(2, 23, "Exact recorded File access revoked;");
        self.capture("legacy-native-retirement-and-service-reconciliation-status");
    }
    fn shutdown_extension(&mut self, power_ready: bool) {
        const TITLE: &str = "Confirm shutdown: committed files retained";
        self.await_view(1, "Saved", "note1", -1);
        self.click(380, 5);
        self.move_to(620, 85); // Cursor cannot cover the exact protected title.
        self.await_label(2, 11, TITLE);
        if power_ready {
            self.step(Action::AwaitPowerReady {
                restart: false,
                require_release: false,
            });
            self.wait(100);
        }
        self.capture("shutdown-first-protected-prompt-before-cancel");
        self.escape();
        self.await_label(2, 11, "Evrosion workspace");
        self.await_view(1, "Saved", "note1", -1);
        self.capture("shutdown-cancel-preserved-saved-desktop");
        if power_ready {
            // New Input lifetime: establish prior-break knowledge through the
            // actual reference device outside any protected dialog. The next
            // actual post-Present barrier must report it before confirmation.
            self.step(Action::Enter(false));
            self.wait(150);
            self.capture("restart-explicit-Enter-break-before-new-protected-request");
        }
        self.click(380, 5);
        self.move_to(620, 85);
        self.await_label(2, 11, TITLE);
        if power_ready {
            self.step(Action::AwaitPowerReady {
                restart: false,
                require_release: true,
            });
            self.wait(100);
        }
        self.capture("shutdown-second-prompt-before-new-released-confirm");
        // Final command contains both released physical edges. No later
        // capture, key release or other dependent QMP action is scheduled.
        self.step(Action::ReleasedShutdownConfirm);
    }
    fn reader_extension(&mut self) {
        self.click(610, 454);
        self.inspector_stats();
        self.request_semantic_review(); // exact READ1 ACTION0 TEXT0 CONFIRM0
        self.click(440, 75);
        self.await_label(322, 347, "Editor");
        self.text("?");
        self.await_label(320, 454, "Previous node or text page");
        self.await_label(2, 23, "Inspector control ready: Previous node or text page");
        self.capture("reader-own-current-authenticated-control-before-one-Enter");
        self.enter();
        // Root reports this only after exact private reply validation and an
        // actual successful existing assistive_focus under the READ lease.
        self.await_label(2, 23, "Inspector reader action verified: Previous node");
        self.await_label(322, 383, "File name");
        self.capture("reader-own-ordinary-callback-and-repaint-after-original-ack");
        self.text("?");
        self.text("x"); // existing native revoke, no wider reader grant
        self.inspector_stats();
        self.capture("reader-own-original-read-scope-revoked-before-shutdown");
    }
    fn restart_extension(&mut self) {
        const TITLE: &str = "Confirm restart: committed files retained";
        self.await_view(1, "Saved", "note1", -1);
        self.click(500, 5);
        self.move_to(620, 85);
        self.await_label(2, 11, TITLE);
        self.step(Action::AwaitPowerReady {
            restart: true,
            require_release: true,
        });
        self.wait(100);
        self.capture("restart-first-protected-prompt-before-cancel");
        self.escape();
        self.await_label(2, 11, "Evrosion workspace");
        self.await_view(1, "Saved", "note1", -1);
        self.capture("restart-cancel-preserved-saved-desktop");
        self.click(500, 5);
        self.move_to(620, 85);
        self.await_label(2, 11, TITLE);
        self.step(Action::AwaitPowerReady {
            restart: true,
            require_release: true,
        });
        self.wait(100);
        self.capture("restart-second-prompt-before-new-released-confirm");
        self.step(Action::ReleasedRestartConfirm);
    }
    fn reopen_after_restart(&mut self) {
        self.await_view(0, "Ready", "note1", 1);
        self.capture("restart-fresh-second-boot-Files-list");
        self.click(180, 170);
        self.click(160, 121);
        self.await_picker("Root file chooser:", "folder1", false);
        self.click(60, 75);
        self.await_picker("Root file chooser:", "note1", false);
        self.click(220, 75);
        self.await_picker("Root file chooser:", "note1", true);
        self.click(400, 75);
        self.await_picker("Confirm Open:", "note1", true);
        self.capture("restart-new-boot-protected-open-before-distinct-confirm");
        self.click(400, 75);
        self.await_view(1, "Saved", "note1", -1);
        self.click(610, 454);
        self.await_label(324, 129, TEXT);
        self.capture("restart-native-reopened-exact-committed-text");
        self.shutdown_extension(true);
    }
    fn own_extension(&mut self) {
        const VERIFIED: &str = "Inspector control ready: Refresh";
        self.click(610, 454);
        self.inspector_stats();
        self.text("?");
        self.await_label(320, 454, "Refresh");
        self.await_label(2, 23, VERIFIED);
        self.capture("own-Inspector-authenticated-tree-and-current-focus");
        self.step(Action::Right(true));
        self.wait(150);
        self.step(Action::Right(false));
        self.wait(150);
        self.await_label(320, 454, "Next page");
        // One physical Enter follows the visible control promptly, even if
        // Root's exact current self-tree capture is still in flight. No retry
        // or generic old verified status can satisfy the actual page gate.
        self.enter();
        self.await_label(322, 347, "NetDriver");
        self.capture("own-Inspector-ordinary-Enter-changed-actual-stats-page");
        self.text("?");
        self.inspector_stats();

        self.click(400, 145);
        self.text("x");
        self.step(Action::Backspace(true));
        self.wait(150);
        self.step(Action::Backspace(false));
        self.wait(150);
        self.await_view(1, "Unsaved changes", "note1", -1);
        self.click(380, 5);
        self.move_to(620, 85);
        self.await_label(2, 23, "Save or recover unfinished work before shutdown;");
        self.await_label(296, 23, "no application was stopped");
        self.click(610, 454); // Hide the Editor EOF caret before exact text ROI.
        self.await_view(1, "Unsaved changes", "note1", -1);
        self.await_label(324, 129, TEXT);
        self.capture("own-Inspector-dirty-shutdown-refused-with-original-private-text");
        self.click(440, 100);
        // Return to Inspector while the actual Editor independently saves.
        // Overlap is observed from the guest, never inferred from this input.
        self.click(610, 454);
        self.inspector_stats();
        self.text("?");
        self.await_label(320, 454, "Refresh");
        self.await_label(2, 23, VERIFIED);
        self.await_view(1, "Saved", "note1", -1);
        self.capture("own-Inspector-current-tree-and-second-native-Save");
        self.text("?");
        self.inspector_stats();
    }
}
impl Scenario {
    pub(super) fn set_power_pacing(&mut self, serial: PathBuf, build: String) {
        self.power_pacing = Some(PowerPacing {
            serial,
            build,
            nonce: None,
        });
    }
    pub(super) fn legacy(root: &Path) -> Self {
        let mut p = Plan {
            steps: Vec::new(),
            at: 12_000,
            x: 320,
            y: 240,
            capture: 100,
        };
        p.await_view(0, "Ready", "", -1);
        p.click(15, 5);
        p.original(false);
        p.click(220, 75); // Unsupported legacy write intent must remain READ.
        p.await_label(152, 71, "READ ONLY");
        p.original_select(false);
        p.capture("legacy-Notes-cancel-before-grant");
        p.escape();
        p.await_label(2, 11, "Evrosion workspace");
        p.original_open(false);
        p.private_refusal();
        p.await_view(1, "Saved", "Notes", -1);
        p.click(75, 5);
        p.move_to(100, 85); // Keep the reference cursor out of the layer glyph.
        p.await_label(78, 1, "*");
        p.original_open(true);
        p.exact_revoke(true);
        p.click(15, 5);
        p.move_to(100, 85);
        p.await_label(18, 1, "*");
        p.private_refusal();
        // Reopen after the actual revoke: the old client may still hold a
        // revoked handle/private bytes, so Root must obtain real Release.
        p.original_open(false);
        p.exact_revoke(false);
        p.await_label(2, 11, "Evrosion workspace");
        p.capture("legacy-readonly-observation-complete");
        assert!(
            p.steps.len() < 768 && p.at < 180_000,
            "bounded legacy owner scenario"
        );
        Self {
            steps: p.steps,
            next: 0,
            observed: Vec::new(),
            decoder: root.join("tools/ev/tools/scanout_roi.py"),
            delay_ms: 0,
            waiting: None,
            gate_capture: 1000,
            a1: false,
            large: false,
            large_finite: false,
            legacy: true,
            shutdown: false,
            own: false,
            reader: false,
            restart: false,
            reopened: false,
            root_binding: None,
            power_pacing: None,
        }
    }
    pub(super) fn large(root: &Path) -> Self {
        Self::large_profile(root, false)
    }
    pub(super) fn large_finite(root: &Path) -> Self {
        Self::large_profile(root, true)
    }
    fn large_profile(root: &Path, large_finite: bool) -> Self {
        let mut p = Plan {
            steps: Vec::new(),
            at: 12000,
            x: 320,
            y: 240,
            capture: 100,
        };
        p.capture("large-initial-actual-desktop");
        p.click(220, 5);
        p.await_picker("Root file chooser:", "large1m.txt", false);
        p.click(220, 75);
        p.await_picker("Root file chooser:", "large1m.txt", true);
        p.click(400, 75);
        p.await_picker("Confirm Open:", "large1m.txt", true);
        p.click(400, 75);
        p.await_view(1, "Saved", "large1m.txt", -1);
        p.capture("large-native-exact-read-completed");
        p.click(400, 145);
        p.await_view(1, "Saved", "large1m.txt", -1);
        p.replace_last_scalar();
        p.await_view(1, "Unsaved changes", "large1m.txt", -1);
        p.capture("large-one-byte-replacement-before-save");
        p.click(440, 100);
        p.await_view(1, "Saved", "large1m.txt", -1);
        p.capture("large-native-save-and-exact-readback-completed");
        assert!(
            p.steps.len() < 128 && p.at < 40000,
            "bounded large measurement"
        );
        Self {
            steps: p.steps,
            next: 0,
            observed: Vec::new(),
            decoder: root.join("tools/ev/tools/scanout_roi.py"),
            delay_ms: 0,
            waiting: None,
            gate_capture: 1000,
            a1: false,
            large: true,
            large_finite,
            legacy: false,
            shutdown: false,
            own: false,
            reader: false,
            restart: false,
            reopened: false,
            root_binding: None,
            power_pacing: None,
        }
    }
    pub(super) fn new(root: &Path) -> Self {
        Self::with_profile(root, false, false, false, false, false)
    }
    pub(super) fn a1(root: &Path) -> Self {
        Self::with_profile(root, true, false, false, false, false)
    }
    pub(super) fn shutdown(root: &Path) -> Self {
        Self::with_profile(root, false, true, false, false, false)
    }
    pub(super) fn own(root: &Path) -> Self {
        Self::with_profile(root, false, true, true, false, false)
    }
    pub(super) fn reader(root: &Path) -> Self {
        Self::with_profile(root, false, true, false, true, false)
    }
    pub(super) fn restart(root: &Path) -> Self {
        Self::with_profile(root, false, false, false, false, true)
    }
    pub(super) fn reopened(root: &Path) -> Self {
        let mut scenario = Self::shutdown(root);
        let mut plan = Plan {
            steps: Vec::new(),
            at: 12_000,
            x: 320,
            y: 240,
            capture: 300,
        };
        plan.reopen_after_restart();
        scenario.steps = plan.steps;
        scenario.reopened = true;
        scenario.gate_capture = 3000;
        scenario
    }
    fn with_profile(
        root: &Path,
        a1: bool,
        shutdown: bool,
        own: bool,
        reader: bool,
        restart: bool,
    ) -> Self {
        let mut p = Plan {
            steps: Vec::new(),
            at: 12_000,
            x: 320,
            y: 240,
            capture: 100,
        };
        p.capture("initial-actual-desktop");
        p.await_view(0, "Ready", "", -1);
        p.click(96, 100);
        p.wait(800);
        p.capture("new-folder-name-prompt");
        p.text("folder1");
        p.enter();
        p.wait(100);
        p.await_view(0, "Ready", "folder1", 0);
        p.capture("after-folder-submit");
        p.click(160, 100);
        p.wait(800);
        p.capture("new-text-name-prompt");
        p.text("note1");
        p.enter();
        p.wait(100);
        p.await_view(0, "Ready", "note1", 1);
        p.capture("after-text-submit");
        p.click(180, 170);
        p.wait(700);
        p.capture("selected-second-Files-row");
        p.click(160, 121);
        p.wait(1400);
        p.capture("Root-picker-requested");
        p.await_picker("Root file chooser:", "folder1", false);
        p.click(60, 75);
        p.wait(800);
        p.capture("Root-picker-next-entry");
        p.await_picker("Root file chooser:", "note1", false);
        p.click(220, 75);
        p.wait(800);
        p.capture("Root-picker-edit-rights-request");
        p.await_picker("Root file chooser:", "note1", true);
        p.click(400, 75);
        p.wait(1600);
        p.capture("Root-challenge-before-new-gesture");
        p.await_picker("Confirm Open:", "note1", true);
        p.click(400, 75);
        p.wait(3000);
        p.capture("after-distinct-Root-confirm-gesture");
        p.await_view(1, "Saved", "note1", -1);
        p.click(400, 145);
        p.wait(1200);
        p.capture("Editor-one-focused");
        p.text(TEXT);
        p.wait(600);
        p.capture("before-save");
        p.await_view(1, "Unsaved changes", "note1", -1);
        p.click(440, 100);
        p.wait(100);
        p.await_view(1, "Saved", "note1", -1);
        p.capture("after-native-save-request");
        p.wait(1000);
        p.capture("final-actual-scanout");
        assert!(
            p.steps.len() < 256 && p.at < 55_000,
            "fixed bounded scenario"
        );
        if a1 {
            p.a1_extension();
            assert!(p.steps.len() < 768 && p.at < 180_000, "bounded A1 scenario");
        }
        if reader {
            p.reader_extension();
        }
        if own {
            p.own_extension();
        }
        if shutdown {
            p.shutdown_extension(false);
            assert!(
                p.steps.len() < 384 && p.at < if own { 150_000 } else { 90_000 },
                "bounded files-shutdown scenario"
            );
        }
        if restart {
            p.restart_extension();
            assert!(
                p.steps.len() < 384 && p.at < 90_000,
                "bounded files-restart scenario"
            );
        }
        Self {
            steps: p.steps,
            next: 0,
            observed: Vec::new(),
            decoder: root.join("tools/ev/tools/scanout_roi.py"),
            delay_ms: 0,
            waiting: None,
            gate_capture: 1000,
            a1,
            large: false,
            large_finite: false,
            legacy: false,
            shutdown,
            own,
            reader,
            restart,
            reopened: false,
            root_binding: None,
            power_pacing: None,
        }
    }
    pub(super) fn tick(&mut self, qmp: &mut Qmp, elapsed: Duration) -> Result<(), String> {
        let Some(step) = self.steps.get(self.next).copied() else {
            return Ok(());
        };
        let scheduled = step.at_ms + self.delay_ms;
        if elapsed.as_millis() < u128::from(scheduled) {
            return Ok(());
        }
        if let Action::AwaitPowerReady {
            restart,
            require_release,
        } = step.action
        {
            let now = elapsed.as_millis() as u64;
            let (started, last, _) = self.waiting.unwrap_or((now, 0, 0));
            if now - started > 10_000 {
                return Err(
                    "post-attest power readiness gate timed out; no dependent confirmation sent"
                        .into(),
                );
            }
            if now - last < 100 {
                return Ok(());
            }
            let pacing = self
                .power_pacing
                .as_mut()
                .ok_or("power pacing source missing")?;
            let bytes = std::fs::read(&pacing.serial).map_err(|e| e.to_string())?;
            let ready = super::restart::dialog_ready(&bytes, &pacing.build, restart, pacing.nonce)?;
            let matched = ready
                .as_ref()
                .is_some_and(|r| !require_release || r.permits_main_enter());
            self.observed.push(serde_json::json!({"step":step,"actual_elapsed_ms":now,"actual_power_ready":ready,"matched":matched,"serial_prefix_bytes":bytes.len(),"serial_prefix_sha256":super::bundle::hex(&super::bundle::hash(&bytes)),"scope":"Post-attest trusted Root diagnostic pacing only; no consent, authority or power success inferred"}));
            if matched {
                pacing.nonce = Some(ready.unwrap().nonce);
                self.delay_ms += now - scheduled;
                self.waiting = None;
                self.next += 1;
            } else {
                self.waiting = Some((started, now, 0));
            }
            return Ok(());
        }
        if matches!(
            step.action,
            Action::AwaitLabel { .. }
                | Action::AwaitRootBindingUnchanged
                | Action::AwaitRootBindingChanged
        ) {
            let now = elapsed.as_millis() as u64;
            let (started, last, consecutive) = self.waiting.unwrap_or((now, 0, 0));
            if now - started > 10_000 {
                return Err(format!(
                    "actual A1 view gate timed out: {:?}; no dependent input sent",
                    step.action
                ));
            }
            if now - last < 500 {
                return Ok(());
            }
            let path = qmp.capture_png(self.gate_capture)?;
            self.gate_capture += 1;
            let (matched, roi) = match step.action {
                Action::AwaitLabel { x, y, label } => {
                    let roi = self.roi(
                        &path,
                        &[
                            "label".into(),
                            x.to_string(),
                            y.to_string(),
                            label.len().to_string(),
                        ],
                    )?;
                    let actual = unhex(roi["label"].as_str().ok_or("A1 label ROI absent")?)?;
                    let matched = visible_label_matches(&actual, label);
                    (matched, roi)
                }
                Action::AwaitRootBindingUnchanged | Action::AwaitRootBindingChanged => {
                    let roi = self.roi(&path, &["binding".into()])?;
                    let actual = roi["binding_sha256"]
                        .as_str()
                        .ok_or("Root binding ROI absent")?;
                    let matched = self.root_binding.as_deref().is_some_and(|before| {
                        (before == actual)
                            == matches!(step.action, Action::AwaitRootBindingUnchanged)
                    });
                    (matched, roi)
                }
                _ => unreachable!(),
            };
            let stable = if matched { consecutive + 1 } else { 0 };
            self.observed.push(serde_json::json!({"step":step,"actual_elapsed_ms":now,"actual_png":path,"sha256":build::hash_file(&path)?,"matched":matched,"consecutive_matches":stable,"roi":roi,"scope":"Actual scanout pacing only; not protected authority, denial or human consent proof"}));
            if stable >= 2 {
                self.delay_ms += now - scheduled;
                self.waiting = None;
                self.next += 1;
            } else {
                self.waiting = Some((started, now, stable));
            }
            return Ok(());
        }
        if let Action::AwaitView {
            pane,
            status,
            name,
            row,
            root_rights,
        } = step.action
        {
            let now = elapsed.as_millis() as u64;
            let (started, last, consecutive) = self.waiting.unwrap_or((now, 0, 0));
            // Separate finite host observation allowance for the explicitly
            // selected whole-transfer guest. This is no guest cut renewal or
            // throughput guarantee; original large-io keeps its10s gate.
            let maximum = if self.large_finite && pane == 1 && status == "Saved" {
                ev_workspace_client::transfer::MAX_TRANSFER_TICKS
                    + 4 * ev_workspace_client::transfer::FILE_RPC_TICKS
            } else {
                10_000
            };
            if now - started > maximum {
                return Err(format!(
                    "actual view never became {status}/{name}; no dependent input sent"
                ));
            }
            if now - last < 500 {
                return Ok(());
            }
            let path = qmp.capture_png(self.gate_capture)?;
            self.gate_capture += 1;
            let output = Command::new("python3")
                .arg(&self.decoder)
                .arg(&path)
                .arg(pane.to_string())
                .arg(row.to_string())
                .arg(name.len().to_string())
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() || output.stdout.len() > 32 * 1024 {
                return Err(format!(
                    "read-only scanout decoder failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            let roi: serde_json::Value =
                serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
            let status_bytes = unhex(roi["status"].as_str().ok_or("scanout status absent")?)?;
            let name_bytes = unhex(roi["name"].as_str().ok_or("scanout name absent")?)?;
            let status_ok = label_matches(
                &status_bytes,
                if pane == 2 { 384 } else { 120 },
                status,
                if pane == 2 {
                    ev_graphics::ACCENT
                } else {
                    ev_graphics::MUTED
                },
                ev_graphics::BACKGROUND,
            )?;
            let name_ok = name.is_empty()
                || [
                    (ev_graphics::BACKGROUND, ev_graphics::ACCENT),
                    (ev_graphics::INK, ev_graphics::PANEL),
                    (ev_graphics::INK, ev_graphics::BACKGROUND),
                    (ev_graphics::MUTED, ev_graphics::PANEL),
                ]
                .into_iter()
                .any(|(fg, bg)| {
                    label_matches(&name_bytes, (name.len() + 1) * 6, name, fg, bg).unwrap_or(false)
                });
            let rights_ok = if let Some(writable) = root_rights {
                let bytes = unhex(roi["rights"].as_str().ok_or("scanout rights absent")?)?;
                label_matches(
                    &bytes,
                    66,
                    if writable { "READ/WRITE" } else { "READ ONLY" },
                    ev_graphics::ACCENT,
                    ev_graphics::BACKGROUND,
                )?
            } else {
                true
            };
            let matched = status_ok && name_ok && rights_ok;
            let stable = if matched { consecutive + 1 } else { 0 };
            self.observed.push(serde_json::json!({"step":step,"actual_elapsed_ms":now,"actual_png":path,"sha256":build::hash_file(&path)?,"status_match":status_ok,"name_match":name_ok,"rights_match":rights_ok,"consecutive_matches":stable,"scope":"Visual pacing only, not protected Display/consent proof"}));
            if stable >= 2 {
                self.delay_ms += now - scheduled;
                self.waiting = None;
                self.next += 1;
            } else {
                self.waiting = Some((started, now, stable));
            }
            return Ok(());
        }
        if elapsed.as_millis() > u128::from(scheduled + 3000) {
            return Err("scenario fell behind original finite schedule; no input retry".into());
        }
        let result = match step.action {
            Action::Move { dx, dy } => qmp.relative(dx, dy).map(|()| serde_json::Value::Null),
            Action::Button(down) => qmp.left_button(down).map(|()| serde_json::Value::Null),
            Action::Byte(b) => qmp.ascii(b).map(|()| serde_json::Value::Null),
            Action::Enter(down) => qmp
                .key_state(Key::Enter, down)
                .map(|()| serde_json::Value::Null),
            Action::Escape(down) => qmp
                .key_state(Key::Escape, down)
                .map(|()| serde_json::Value::Null),
            Action::Right(down)=>qmp.key_state(Key::Right,down).map(|()|serde_json::Value::Null),
            Action::Backspace(down)=>qmp.key_state(Key::Backspace,down).map(|()|serde_json::Value::Null),
            Action::ReleasedShutdownConfirm|Action::ReleasedRestartConfirm=>qmp.released_enter().map(|()|serde_json::json!({"released_physical_Enter_queued":true,"guest_acceptance_inferred":false})),
            Action::Capture { index, label } => qmp.capture_png(index).and_then(|path| {
                Ok(serde_json::json!({"path":path,"sha256":build::hash_file(&path)?,"label":label}))
            }),
            Action::RememberRootBinding => qmp.capture_png(self.gate_capture).and_then(|path| {
                self.gate_capture += 1;
                let roi = self.roi(&path, &["binding".into()])?;
                let hash = roi["binding_sha256"].as_str().ok_or("Root binding ROI absent")?;
                self.root_binding = Some(hash.to_owned());
                Ok(serde_json::json!({"actual_png":path,"sha256":build::hash_file(&path)?,"roi":roi,"scope":"Visual binding/nonce comparison only; not authority proof"}))
            }),
            Action::AwaitView { .. } | Action::AwaitLabel { .. } | Action::AwaitRootBindingUnchanged | Action::AwaitRootBindingChanged | Action::AwaitPowerReady { .. } => unreachable!(),
        };
        self.observed.push(serde_json::json!({"step":step,"actual_elapsed_ms":elapsed.as_millis(),"result":result}));
        result?;
        self.next += 1;
        Ok(())
    }
    fn roi(&self, path: &Path, args: &[String]) -> Result<serde_json::Value, String> {
        let output = Command::new("python3")
            .arg(&self.decoder)
            .arg(path)
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() || output.stdout.len() > 32 * 1024 {
            return Err(format!(
                "read-only bounded A1 scanout decoder failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
    }
    pub(super) fn complete(&self) -> bool {
        self.next == self.steps.len()
    }
    pub(super) fn power_gesture_delivered(&self) -> bool {
        (self.shutdown || self.restart) && self.complete()
    }
    pub(super) fn report(&self, path: &Path, error: &Option<String>) -> Result<(), String> {
        super::bundle::write_json_new(
            path,
            &serde_json::json!({"schema":1,"scope":"Fixed synthetic reference-device PS2 input, actual Root/Apps decide outcomes; NOT human approval or authority evidence","scenario":if self.restart{"files-restart-before-reset"}else if self.reopened{"files-restart-second-boot"}else if self.reader{"inspector-reader"}else if self.own{"inspector-own"}else if self.shutdown{"files-shutdown"}else if self.legacy{"legacy-owner"}else if self.large_finite{"large-io-finite"}else if self.large{"large-io"}else if self.a1 {"files-a1"}else{"files-basic"},"profile":"Root logical640x480 initialcursor320,240; Files/Editor1 factory geometry; current protected Root picker footer70..79","planned":self.steps,"actual":self.observed,"completed_actions":self.next,"total_actions":self.steps.len(),"all_actions_delivered":self.complete(),"error":error,"expected_file":if self.legacy{"original Notes/Private READ only"}else if self.large{"large1m.txt"}else{"note1"},"expected_text":if self.legacy{"unchanged explicit owned template; no document edits or Save"}else if self.large{"1MiB ASCII pattern with last byte replaced by Z; initial caret is EOF and body click focuses only"}else{TEXT},"finite_transfer_observer":self.large_finite,"load_save_host_gate_ms":if self.large_finite{ev_workspace_client::transfer::MAX_TRANSFER_TICKS+4*ev_workspace_client::transfer::FILE_RPC_TICKS}else{10000},"host_gate_scope":"Explicit reference observation allowance, not a ticks-to-wall-time guarantee or any admitted RPC renewal","checked_shutdown_required":self.shutdown,"actual_guest_restart_required":self.restart,"fresh_second_boot_native_reopen":self.reopened,"own_Inspector_reader_exact_callback_observer":self.reader,"own_Inspector_actual_control_and_second_Save_observer":self.own,"own_Inspector_cold_minimum_note_revision":if self.own{3}else{2},"proof":"Independent cold bytes confirm persistence/preservation separately; glyph/nonce gates pace input and retain observations, not broad authority/negative-access/consent acceptance"}),
        )
    }
}
fn visible_label_matches(actual: &[u8], text: &str) -> bool {
    [
        (ev_graphics::BACKGROUND, ev_graphics::ACCENT),
        (ev_graphics::INK, ev_graphics::PANEL),
        (ev_graphics::INK, ev_graphics::BACKGROUND),
        (ev_graphics::MUTED, ev_graphics::PANEL),
        (ev_graphics::MUTED, ev_graphics::ACCENT),
        (ev_graphics::ACCENT, ev_graphics::BACKGROUND),
        (ev_graphics::DANGER, ev_graphics::BACKGROUND),
    ]
    .into_iter()
    .any(|(fg, bg)| label_matches(actual, (text.len() + 1) * 6, text, fg, bg).unwrap_or(false))
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() > 16 * 1024
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("bounded ROI hex refused".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn label_matches(
    actual: &[u8],
    stride: usize,
    text: &str,
    fg: ev_graphics::Color,
    bg: ev_graphics::Color,
) -> Result<bool, String> {
    use ev_graphics::{Canvas, Color, Error, Pixels};
    struct Reference {
        width: usize,
        pixels: Vec<Color>,
    }
    impl Pixels for Reference {
        fn dimensions(&self) -> (usize, usize) {
            (self.width, 7)
        }
        fn write(&mut self, x: usize, y: usize, c: Color) -> Result<(), Error> {
            if x >= self.width || y >= 7 {
                return Err(Error::Bounds);
            }
            self.pixels[y * self.width + x] = c;
            Ok(())
        }
    }
    let width = (text.len() + 1) * 6;
    if width > stride || actual.len() != stride * 7 * 3 {
        return Ok(false);
    }
    let mut expected = Reference {
        width,
        pixels: vec![bg; width * 7],
    };
    Canvas::new(&mut expected)
        .text_exact(0, 0, text.as_bytes(), fg)
        .map_err(|e| format!("reference glyph:{e:?}"))?;
    for y in 0..7 {
        for x in 0..width {
            let c = expected.pixels[y * width + x].0;
            let at = (y * stride + x) * 3;
            if actual[at..at + 3] != [(c >> 16) as u8, (c >> 8) as u8, c as u8] {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reader_profile_requires_root_callback_and_new_pixels_before_revoke_and_checked_power() {
        let basic = Scenario::new(Path::new("/sdk"));
        let reader = Scenario::reader(Path::new("/sdk"));
        assert!(reader.reader && reader.shutdown && !reader.own && !reader.a1);
        assert_eq!(
            serde_json::to_value(&reader.steps[..basic.steps.len()]).unwrap(),
            serde_json::to_value(&basic.steps).unwrap()
        );
        let extra = &reader.steps[basic.steps.len()..];
        let at = |label| {
            extra
                .iter()
                .position(
                    |s| matches!(s.action, Action::Capture { label: got, .. } if got == label),
                )
                .unwrap()
        };
        let before = at("reader-own-current-authenticated-control-before-one-Enter");
        let after = at("reader-own-ordinary-callback-and-repaint-after-original-ack");
        let revoked = at("reader-own-original-read-scope-revoked-before-shutdown");
        assert!(before < after && after < revoked);
        assert_eq!(
            extra[before..after]
                .iter()
                .filter(|s| matches!(s.action, Action::Enter(true)))
                .count(),
            1
        );
        for label in [
            "Inspector reader action verified: Previous node",
            "File name",
        ] {
            assert!(extra[before..after].iter().any(
                |s| matches!(s.action, Action::AwaitLabel { label: got, .. } if got == label)
            ));
        }
        assert!(extra[..before].iter().any(|s| matches!(
            s.action,
            Action::AwaitLabel {
                label: "READ1 ACTION0 TEXT0 CONFIRM0",
                ..
            }
        )));
        assert!(matches!(
            extra.last().unwrap().action,
            Action::ReleasedShutdownConfirm
        ));
        assert!(
            extra[..revoked]
                .iter()
                .all(|s| !matches!(s.action, Action::Backspace(_) | Action::Right(_)))
        );
    }
    #[test]
    fn restart_preserves_real_save_and_requires_new_boot_reopen_without_recreating_data() {
        let root = Path::new("/sdk");
        let basic = Scenario::new(root);
        let restart = Scenario::restart(root);
        assert_eq!(
            serde_json::to_value(&restart.steps[..basic.steps.len()]).unwrap(),
            serde_json::to_value(&basic.steps).unwrap()
        );
        assert!(matches!(
            restart.steps.last().unwrap().action,
            Action::ReleasedRestartConfirm
        ));
        assert_eq!(
            restart
                .steps
                .iter()
                .filter(|s| matches!(s.action, Action::ReleasedRestartConfirm))
                .count(),
            1
        );
        assert!(
            !restart
                .steps
                .iter()
                .any(|s| matches!(s.action, Action::ReleasedShutdownConfirm))
        );
        let reopened = Scenario::reopened(root);
        assert!(reopened.reopened && reopened.shutdown && !reopened.restart);
        let release = reopened
            .steps
            .iter()
            .position(|s| matches!(s.action, Action::Enter(false)))
            .unwrap();
        let gate = reopened
            .steps
            .iter()
            .position(|s| {
                matches!(
                    s.action,
                    Action::AwaitPowerReady {
                        restart: false,
                        require_release: true
                    }
                )
            })
            .unwrap();
        assert!(release < gate);
        assert!(
            !reopened
                .steps
                .iter()
                .any(|s| matches!(s.action, Action::Enter(true)))
        );
        assert!(
            !reopened
                .steps
                .iter()
                .any(|s| matches!(s.action, Action::Byte(_) | Action::Backspace(_)))
        );
        let loaded = reopened
            .steps
            .iter()
            .position(|s| {
                matches!(
                    s.action,
                    Action::Capture {
                        label: "restart-native-reopened-exact-committed-text",
                        ..
                    }
                )
            })
            .unwrap();
        let confirm = reopened
            .steps
            .iter()
            .position(|s| matches!(s.action, Action::ReleasedShutdownConfirm))
            .unwrap();
        assert!(loaded < confirm && confirm == reopened.steps.len() - 1);
    }
    #[test]
    fn own_inspector_observes_real_navigation_and_second_save_before_checked_power() {
        let basic = Scenario::new(Path::new("/sdk"));
        let own = Scenario::own(Path::new("/sdk"));
        assert!(own.own && own.shutdown && !own.a1 && !own.large && !own.legacy);
        assert_eq!(
            serde_json::to_value(&own.steps[..basic.steps.len()]).unwrap(),
            serde_json::to_value(&basic.steps).unwrap()
        );
        let extra = &own.steps[basic.steps.len()..];
        assert!(matches!(
            extra.last().unwrap().action,
            Action::ReleasedShutdownConfirm
        ));
        let position = |label| {
            extra
                .iter()
                .position(
                    |s| matches!(s.action, Action::Capture { label: found, .. } if found == label),
                )
                .unwrap()
        };
        let verified = position("own-Inspector-authenticated-tree-and-current-focus");
        let page = position("own-Inspector-ordinary-Enter-changed-actual-stats-page");
        let dirty = position("own-Inspector-dirty-shutdown-refused-with-original-private-text");
        let saved = position("own-Inspector-current-tree-and-second-native-Save");
        let cancel = position("shutdown-cancel-preserved-saved-desktop");
        assert!(verified < page && page < dirty && dirty < saved && saved < cancel);
        assert!(extra[page..dirty].iter().any(|s| matches!(
            s.action,
            Action::AwaitLabel {
                label: "no application was stopped",
                ..
            }
        )));
        assert!(
            extra[page..dirty]
                .iter()
                .any(|s| matches!(s.action, Action::AwaitLabel { label: TEXT, .. }))
        );
        assert!(
            extra[verified..page]
                .iter()
                .any(|s| matches!(s.action, Action::Right(true)))
        );
        assert!(
            extra[verified..page]
                .iter()
                .any(|s| matches!(s.action, Action::Enter(false)))
        );
        let navigation = &extra[verified..page];
        let next = navigation
            .iter()
            .position(|s| {
                matches!(
                    s.action,
                    Action::AwaitLabel {
                        label: "Next page",
                        ..
                    }
                )
            })
            .unwrap();
        assert!(matches!(navigation[next + 1].action, Action::Enter(true)));
        assert_eq!(navigation[next + 1].at_ms - navigation[next].at_ms, 100);
        assert_eq!(
            navigation
                .iter()
                .filter(|s| matches!(s.action, Action::Enter(true)))
                .count(),
            1
        );
        assert_eq!(
            extra
                .iter()
                .filter(|s| matches!(
                    s.action,
                    Action::AwaitLabel {
                        label: "Inspector control ready: Refresh",
                        ..
                    }
                ))
                .count(),
            2
        );
        assert!(!extra.iter().any(|s| matches!(
            s.action,
            Action::AwaitLabel {
                label: "Inspector own controls verified against actual sender",
                ..
            }
        )));
        assert!(
            extra[page..saved]
                .iter()
                .any(|s| matches!(s.action, Action::Backspace(false)))
        );
        assert!(extra.iter().any(|s| matches!(
            s.action,
            Action::AwaitLabel {
                label: "NetDriver",
                ..
            }
        )));
        assert!(!own.complete() && !own.power_gesture_delivered());
        let (mut button, mut enter, mut escape, mut right, mut backspace) =
            (false, false, false, false, false);
        for step in &own.steps {
            let (held, down) = match step.action {
                Action::Button(down) => (&mut button, down),
                Action::Enter(down) => (&mut enter, down),
                Action::Escape(down) => (&mut escape, down),
                Action::Right(down) => (&mut right, down),
                Action::Backspace(down) => (&mut backspace, down),
                _ => continue,
            };
            assert_ne!(*held, down);
            *held = down;
        }
        assert!(!button && !enter && !escape && !right && !backspace);
    }
    #[test]
    fn shutdown_extends_the_same_real_save_with_cancel_then_a_last_released_confirm() {
        let basic = Scenario::new(Path::new("/sdk"));
        let shutdown = Scenario::shutdown(Path::new("/sdk"));
        assert!(shutdown.shutdown && !shutdown.a1 && !shutdown.large && !shutdown.legacy);
        assert_eq!(
            serde_json::to_value(&shutdown.steps[..basic.steps.len()]).unwrap(),
            serde_json::to_value(&basic.steps).unwrap()
        );
        let extra = &shutdown.steps[basic.steps.len()..];
        assert!(matches!(
            extra.last().unwrap().action,
            Action::ReleasedShutdownConfirm
        ));
        assert_eq!(
            extra
                .iter()
                .filter(|s| matches!(s.action, Action::ReleasedShutdownConfirm))
                .count(),
            1
        );
        assert_eq!(
            extra
                .iter()
                .filter(|s| matches!(s.action, Action::Escape(true)))
                .count(),
            1
        );
        assert_eq!(
            extra
                .iter()
                .filter(|s| matches!(s.action, Action::Escape(false)))
                .count(),
            1
        );
        let prompts: Vec<_> = extra
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                matches!(
                    s.action,
                    Action::AwaitLabel {
                        label: "Confirm shutdown: committed files retained",
                        ..
                    }
                )
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(prompts.len(), 2);
        assert!(extra[prompts[0]..prompts[1]].iter().any(|s| matches!(
            s.action,
            Action::AwaitLabel {
                label: "Evrosion workspace",
                ..
            }
        )));
        assert!(
            extra[prompts[1]..extra.len() - 1]
                .iter()
                .any(|s| matches!(s.action, Action::Capture { .. }))
        );
        assert!(
            !basic
                .steps
                .iter()
                .any(|s| matches!(s.action, Action::ReleasedShutdownConfirm))
        );
        assert!(shutdown.steps.len() < 384 && shutdown.steps.last().unwrap().at_ms < 90_000);
    }
    #[test]
    fn legacy_owner_paces_refusal_override_and_revoke_without_editing() {
        let scenario = Scenario::legacy(Path::new("/sdk"));
        assert!(scenario.legacy && !scenario.large && !scenario.a1);
        let (mut held, mut escape, mut remembered) = (false, false, false);
        let (mut changed, mut refusals, mut loaded_private, mut loaded_notes) = (0, 0, 0, 0);
        for (i, step) in scenario.steps.iter().enumerate() {
            match step.action {
                Action::Button(down) => {
                    assert_ne!(held, down);
                    held = down;
                }
                Action::Escape(down) => {
                    assert_ne!(escape, down);
                    escape = down;
                }
                Action::Byte(byte) => {
                    assert_eq!(byte, b'v');
                    assert!(matches!(
                        scenario.steps[i + 1].action,
                        Action::Capture { .. }
                    ));
                }
                Action::Enter(_) | Action::Right(_) | Action::Backspace(_) => {
                    panic!("legacy observation must not insert, delete or edit text")
                }
                Action::AwaitLabel { x, y, label } => {
                    assert!(usize::from(x) + (label.len() + 1) * 6 <= 640 && y + 7 <= 480);
                    refusals += usize::from(label == "Original EVRO-USERS-VOL01 / local2 Private");
                }
                Action::AwaitView {
                    pane: 1,
                    status: "Saved",
                    name,
                    ..
                } => {
                    loaded_private += usize::from(name == "Private");
                    loaded_notes += usize::from(name == "Notes");
                }
                Action::RememberRootBinding => {
                    assert!(!remembered);
                    remembered = true;
                }
                Action::AwaitRootBindingChanged => {
                    assert!(remembered && loaded_private > 0);
                    assert!(matches!(
                        scenario.steps[i + 1].action,
                        Action::AwaitLabel { .. }
                    ));
                    remembered = false;
                    changed += 1;
                }
                Action::Move { dx, dy } => {
                    assert!((-64..=64).contains(&dx) && (-64..=64).contains(&dy))
                }
                _ => (),
            }
        }
        assert!(!held && !escape && !remembered);
        assert_eq!(
            (changed, refusals, loaded_private, loaded_notes),
            (2, 2, 1, 3)
        );
        assert!(scenario.steps.len() < 768 && scenario.steps.last().unwrap().at_ms < 180_000);
    }
    #[test]
    fn legacy_glyph_and_nonce_gates_keep_actual_cursor_footprint_outside() {
        let scenario = Scenario::legacy(Path::new("/sdk"));
        let (mut x, mut y) = (320i32, 240i32);
        let overlap = |left: i32, top: i32, width: i32, height: i32, x: i32, y: i32| {
            x < left + width && x + 8 > left && y < top + height && y + 12 > top
        };
        for step in scenario.steps {
            match step.action {
                Action::Move { dx, dy } => {
                    x += i32::from(dx);
                    y += i32::from(dy);
                }
                Action::AwaitLabel {
                    x: left,
                    y: top,
                    label,
                } => assert!(
                    !overlap(
                        i32::from(left),
                        i32::from(top),
                        ((label.len() + 1) * 6) as i32,
                        7,
                        x,
                        y
                    ),
                    "cursor at{x},{y} occludes {label}"
                ),
                Action::RememberRootBinding
                | Action::AwaitRootBindingChanged
                | Action::AwaitRootBindingUnchanged => assert!(
                    !overlap(2, 11, 638, 27, x, y),
                    "cursor must not change the binding comparison"
                ),
                _ => (),
            }
        }
        // The exact failed physical location intersects the protected title.
        assert!(overlap(2, 11, 246, 7, 220, 5));
    }
    #[test]
    fn refusal_glyph_gate_requires_actual_unchanged_pixels_and_word_boundary() {
        use ev_graphics::{BACKGROUND, Canvas, Color, DANGER, Error, Pixels};
        struct Image(Vec<Color>);
        impl Pixels for Image {
            fn dimensions(&self) -> (usize, usize) {
                (640, 7)
            }
            fn write(&mut self, x: usize, y: usize, c: Color) -> Result<(), Error> {
                if x >= 640 || y >= 7 {
                    return Err(Error::Bounds);
                }
                self.0[y * 640 + x] = c;
                Ok(())
            }
        }
        let expected = "Original EVRO-USERS-VOL01 / local2 Private";
        let render = |title: &[u8]| {
            let mut pixels = Image(vec![BACKGROUND; 640 * 7]);
            Canvas::new(&mut pixels)
                .text_exact(0, 0, title, DANGER)
                .unwrap();
            let width = (expected.len() + 1) * 6;
            let mut bytes = Vec::new();
            for row in 0..7 {
                for x in 0..width {
                    bytes.extend(pixels.0[row * 640 + x].components());
                }
            }
            bytes
        };
        let actual = render(b"Original EVRO-USERS-VOL01 / local2 Private refused;");
        assert!(visible_label_matches(&actual, expected));
        assert!(!visible_label_matches(
            &render(b"Original EVRO-USERS-VOL01 / local2 Private: deliberate"),
            expected
        ));
        let mut corrupted = actual;
        corrupted[0] ^= 1;
        assert!(!visible_label_matches(&corrupted, expected));
    }
    #[test]
    fn fixed_input_is_finite_released_and_observed_per_character() {
        let s = Scenario::new(Path::new("/sdk"));
        assert!(s.steps.len() < 256);
        assert!(s.steps.last().unwrap().at_ms < 55_000);
        let mut held = false;
        for (i, step) in s.steps.iter().enumerate() {
            match step.action {
                Action::Move { dx, dy } => {
                    assert!((-64..=64).contains(&dx) && (-64..=64).contains(&dy))
                }
                Action::Button(down) => {
                    assert_ne!(held, down);
                    held = down
                }
                Action::Byte(_) => assert!(matches!(s.steps[i + 1].action, Action::Capture { .. })),
                _ => {}
            }
        }
        assert!(!held);
    }
    #[test]
    fn large_measurement_never_edits_before_exact_load_gate_and_releases_keys() {
        let s = Scenario::large(Path::new("/sdk"));
        let (mut button, mut right, mut backspace, mut loaded) = (false, false, false, false);
        for step in &s.steps {
            match step.action {
                Action::AwaitView {
                    status: "Saved",
                    name: "large1m.txt",
                    ..
                } => loaded = true,
                Action::Button(down) => {
                    assert_ne!(button, down);
                    button = down;
                }
                Action::Right(down) => {
                    assert!(loaded);
                    assert_ne!(right, down);
                    right = down;
                }
                Action::Backspace(down) => {
                    assert!(loaded);
                    assert_ne!(backspace, down);
                    backspace = down;
                }
                Action::Byte(b) => {
                    assert!(loaded);
                    assert_eq!(b, b'Z');
                }
                Action::Move { dx, dy } => {
                    assert!((-64..=64).contains(&dx) && (-64..=64).contains(&dy))
                }
                _ => (),
            }
        }
        assert!(!button && !right && !backspace);
        assert!(s.steps.len() < 128 && s.steps.last().unwrap().at_ms < 40000);
        assert!(!s.complete());
        let finite = Scenario::large_finite(Path::new("/sdk"));
        assert_eq!(
            serde_json::to_value(&s.steps).unwrap(),
            serde_json::to_value(&finite.steps).unwrap()
        );
        assert!(!s.large_finite && finite.large_finite);
    }
    #[test]
    fn a1_extension_keeps_basic_prefix_fresh_edges_and_bounded_observation_gates() {
        let basic = Scenario::new(Path::new("/sdk"));
        let a1 = Scenario::a1(Path::new("/sdk"));
        assert_eq!(
            serde_json::to_value(&a1.steps[..basic.steps.len()]).unwrap(),
            serde_json::to_value(&basic.steps).unwrap()
        );
        assert!(a1.steps.len() < 768 && a1.steps.last().unwrap().at_ms < 180_000);
        let (mut button, mut enter, mut escape) = (false, false, false);
        let mut remembers = 0;
        let mut comparisons = 0;
        let mut exact_document = 0;
        let mut stats_returns = 0;
        for (index, step) in a1.steps.iter().enumerate() {
            match step.action {
                Action::Button(down) => {
                    assert_ne!(button, down);
                    button = down;
                }
                Action::Enter(down) => {
                    assert_ne!(enter, down);
                    enter = down;
                }
                Action::Escape(down) => {
                    assert_ne!(escape, down);
                    escape = down;
                }
                Action::Move { dx, dy } => {
                    assert!((-64..=64).contains(&dx) && (-64..=64).contains(&dy))
                }
                Action::Byte(_) => {
                    assert!(matches!(a1.steps[index + 1].action, Action::Capture { .. }))
                }
                Action::AwaitLabel { x, y, label } => {
                    assert!(!label.is_empty() && label.is_ascii());
                    assert!(usize::from(x) + (label.len() + 1) * 6 <= 640 && y + 7 <= 480);
                    exact_document += usize::from(label == TEXT);
                    stats_returns += usize::from(label == "Sampled resource data");
                }
                Action::RememberRootBinding => remembers += 1,
                Action::AwaitRootBindingUnchanged => {
                    assert_eq!(remembers, 1);
                    assert!(
                        a1.steps[..index]
                            .iter()
                            .rev()
                            .take(3)
                            .any(|s| matches!(s.action, Action::Byte(b'a')))
                    );
                    comparisons += 1;
                }
                _ => (),
            }
        }
        assert!(!button && !enter && !escape);
        assert_eq!(
            (remembers, comparisons, exact_document, stats_returns),
            (1, 1, 1, 4)
        );
        assert!(!a1.complete());
    }
}
