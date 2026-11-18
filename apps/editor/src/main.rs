#![no_std]
#![no_main]
mod native_semantic;

use core::{
    arch::global_asm,
    cell::UnsafeCell,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};
use ev_graphics::{Color, Error as GraphicsError, Pixels};
use ev_userspace_contract::{
    Bootstrap,
    file_v2::{Method, Response},
    root_v5::{
        resources,
        surface::{Header, Producer},
    },
    workspace::Outcome,
};
use ev_userspace_runtime as rt;
use ev_workspace_client::{
    FileClient,
    native::{NativeLink, SelfFacts, self_facts},
    selection::{Access, Selection},
    semantic::{self as a1, Publisher as SemanticPublisher},
    transfer::Transfer,
    ui::{Command, Event, Navigation, ReleaseMode, State},
};
use ev_workspace_editor::{Close, Editor, MAX_DOCUMENT_BYTES, Phase, Receipt, Status};
use sha2::{Digest, Sha256};
// SAFETY: unique native entry owns the shared userspace entry/intrinsic symbols.
global_asm!(ev_userspace_runtime::start_assembly!());
// SAFETY: the selected measured loader owns exactly eight RW/NX stack pages
// 480..487 with both guards absent; the entry stack is not the document buffer.
global_asm!(
    ".section .text",
    ".global ev_user_main",
    "ev_user_main:",
    "mov rsp,0x80001e8000",
    "and rsp,-16",
    "call ev_editor_main",
    "ud2"
);
#[repr(C, align(4096))]
struct Document(UnsafeCell<[u8; MAX_DOCUMENT_BYTES]>);
// SAFETY: one-way claim and the admitted one-thread Job permit one document
// owner. Raw access occurs only while no Editor mutable borrow exists.
unsafe impl Sync for Document {}
#[unsafe(link_section = ".workspace_document")]
static DOCUMENT: Document = Document(UnsafeCell::new([0; MAX_DOCUMENT_BYTES]));
static CLAIMED: AtomicBool = AtomicBool::new(false);
const BASE: usize = 1 << 39;
const SURFACE: usize = BASE + resources::APP_SURFACE_FIRST_PAGE as usize * 4096;
const FRAME: usize = BASE + resources::APP_FILE_FIRST_PAGE as usize * 4096;
fn require(ok: bool, code: u64) {
    if !ok {
        rt::exit(code)
    }
}
fn now() -> u64 {
    let r = rt::monotonic();
    require(r.status == 0 && r.capability == 0, 1400);
    r.value
}
fn transfer(bound: u64, length: u64) -> Result<Transfer, ()> {
    let captured = now();
    if !rt::execution::live(bound, captured) {
        return Err(());
    }
    Transfer::capture(captured, length).map_err(|_| ())
}
fn notify(events: u64, event: Event, bound: u64) {
    let bytes = event.encode().unwrap_or_else(|_| rt::exit(1402));
    let deadline = rt::execution::deadline(bound, now(), 512).unwrap_or_else(|_| rt::exit(1403));
    loop {
        let r = rt::send(events, bytes);
        require(r.value == 0 && r.capability == 0, 1404);
        match r.status {
            0 => return,
            2 => {
                require(now() < deadline, 1405);
                let _ = rt::yield_now();
            }
            _ => rt::exit(1406),
        }
    }
}
struct Surface {
    header: Header,
    fenced: bool,
}
impl Pixels for Surface {
    fn dimensions(&self) -> (usize, usize) {
        (self.header.width as usize, self.header.height as usize)
    }
    fn write(&mut self, x: usize, y: usize, color: Color) -> Result<(), GraphicsError> {
        if self.fenced || x >= self.header.width as usize || y >= self.header.height as usize {
            return Err(GraphicsError::Bounds);
        }
        let offset = 256 + y * self.header.stride_bytes as usize + x * 4;
        // SAFETY: actual admitted sole-writer63-page Surface, bounded header
        // geometry and no accepted Present read credit while this method runs.
        unsafe { ((SURFACE + offset) as *mut u32).write_volatile(color.0 & 0x00ff_ffff) };
        Ok(())
    }
}
impl Surface {
    fn present(&mut self, endpoint: u64, bound: u64) -> Result<bool, ()> {
        if self.fenced {
            return Err(());
        }
        self.header.frame = self
            .header
            .frame
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .ok_or(())?;
        let header = self.header.encode().map_err(|_| ())?;
        for (i, b) in header.iter().enumerate() {
            // SAFETY: exact initialized Surface header, sole writer, no current
            // accepted Present. This borrow ends before issuing the actual RPC.
            unsafe { ((SURFACE + i) as *mut u8).write_volatile(*b) };
        }
        let deadline =
            rt::execution::deadline(bound, now(), resources::RPC_TICKS).map_err(|_| ())?;
        match rt::rpc::call(endpoint, self.header.frame.to_le_bytes(), deadline) {
            Ok(reply) if u64::from_le_bytes(reply) == self.header.frame => Ok(true),
            Ok(reply) if u64::from_le_bytes(reply) == u64::MAX => Ok(false), // exact completed refusal returns credit
            _ => {
                self.fenced = true;
                Err(())
            }
        }
    }
}
struct Loading {
    selection: Selection,
    offset: u32,
    hash: Sha256,
    transfer: Transfer,
}
struct App {
    editor: Option<Editor<'static>>,
    file: Option<FileClient<NativeLink>>,
    file_contract: Option<ev_userspace_contract::file_v2::Support>,
    selection: Option<Selection>,
    loading: Option<Loading>,
    save_transfer: Option<Transfer>,
    /// Exact acknowledged staged verification prefix; None means every stage
    /// byte was verified. Retained with the frozen Save on any uncertainty.
    save_verified: Option<u32>,
    /// Last actually accepted fourth-button label was Cancel. Delayed clicks
    /// stay cancellation-only until another presentation is accepted.
    cancel_presented: bool,
    surface: Surface,
    configured: bool,
    scene_ready: bool,
    scene_low: Option<u32>,
    paint: bool,
    follow_caret: bool,
    focused: bool,
    start: usize,
    error: Option<State>,
    handoff: ev_native_editor::FileHandoff,
    semantics: SemanticPublisher,
    semantic_accepted: bool,
    visible_end: usize,
    ops: native_semantic::Operations,
}
impl App {
    fn semantic_request(&mut self, request: a1::Request) {
        match request {
            a1::Request::Abort { nonce } => {
                let _ = self.semantics.abort(nonce);
            }
            a1::Request::Snapshot { page, nonce } => {
                if self.semantics.busy() {
                    return;
                }
                let refusal = if self.ops.busy() {
                    Some(2)
                } else if page != 0 {
                    Some(1)
                } else if !self.semantic_accepted
                    || self.paint
                    || !self.configured
                    || !self.scene_ready
                    || self.surface.fenced
                {
                    Some(3)
                } else {
                    None
                };
                if let Some(code) = refusal {
                    let _ = self.semantics.refuse(nonce, code);
                    return;
                }
                let h = self.surface.header;
                let header = a1::Header {
                    nonce,
                    page: 0,
                    pages: 1,
                    model: h.model_revision,
                    view: h.view_revision,
                    frame: h.frame,
                    mapping_epoch: h.mapping_epoch,
                    width: h.width as u16,
                    height: h.height as u16,
                    keyboard: if self.focused && self.editor.is_some() {
                        3
                    } else {
                        0
                    },
                    modal: 0,
                };
                let view = ev_native_editor::View {
                    editor: self.editor.as_ref(),
                    name: self.selection.as_ref().map(|s| s.name.as_str()),
                    state: self.state(),
                    start: self.start,
                    focused: self.focused,
                };
                let writable = self
                    .selection
                    .as_ref()
                    .is_some_and(|s| s.access == Access::ReadWrite);
                let published = ev_native_editor::semantic::publish(
                    &mut self.semantics,
                    header,
                    view,
                    self.visible_end,
                    writable,
                );
                if published.is_ok() {
                    self.ops.snapshot_started(header);
                } else {
                    let _ = self.semantics.refuse(nonce, 4);
                }
            }
        }
    }
    fn pump_semantics(&mut self, events: u64) {
        // One bounded word per loop; a full RootEvents inbox keeps the exact
        // unsent frame. Only actual successful SEND advances publication.
        if let Some(frame) = self.semantics.next() {
            let r = rt::send(events, frame.encode());
            require(
                r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                1423,
            );
            if r.status == 0 {
                require(self.semantics.sent(frame).is_ok(), 1424);
                self.ops.snapshot_sent(frame);
            }
        }
    }
    fn pump_semantic_operation(&mut self, events: u64) {
        if let Some(frame) = self.ops.next(
            self.semantic_accepted,
            self.paint,
            self.surface.header.frame,
            self.editor.as_ref().and_then(Editor::cancelled_save),
        ) {
            let r = rt::send(events, frame.encode());
            require(
                r.value == 0 && r.capability == 0 && matches!(r.status, 0 | 2),
                1429,
            );
            if r.status == 0 {
                self.ops.sent(frame);
            }
        }
    }
    fn state(&self) -> State {
        if let Some(error) = self.error {
            return error;
        }
        if self.loading.is_some() {
            return State::Loading;
        }
        match self.editor.as_ref().map(Editor::status) {
            None => State::NoFile,
            Some(Status::Saved) => State::Saved,
            Some(Status::Dirty) => State::Dirty,
            Some(Status::Conflict) => State::Conflict,
            Some(Status::Uncertain) => State::Uncertain,
            _ => State::Saving,
        }
    }
    fn failed(&mut self) {
        if let Some(load) = self.loading.as_mut() {
            load.transfer.fence();
        }
        if let Some(save) = self.save_transfer.as_mut() {
            save.fence();
        }
        if let Some(editor) = self.editor.as_mut() {
            editor.mark_uncertain();
        }
        self.error = Some(State::Uncertain);
        self.paint = true;
    }
    fn bump_view(&mut self) {
        self.surface.header.view_revision = self
            .surface
            .header
            .view_revision
            .checked_add(1)
            .filter(|v| *v != u64::MAX)
            .unwrap_or_else(|| rt::exit(1407));
        self.paint = true;
    }
    fn accept_grant(&mut self, nonce: u64, cap: u64, facts: SelfFacts, bound: u64) -> bool {
        if !self.handoff.may_receive()
            || self.loading.is_some()
            || self.file.is_some()
            || self.error.is_some()
            || self.editor.as_ref().is_some_and(|e| e.pending().is_some())
        {
            let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
            return false;
        }
        let bytes = core::array::from_fn::<_, 256, _>(|i| {
            // SAFETY: exact admitted two-page FileWindow, no retained client or
            // accepted request. Root broker published metadata before cap send.
            unsafe { ((FRAME + i) as *const u8).read_volatile() }
        });
        let Ok(admitted) = ev_native_editor::admission::decode(&bytes, nonce, facts) else {
            let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
            return false;
        };
        let selection = admitted.selection;
        if rt::inspect(cap, 8).status != 0 {
            let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
            return false;
        }
        let keep = self.handoff.receive_mode() == Some(ReleaseMode::KeepDocument);
        if keep
            && (self.editor.is_none()
                || !admitted.supports_staged_write()
                || selection.revision >= u64::MAX - 1)
        {
            let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
            return false;
        }
        // SAFETY: independently admitted FileWindow mapping and received SEND
        // cap paired with the Root-installed route. This actor stopped all old
        // window access before Released; Root must independently retire that
        // kernel branch and reconcile the service before changing the route.
        let Ok(link) = (unsafe { NativeLink::from_admitted_mapping(FRAME, 8192, cap) }) else {
            let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
            return false;
        };
        if keep {
            if self
                .editor
                .as_mut()
                .unwrap()
                .retarget_for_save(selection.revision, true)
                .is_err()
            {
                let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
                return false;
            }
        } else {
            self.editor = None;
        }
        let loading = if keep {
            None
        } else {
            let Ok(transfer) = transfer(bound, u64::from(selection.length)) else {
                let _ = rt::call(rt::syscall::CLOSE, cap, 0, 0);
                return false;
            };
            Some(Loading {
                selection,
                offset: 0,
                hash: Sha256::new(),
                transfer,
            })
        };
        self.file = Some(FileClient::new(link));
        self.file_contract = admitted.file;
        self.handoff.received();
        self.loading = loading;
        self.selection = Some(selection);
        self.error = None;
        if keep {
            if self.start_save(bound).is_err() {
                self.failed();
            }
        } else {
            self.start = 0;
        }
        self.paint = true;
        true
    }
    fn release_file(&mut self, nonce: u32, mode: ReleaseMode, events: u64, bound: u64) {
        use ev_native_editor::ReleaseAction;
        match self.handoff.release_action(nonce, mode) {
            Some(ReleaseAction::RepeatAck) => {
                notify(events, Event::Released { nonce }, bound);
                return;
            }
            Some(ReleaseAction::Close) => (),
            None => {
                notify(events, Event::Refused(7), bound);
                return;
            }
        }
        if self.loading.is_some()
            || self.error.is_some()
            || self.file.as_ref().is_some_and(FileClient::fenced)
            || self.editor.as_ref().is_some_and(|e| e.pending().is_some())
            || (mode == ReleaseMode::KeepDocument && self.editor.is_none())
            || (mode == ReleaseMode::CloseSaved
                && self
                    .editor
                    .as_ref()
                    .is_some_and(|e| e.close() != Close::Ready))
        {
            notify(events, Event::Refused(7), bound);
            return;
        }
        if let Some(mut file) = self.file.take()
            && file.close_quiescent().is_err()
        {
            self.file = Some(file);
            self.failed();
            notify(events, Event::Refused(7), bound);
            return;
        }
        self.save_transfer = None;
        self.file_contract = None;
        self.save_verified = None;
        if mode != ReleaseMode::KeepDocument {
            self.editor = None;
            self.selection = None;
            self.start = 0;
        }
        self.handoff.released(nonce, mode);
        self.paint = true;
        // Protocol acknowledgment only: this actor has stopped touching FRAME.
        // It conveys no kernel revocation, loan-return or device-flush proof.
        notify(events, Event::Released { nonce }, bound);
    }
    fn load_step(&mut self) -> Result<(), ()> {
        let load = self.loading.as_mut().ok_or(())?;
        // This is a distinct new Read; no accepted request is renewed. The
        // FileClient independently refuses reuse while its old loan is held.
        let deadline = load.transfer.next_request(now()).map_err(|_| ())?;
        let mut bytes = [0; 4096];
        let amount = (load.selection.length - load.offset).clamp(1, 4096);
        let reply = self
            .file
            .as_mut()
            .ok_or(())?
            .issue(
                load.selection.revision,
                Method::Read {
                    offset: load.offset,
                    length: amount,
                },
                deadline,
                &[],
                &mut bytes,
            )
            .map_err(|_| ())?
            .response;
        load.transfer.check(now()).map_err(|_| ())?;
        if reply.outcome != Outcome::Completed
            || reply.file_length != load.selection.length
            || reply.length
                != load
                    .selection
                    .length
                    .saturating_sub(load.offset)
                    .min(amount)
        {
            return Err(());
        }
        let n = reply.length as usize;
        load.hash.update(&bytes[..n]);
        require(self.editor.is_none(), 1408);
        // SAFETY: the sole resident buffer has no current Editor/reference;
        // checked file range fits1MiB, bytes came from exact verified chunk.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (*DOCUMENT.0.get()).as_mut_ptr().add(load.offset as usize),
                n,
            )
        };
        load.offset += reply.length;
        if load.offset == load.selection.length {
            if <[u8; 32]>::from(load.hash.clone().finalize()) != load.selection.digest {
                return Err(());
            }
            // SAFETY: claim is unique, loading is complete, no previous Editor
            // borrows exist. This mutable borrow lasts through this open session.
            let resident = unsafe { &mut *DOCUMENT.0.get() };
            self.editor = Some(
                Editor::open(
                    resident,
                    load.selection.length as usize,
                    load.selection.revision,
                    load.selection.access == Access::ReadWrite,
                )
                .map_err(|_| ())?,
            );
            load.transfer.check(now()).map_err(|_| ())?;
            self.loading = None;
            self.follow_caret = true;
            self.bump_view();
        }
        Ok(())
    }
    fn start_save(&mut self, bound: u64) -> Result<(), ()> {
        if self.error.is_some()
            || self.surface.fenced
            || !ev_native_editor::admission::supports_staged_verify(self.file_contract)
        {
            return Err(());
        }
        let file = self.file.as_ref().ok_or(())?;
        let nonce = file.next_mutation_nonce().map_err(|_| ())?;
        // Capture before begin_save hashes/freezes the proposal. All chunks,
        // the one accepted Commit and independent readback share this horizon.
        let transfer = transfer(bound, self.editor.as_ref().ok_or(())?.bytes().len() as u64)?;
        self.editor
            .as_mut()
            .ok_or(())?
            .begin_save(nonce)
            .map_err(|_| ())?;
        self.save_transfer = Some(transfer);
        self.save_verified = Some(0);
        self.paint = true;
        Ok(())
    }
    fn cancel_save(&mut self) -> Result<(), ()> {
        if self.error.is_some()
            || self.loading.is_some()
            || self.surface.fenced
            || self.paint
            || !self.semantic_accepted
            || !self.cancel_presented
            || self.file.as_ref().is_none_or(FileClient::fenced)
            || self.editor.as_ref().is_none_or(|e| !e.can_cancel_save())
        {
            return Err(());
        }
        if self.save_transfer.as_mut().ok_or(())?.check(now()).is_err() {
            self.failed();
            return Err(());
        }
        let editor = self.editor.as_mut().ok_or(())?;
        let proposal = editor.pending().ok_or(())?.proposal;
        editor.cancel_save(proposal).map_err(|_| ())?;
        self.bump_view();
        Ok(())
    }
    fn save_step(&mut self) -> Result<(), ()> {
        let editor = self.editor.as_mut().ok_or(())?;
        let p = editor.pending().ok_or(())?;
        let file = self.file.as_mut().ok_or(())?;
        let deadline = self
            .save_transfer
            .as_mut()
            .ok_or(())?
            .next_request(now())
            .map_err(|_| ())?;
        let mut bytes = [0; 4096];
        let complete=|r:Result<ev_workspace_client::Completion,ev_workspace_client::Error>|->Result<Response,()>{let r=r.map_err(|_|())?.response;if r.outcome!=Outcome::Completed{return Err(());}Ok(r)};
        match p.phase {
            Phase::Begin => {
                let completion = file
                    .issue(
                        p.proposal.base_revision,
                        Method::BeginWrite {
                            length: p.proposal.length as u32,
                            digest: p.proposal.digest,
                        },
                        deadline,
                        &[],
                        &mut [],
                    )
                    .map_err(|_| ())?;
                if let Some(reason) = ev_native_editor::save::settled_begin_refusal(
                    p,
                    completion,
                    file.fenced(),
                    deadline,
                ) {
                    editor.begin_refused(p.proposal, reason).map_err(|_| ())?;
                    // Only this exact settled Begin has no accepted stage.
                    // Drop its scheduling cursor, never an accepted request,
                    // token or post-Begin frozen proposal. No retry follows.
                    self.save_transfer = None;
                    self.save_verified = None;
                    self.paint = true;
                    return Ok(());
                }
                let r = complete(Ok(completion))?;
                editor
                    .begin_confirmed(r.transfer_id, u64::from(r.file_length), r.digest)
                    .map_err(|_| ())?;
            }
            Phase::Chunks => {
                let chunk = editor.next_chunk(&mut bytes).map_err(|_| ())?;
                let _ = complete(file.issue(
                    p.proposal.base_revision,
                    Method::WriteChunk {
                        transfer_id: p.transfer,
                        offset: chunk.offset as u32,
                        length: chunk.length,
                        digest: chunk.digest,
                    },
                    deadline,
                    &bytes[..chunk.length as usize],
                    &mut [],
                ))?;
                editor.chunk_confirmed(p.transfer, chunk).map_err(|_| ())?;
            }
            Phase::CommitReady => {
                if let Some(offset) = self.save_verified {
                    let r = complete(file.issue(
                        p.proposal.base_revision,
                        Method::Verify {
                            transfer_id: p.transfer,
                            offset,
                            length: p.proposal.length as u32,
                            digest: p.proposal.digest,
                        },
                        deadline,
                        &[],
                        &mut [],
                    ))?;
                    self.save_verified =
                        (u64::from(r.offset) < p.proposal.length).then_some(r.offset);
                    // This is a completed distinct verification request. The
                    // exact frozen proposal remains CommitReady until all
                    // bytes are verified; no accepted Commit exists yet.
                    return Ok(());
                }
                let proposal = editor.commit_request().map_err(|_| ())?;
                let r = complete(file.issue(
                    proposal.base_revision,
                    Method::Commit {
                        transfer_id: p.transfer,
                        length: proposal.length as u32,
                        digest: proposal.digest,
                    },
                    deadline,
                    &[],
                    &mut [],
                ))?;
                editor
                    .commit_confirmed(Receipt {
                        transfer: r.transfer_id,
                        revision: r.revision,
                        length: u64::from(r.file_length),
                        digest: r.digest,
                    })
                    .map_err(|_| ())?;
            }
            Phase::Verify => {
                let amount = (p.proposal.length - p.read_back).clamp(1, 4096) as u32;
                let r = complete(file.issue(
                    p.proposal.revision,
                    Method::Read {
                        offset: p.read_back as u32,
                        length: amount,
                    },
                    deadline,
                    &[],
                    &mut bytes,
                ))?;
                if u64::from(r.file_length) != p.proposal.length {
                    return Err(());
                }
                editor
                    .readback(r.revision, p.read_back, &bytes[..r.length as usize])
                    .map_err(|_| ())?;
                if p.read_back + u64::from(r.length) == p.proposal.length {
                    self.save_transfer
                        .as_mut()
                        .ok_or(())?
                        .check(now())
                        .map_err(|_| ())?;
                    editor.finish_readback().map_err(|_| ())?;
                    self.save_transfer = None;
                }
            }
            Phase::AbortReady => {
                let request = editor
                    .abort_request(file.next_mutation_nonce().map_err(|_| ())?)
                    .map_err(|_| ())?;
                let completion = file
                    .issue(
                        request.base_revision,
                        Method::Abort {
                            transfer_id: request.transfer,
                        },
                        deadline,
                        &[],
                        &mut [],
                    )
                    .map_err(|_| ())?;
                let receipt = ev_native_editor::save::confirmed_abort(
                    editor.pending().ok_or(())?,
                    completion,
                    file.fenced(),
                    deadline,
                )
                .ok_or(())?;
                self.save_transfer
                    .as_mut()
                    .ok_or(())?
                    .check(now())
                    .map_err(|_| ())?;
                editor.abort_confirmed(receipt).map_err(|_| ())?;
                self.save_transfer = None;
                self.save_verified = None;
                self.paint = true;
            }
            _ => return Err(()),
        }
        // Saving is already painted by start_save. Chunk/Commit progress does
        // not change this frozen document's pixels. Preserve other pending
        // focus/geometry paints and redraw only the verified Saved transition.
        self.paint |= editor.status() == Status::Saved;
        Ok(())
    }
    fn control(&mut self, command: Command, events: u64, bound: u64) {
        if ev_native_editor::save::is_cancel_action(command, self.cancel_presented) {
            if self.cancel_save().is_err() {
                notify(events, Event::Refused(8), bound);
            }
            return; // cancellation can never fall through into Close
        }
        if self.error.is_some()
            && matches!(
                command,
                Command::Insert(_)
                    | Command::Navigate { .. }
                    | Command::SelectAll
                    | Command::Save
                    | Command::Activate(2)
            )
        {
            notify(events, Event::Refused(6), bound);
            return;
        }
        match command {
            Command::ReleaseFile { nonce, mode } => self.release_file(nonce, mode, events, bound),
            Command::Configure {
                instance,
                mapping_epoch,
            } => {
                if !matches!(instance, 2 | 3) || self.configured {
                    notify(events, Event::Refused(1), bound);
                    return;
                }
                self.surface.header.instance = u16::from(instance);
                self.surface.header.surface_object = if instance == 2 { 9 } else { 30 };
                self.surface.header.mapping_epoch = u64::from(mapping_epoch);
                self.configured = true;
                self.scene_ready = false;
                notify(events, Event::Ready(instance), bound);
            }
            Command::Resize { width, height } => {
                self.surface.header.width = u32::from(width);
                self.surface.header.height = u32::from(height);
                self.surface.header.stride_bytes = u32::from(width) * 4;
                self.surface.header.payload_bytes = u32::from(width) * u32::from(height) * 4;
                self.scene_ready = false;
                self.bump_view();
            }
            Command::ScenePart { high: false, word } => {
                self.scene_low = Some(word);
                self.scene_ready = false;
            }
            Command::ScenePart { high: true, word } => {
                if let Some(low) = self.scene_low.take() {
                    let revision = (u64::from(word) << 32) | u64::from(low);
                    if !matches!(revision, 0 | u64::MAX) {
                        self.surface.header.model_revision = revision;
                        self.scene_ready = true;
                        self.paint = true;
                    }
                }
            }
            Command::Focus(focused) => {
                self.focused = focused;
                self.follow_caret = focused;
                self.bump_view();
            }
            Command::Save | Command::Activate(2) => {
                if self.start_save(bound).is_err() {
                    notify(events, Event::Refused(2), bound);
                }
            }
            Command::Activate(1) => notify(events, Event::Open, bound),
            Command::Activate(3) => notify(events, Event::SaveAs, bound),
            Command::Close { .. } | Command::Activate(4) if self.loading.is_none() => {
                let discard = matches!(command, Command::Close { discard: true });
                match self.editor.as_ref().map_or(Close::Ready, Editor::close) {
                    Close::RecoveryRequired => notify(events, Event::Refused(3), bound),
                    Close::ConfirmDiscard if !discard => {
                        notify(events, Event::CloseNeedsDiscard, bound)
                    }
                    _ => {
                        if self.surface.fenced {
                            notify(events, Event::Refused(3), bound);
                            return;
                        }
                        if let Some(mut file) = self.file.take()
                            && file.close_quiescent().is_err()
                        {
                            self.file = Some(file);
                            notify(events, Event::Refused(3), bound);
                            return;
                        }
                        notify(events, Event::Closed, bound);
                        rt::exit(0)
                    }
                }
            }
            Command::Insert(c) if self.focused => {
                if let Some(editor) = self.editor.as_mut() {
                    let mut bytes = [0; 4];
                    if editor.replace(c.encode_utf8(&mut bytes).as_bytes()).is_ok() {
                        self.follow_caret = true;
                        self.bump_view();
                    }
                }
            }
            Command::Navigate { key, extend } if self.focused => {
                if let Some(editor) = self.editor.as_mut() {
                    match key {
                        Navigation::Left => editor.left(extend),
                        Navigation::Right => editor.right(extend),
                        Navigation::Up => editor.vertical(false, extend),
                        Navigation::Down => editor.vertical(true, extend),
                        Navigation::Home => editor.line_home(extend),
                        Navigation::End => editor.line_end(extend),
                        Navigation::Backspace => {
                            let _ = editor.backspace();
                        }
                    }
                    self.follow_caret = true;
                    self.bump_view();
                }
            }
            Command::SelectAll => {
                if let Some(editor) = self.editor.as_mut() {
                    editor.select_all();
                    self.follow_caret = true;
                    self.bump_view();
                }
            }
            Command::Scroll(lines) => {
                if let Some(editor) = self.editor.as_ref() {
                    let mut at = self.start;
                    for _ in 0..lines.unsigned_abs().min(100) {
                        if lines >= 0 {
                            if let Some(n) = editor.text()[at..].find('\n') {
                                at += n + 1;
                            } else {
                                at = editor.bytes().len();
                            }
                        } else {
                            let before = editor.text()[..at]
                                .char_indices()
                                .next_back()
                                .map_or(0, |(i, _)| i);
                            at = editor.text()[..before].rfind('\n').map_or(0, |n| n + 1);
                        }
                    }
                    self.start = at;
                    self.follow_caret = false;
                    self.bump_view();
                }
            }
            _ => (),
        }
    }
}
// SAFETY: one named admitted process entry receives its actual immutable336
// startup page; the selected loader owns all named mappings for this lifetime.
#[unsafe(no_mangle)]
extern "C" fn ev_editor_main(record: u64, length: u64, bound: u64) -> ! {
    require(
        length == ev_userspace_contract::SIZE as u64 && record as usize == BASE + 509 * 4096,
        1410,
    );
    // SAFETY: exact retained initialized readonly startup page checked above.
    let startup = unsafe { core::slice::from_raw_parts(record as *const u8, length as usize) };
    let b = Bootstrap::parse(startup).unwrap_or_else(|_| rt::exit(1411));
    require(
        b.grants().count() == 6
            && [0, 1, 2, 3]
                .map(|i| u64::from_le_bytes(startup[40 + i * 8..48 + i * 8].try_into().unwrap()))
                == resources::JOB_TEMPLATE_LIMITS[3],
        1412,
    );
    let specs = [(1, 7), (2, 8), (2, 8), (2, 272), (1, 7), (2, 272)];
    let mut handles = [0; 6];
    for (i, g) in b.grants().enumerate() {
        require(
            g.selector == i as u64 + 1 && (g.kind, g.rights) == specs[i],
            1413,
        );
        handles[i] = g.handle;
    }
    let facts = self_facts().unwrap_or_else(|_| rt::exit(1414));
    require(
        facts.process == b.process() && facts.registered_incarnation == b.incarnation(),
        1415,
    );
    require(
        CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok(),
        1416,
    );
    let header = Header {
        producer: Producer::Application,
        instance: 2,
        process: facts.process,
        thread: facts.thread,
        incarnation: facts.registered_incarnation,
        surface_object: 9,
        surface_generation: facts.process,
        frame: 1,
        view_revision: 1,
        model_revision: 1,
        width: 320,
        height: 180,
        stride_bytes: 1280,
        payload_bytes: 230400,
        mapping_epoch: 1,
        protected_scope_nonce: 0,
    };
    let mut app = App {
        editor: None,
        file: None,
        file_contract: None,
        selection: None,
        loading: None,
        save_transfer: None,
        save_verified: None,
        cancel_presented: false,
        surface: Surface {
            header,
            fenced: false,
        },
        configured: false,
        scene_ready: false,
        scene_low: None,
        paint: false,
        follow_caret: false,
        focused: false,
        start: 0,
        error: None,
        handoff: ev_native_editor::FileHandoff::default(),
        semantics: SemanticPublisher::new(),
        semantic_accepted: false,
        visible_end: 0,
        ops: native_semantic::Operations::new(),
    };
    let mut last_state = State::NoFile;
    loop {
        require(rt::execution::live(bound, now()), 1417);
        for _ in 0..16 {
            let r = rt::receive(handles[3]);
            if r.status == 2 {
                break;
            }
            require(r.status == 0 && r.capability == 0, 1418);
            let wire = r.value.to_le_bytes();
            if let Ok(frame) = a1::Frame::decode(&wire) {
                if (0x8100..=0x81ff).contains(&frame.field) {
                    native_semantic::control(&mut app, frame, handles[2], bound);
                } else if let Ok(request) = a1::Request::decode(frame) {
                    app.semantic_request(request);
                }
            } else if let Ok(c) = Command::decode(wire) {
                app.control(c, handles[2], bound);
            }
        }
        let r = rt::receive(handles[5]);
        if r.status == 0 {
            require(r.capability != 0, 1419);
            if !app.accept_grant(r.value, r.capability, facts, bound) {
                notify(handles[2], Event::Refused(4), bound);
            }
        } else {
            require(r.status == 2 && r.value == 0 && r.capability == 0, 1420);
        }
        if app.loading.is_some() && app.error.is_none() {
            if app.load_step().is_err() {
                // Retain the exact loading identity/hash/offset/whole horizon
                // and private bytes. A failed call is no loan-return proof.
                app.failed();
            }
        } else if app.editor.as_ref().is_some_and(|e| e.pending().is_some())
            && app.error.is_none()
            && app.save_step().is_err()
        {
            app.failed();
        }
        let state = app.state();
        if state != last_state {
            notify(handles[2], Event::State(state), bound);
            last_state = state;
        }
        if app.paint && app.configured && app.scene_ready && !app.surface.fenced {
            let name = app.selection.as_ref().map(|s| s.name.as_str());
            let view = ev_native_editor::View {
                editor: app.editor.as_ref(),
                name,
                state,
                start: app.start,
                focused: app.focused,
            };
            let mut painted =
                // This model tuple is unchanged during the bounded present.
                ev_native_editor::render(&mut app.surface, view).unwrap_or_else(|_| rt::exit(1421));
            let cancel_offered = ev_native_editor::cancel_available(view);
            if app.follow_caret
                && !painted.caret_visible
                && let Some(editor) = app.editor.as_ref()
            {
                app.start = ev_native_editor::around_caret(
                    editor,
                    app.surface.header.width as usize,
                    app.surface.header.height as usize,
                );
                painted = ev_native_editor::render(
                    &mut app.surface,
                    ev_native_editor::View {
                        start: app.start,
                        ..view
                    },
                )
                .unwrap_or_else(|_| rt::exit(1421));
            }
            app.follow_caret = false;
            app.paint = false;
            match app.surface.present(handles[1], bound) {
                Ok(true) => {
                    app.semantic_accepted = true;
                    app.cancel_presented = cancel_offered;
                    app.visible_end = painted.end;
                }
                Ok(false) => {
                    app.semantic_accepted = false;
                    app.cancel_presented = false;
                    app.scene_ready = false;
                }
                Err(()) => {
                    app.cancel_presented = false;
                    app.failed();
                    notify(handles[2], Event::Refused(5), bound);
                }
            }
        }
        app.pump_semantics(handles[2]);
        app.pump_semantic_operation(handles[2]);
        let r = rt::yield_now();
        require(r.status == 0 && r.value == 0 && r.capability == 0, 1422);
    }
}
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    rt::exit(1499)
}
