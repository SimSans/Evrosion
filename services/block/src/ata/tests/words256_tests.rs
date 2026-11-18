//! Real ATA state machine over a scripted port device, not native acceptance.
use super::*;
struct BulkBus {
    bus: Bus,
    groups: Vec<(bool, u16, u64)>,
    clocks: usize,
    fail_word: Option<usize>,
}
impl BulkBus {
    fn new() -> Self {
        let mut bus = Bus::new();
        bus.identify = workspace_identity();
        Self {
            bus,
            groups: Vec::new(),
            clocks: 0,
            fail_word: None,
        }
    }
}
impl Ports for BulkBus {
    fn input(&mut self, port: u16, width: u8) -> Result<u32, u64> {
        self.bus.input(port, width)
    }
    fn output(&mut self, port: u16, width: u8, value: u32) -> Result<(), u64> {
        self.bus.output(port, width, value)
    }
    fn now(&mut self) -> Result<u64, u64> {
        self.clocks += 1;
        self.bus.now()
    }
    fn yield_now(&mut self) -> Result<(), u64> {
        self.bus.yield_now()
    }
    fn input_words256(&mut self, port: u16, cut: u64, bytes: &mut [u8; 512]) -> Result<(), u64> {
        assert!(cut > self.bus.now && cut - self.bus.now <= 1024);
        self.groups.push((false, port, cut));
        let mut scratch = [0; 512];
        for (i, pair) in scratch.as_chunks_mut::<2>().0.iter_mut().enumerate() {
            if self.fail_word == Some(i) {
                return Err(190);
            }
            pair.copy_from_slice(&(self.bus.input(port, 2)? as u16).to_le_bytes());
        }
        *bytes = scratch;
        Ok(())
    }
    fn output_words256(&mut self, port: u16, cut: u64, bytes: &[u8; 512]) -> Result<(), u64> {
        assert!(cut > self.bus.now && cut - self.bus.now <= 1024);
        self.groups.push((true, port, cut));
        for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            if self.fail_word == Some(i) {
                return Err(191);
            }
            self.bus
                .output(port, 2, u32::from(u16::from_le_bytes(*pair)))?;
        }
        Ok(())
    }
}
#[test]
fn full_sector_cut_preserves_original_horizon_and_reserves_exact_256_units_once() {
    let mut io = BulkBus::new();
    let mut budget = Budget::new(&mut io, 100_000).unwrap();
    for now in [1, 100, 5000, 99_800, 99_999] {
        io.bus.now = now;
        let (polls, clocks) = (budget.polls, io.clocks);
        assert_eq!(budget.words256_cut(&mut io), Ok(100_000.min(now + 1024)));
        assert_eq!(
            (budget.deadline, budget.polls, io.clocks),
            (100_000, polls - 256, clocks + 1)
        );
        assert!(io.bus.trace.is_empty());
    }
    budget.polls = 255;
    let clocks = io.clocks;
    assert_eq!(budget.words256_cut(&mut io), Err(Error::PollBudget));
    assert_eq!((budget.polls, io.clocks), (255, clocks));
}
#[test]
fn selected_identity_read_write_flush_readback_use_one_fixed_group_each_without_legacy_widening() {
    let mut disk = AtaPio::new_workspace(BulkBus::new());
    disk.reset(8192).unwrap();
    disk.identify(8192).unwrap();
    disk.write_sector(0, &RECORD, 8192).unwrap();
    disk.flush(8192).unwrap();
    let mut bytes = [0; 512];
    disk.read_sector(0, &mut bytes, 8192).unwrap();
    assert_eq!(bytes, RECORD);
    assert_eq!(disk.io.groups.len(), 3); // IDENTIFY, WRITE, READ.
    assert_eq!(
        disk.io.groups.iter().map(|g| g.0).collect::<Vec<_>>(),
        [false, true, false]
    );
    assert!(disk.io.groups.iter().all(|g| g.1 == DATA && g.2 <= 8192));
    assert_eq!(disk.io.bus.completed_flushes, 1);
    let words = disk
        .io
        .bus
        .trace
        .iter()
        .filter(|op| matches!(op, Op::Input(DATA, 2) | Op::Output(DATA, 2, _)))
        .count();
    assert_eq!(words, 3 * 256);
    let mut io = BulkBus::new();
    io.bus.identify = identify_bytes();
    let mut legacy = AtaPio::new(io);
    legacy.identify(8192).unwrap();
    legacy.read_sector(0, &mut bytes, 8192).unwrap();
    assert!(legacy.io.groups.is_empty()); // Original profile still Word4.
}
#[test]
fn input_prefix_error_publishes_no_sector_and_never_replays_or_claims_not_issued() {
    let mut disk = AtaPio::new_workspace(BulkBus::new());
    disk.identify(8192).unwrap();
    disk.io.fail_word = Some(129);
    let mut bytes = [0xa5; 512];
    let failure = disk.read_sector(0, &mut bytes, 8192).unwrap_err();
    assert_eq!(
        failure,
        Failure {
            error: Error::Io(190),
            progress: Progress::MayHaveExecuted
        }
    );
    assert_eq!(bytes, [0xa5; 512]);
    assert_eq!(disk.io.bus.position, 258);
    let calls = disk.io.bus.trace.len();
    assert_eq!(
        disk.read_sector(0, &mut bytes, 8192).unwrap_err(),
        Failure {
            error: Error::NeedsReset,
            progress: Progress::NotIssued
        }
    );
    assert_eq!(disk.io.bus.trace.len(), calls);
}
#[test]
fn output_prefix_error_preserves_uncertainty_and_deadline_preflight_issues_no_data() {
    let mut disk = AtaPio::new_workspace(BulkBus::new());
    disk.identify(8192).unwrap();
    let calls = disk.io.bus.trace.len();
    assert_eq!(
        disk.write_sector(0, &RECORD, 0).unwrap_err().progress,
        Progress::NotIssued
    );
    assert_eq!(disk.io.bus.trace.len(), calls);
    disk.io.fail_word = Some(129);
    assert_eq!(
        disk.write_sector(0, &RECORD, 8192).unwrap_err(),
        Failure {
            error: Error::Io(191),
            progress: Progress::MayHaveExecuted
        }
    );
    assert_eq!(disk.io.bus.position, 258);
    assert_eq!(disk.io.bus.disk[0], SEED); // Model publication waits for all words.
    assert_eq!(disk.io.groups.last().unwrap().2, 1024);
}
