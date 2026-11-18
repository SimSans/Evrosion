//! Small trusted adapters over the SAME resident IO/Commit owners. These do
//! not choose a publisher, clock, URL, replay state, Backend or new capability.
use super::*;
use ev_content_store::Object;
impl<B: Backend> Update<B> {
    /// A coordinator refusal is releasable only at a settled unpublished IO
    /// boundary. Abandon preserves reservations/high-water and every actual
    /// Arena/Backend fence; it never rolls back an accepted operation.
    #[inline(never)]
    pub fn refuse_fetch(&mut self, now: u64) {
        let observed = self.observe(now);
        // Prepared output has no IO owner; this never clears actual debt.
        self.commit.discard_authorized();
        if !matches!(self.command, Some(Command::Fetch | Command::Local))
            || !self.commit.is_empty()
            || !self.cold.is_empty()
        {
            return;
        }
        let store = match self.io.take() {
            Some(Io::Store(store)) => store,
            Some(Io::Put(put)) => put.abandon(),
            Some(Io::Read(read)) => read.abandon(),
            other => {
                self.io = other;
                return;
            }
        };
        let settled = observed
            && !self.clock_fenced
            && !store.has_unresolved_io()
            && !matches!(self.outcome, Some(Outcome::Failed(_)));
        self.io = Some(Io::Store(store));
        if settled {
            self.settled_auth_refusal = true;
            self.fail(Failure::Authentication);
        }
    }
    /// Borrow only the actual authenticated, quiescent Store at its current
    /// head. A detached local identity snapshot cannot manufacture this view.
    pub fn authorization_store(&self) -> Option<&acq::Store<B>> {
        if !matches!(self.command, Some(Command::Fetch | Command::Local))
            || self.phase != Phase::Done
            || !matches!(self.outcome, Some(Outcome::Complete(_)))
        {
            return None;
        }
        match self.io.as_ref() {
            Some(Io::Store(store))
                if !store.has_unresolved_io() && store.authorization_binding().is_some() =>
            {
                Some(store)
            }
            _ => None,
        }
    }
    /// Disjoint borrows of the actual Store and its existing resident output
    /// workspace; no detached copy or extra publication owner is introduced.
    pub fn authorization_parts(&mut self) -> Option<(&acq::Store<B>, &mut acq::Commit<B>)> {
        if !matches!(self.command, Some(Command::Fetch | Command::Local))
            || self.phase != Phase::Done
            || !matches!(self.outcome, Some(Outcome::Complete(_)))
        {
            return None;
        }
        match self.io.as_ref() {
            Some(Io::Store(store))
                if !store.has_unresolved_io() && store.authorization_binding().is_some() =>
            {
                Some((store, &mut self.commit))
            }
            _ => None,
        }
    }
    #[inline(never)]
    pub fn begin_prepared_fetch(&mut self, now: u64) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.authorization_store().is_none() || !self.commit.has_authorized() {
            return Err(Failure::Authentication);
        }
        let store = self.store();
        match self
            .commit
            .begin_authorized(store, self.transfer.unwrap(), now)
        {
            Ok(()) => {
                self.outcome = None;
                self.phase = Phase::Commit;
                self.stage = Stage::Checkpoint;
                Ok(())
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Authentication);
                Err(Failure::Authentication)
            }
        }
    }
    #[inline(never)]
    pub fn begin_fetch_put(
        &mut self,
        length: u64,
        hash: [u8; 32],
        now: u64,
    ) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.authorization_store().is_none() {
            return Err(Failure::Authentication);
        }
        match self
            .store()
            .begin_put(length, hash, self.transfer.unwrap(), now)
        {
            Ok(put) => {
                self.io = Some(Io::Put(put));
                Ok(())
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
                Err(Failure::Storage)
            }
        }
    }
    pub fn fetch_put_remaining(&self) -> Option<u64> {
        match self.io.as_ref() {
            Some(Io::Put(put)) if matches!(self.command, Some(Command::Fetch | Command::Local)) => {
                Some(put.remaining())
            }
            _ => None,
        }
    }
    pub fn fetch_expected_object(&self) -> Option<Object> {
        match self.io.as_ref() {
            Some(Io::Read(read))
                if matches!(self.command, Some(Command::Fetch | Command::Local)) =>
            {
                read.expected_object()
            }
            _ => None,
        }
    }
    #[inline(never)]
    pub fn write_fetch_chunk(&mut self, bytes: &[u8], now: u64) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if !matches!(self.command, Some(Command::Fetch | Command::Local)) {
            return Err(Failure::Authentication);
        }
        let Some(Io::Put(put)) = self.io.as_mut() else {
            return Err(Failure::Authentication);
        };
        if put.write_chunk(bytes, now).is_err() {
            self.fail(Failure::Storage);
            return Err(Failure::Storage);
        }
        Ok(())
    }
    #[inline(never)]
    pub fn seal_fetch_object(&mut self, now: u64) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.fetch_put_remaining() != Some(0) {
            return Err(Failure::Authentication);
        }
        match self.put().seal(now) {
            Ok(read) => {
                self.io = Some(Io::Read(read));
                Ok(())
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
                Err(Failure::Storage)
            }
        }
    }
    /// Read only an already-authenticated continuity object. Remote metadata
    /// objects enter via the actual Put->Reader path, never server coordinates.
    #[inline(never)]
    pub fn begin_fetch_root_read(&mut self, now: u64) -> Result<Object, Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        let object = self
            .authorization_store()
            .and_then(|store| store.snapshot())
            .and_then(|s| s.current_root_object())
            .ok_or(Failure::Authentication)?;
        match self.store().begin_read(object, self.transfer.unwrap(), now) {
            Ok(read) => {
                self.io = Some(Io::Read(read));
                Ok(object)
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
                Err(Failure::Storage)
            }
        }
    }
    /// Finish actual full-hash readback and retain that same Store. The returned
    /// Object comes from the verified reader, never an untrusted response.
    #[inline(never)]
    pub fn finish_fetch_object(&mut self, now: u64) -> Result<Object, Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if !matches!(self.command, Some(Command::Fetch | Command::Local))
            || self.retained_remaining() != Some(0)
        {
            return Err(Failure::Authentication);
        }
        match self.read().finish() {
            Ok(stored) => {
                let object = stored.object;
                self.io = Some(Io::Store(stored.store));
                Ok(object)
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Storage);
                Err(Failure::Storage)
            }
        }
    }
    #[inline(never)]
    pub fn begin_fetch_decision(
        &mut self,
        decision: acq::Decision,
        now: u64,
    ) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.authorization_store().is_none() || !self.commit.is_empty() {
            return Err(Failure::Authentication);
        }
        let store = self.store();
        match decision.begin_into(store, &mut self.commit, self.transfer.unwrap(), now) {
            Ok(()) => {
                self.outcome = None;
                self.phase = Phase::Commit;
                self.stage = Stage::Checkpoint;
                Ok(())
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Authentication);
                Err(Failure::Authentication)
            }
        }
    }
}

impl<T: ev_block_service::store_io::Wire, W: ev_block_service::store_io::Window>
    Update<content::OwnedBackend<T, W>>
{
    /// Selection decisions retain their private actual Registry/Backend loan
    /// receipt until canonical Commit consumption. No generic conversion.
    #[inline(never)]
    pub fn begin_selection_decision(
        &mut self,
        decision: acq::SelectionDecision,
        state: &crate::native_plan::state::State<T, W>,
        now: u64,
    ) -> Result<(), Failure> {
        if !self.observe(now) {
            return Err(Failure::Clock);
        }
        if self.authorization_store().is_none() || !self.commit.is_empty() {
            return Err(Failure::Authentication);
        }
        let store = self.store();
        match decision.begin_into(store, state, &mut self.commit, self.transfer.unwrap(), now) {
            Ok(()) => {
                self.outcome = None;
                self.phase = Phase::Commit;
                self.stage = Stage::Checkpoint;
                Ok(())
            }
            Err(r) => {
                self.io = Some(Io::Store(r.owner));
                self.fail(Failure::Authentication);
                Err(Failure::Authentication)
            }
        }
    }
}
