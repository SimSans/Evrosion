//! Actual readonly banks: integrity before boot; full contract availability
//! only after an actual Workspace probe and before any App delegation.
use super::*;
impl Root<'_> {
    pub(super) fn development_file_allowed(&self, index: usize, writable: bool) -> bool {
        if !matches!(index, 1 | 2) {
            return false;
        }
        let bytes = match self.development_software(index) {
            Ok(Some((bytes, _, _))) => bytes,
            Ok(None) => match self
                .catalogue
                .packages()
                .find(|(k, _)| *k == v5::catalogue::PackageKind::Editor)
            {
                Some((_, p)) => self.package_bytes(p),
                None => return false,
            },
            Err(()) => return false,
        };
        ev_zion::Package::parse(bytes)
            .is_ok_and(|p| ev_workspace_root::development::allows_file(&p, writable))
    }
    fn package_bytes(&self, expected: v5::catalogue::Package) -> &[u8] {
        let count = usize::try_from(expected.bytes).unwrap_or_else(|_| rt::exit(1665));
        let offset = expected.offset as usize;
        require(expected.bytes <= v5::resources::PACKAGE_MAX_BYTES, 1665);
        require(
            offset
                .checked_add(count)
                .is_some_and(|n| n <= expected.bank.capacity_bytes() as usize),
            1665,
        );
        let address = BASE + expected.bank.first_page() as usize * 4096 + offset;
        // SAFETY: actual V5 loader's retained readonly selected package bank,
        // canonical catalogue bounds and exact known location checked above.
        unsafe { core::slice::from_raw_parts(address as *const u8, count) }
    }
    #[inline(never)]
    pub(super) fn check_catalogue_structure(&self) {
        for (kind, expected) in self.catalogue.packages() {
            ev_workspace_root::requirements::catalogue_structure(
                self.package_bytes(expected),
                expected,
                kind.image(),
            )
            .unwrap_or_else(|_| rt::exit(1666));
        }
    }
    pub(super) fn workspace_service_identity(
        &self,
    ) -> Result<ev_workspace_root::requirements::ServiceIdentity, ()> {
        let actor = self.actors[Child::Workspace.index()].ok_or(())?;
        if !actor.ready || actor.failed {
            return Err(());
        }
        let measured = self.catalogue.image(Child::Workspace.image_slot());
        let service = ev_workspace_root::requirements::ServiceIdentity {
            control: actor.control,
            identity: actor.identity,
            endpoint: self.channel(Channel::RootWorkspaceControl),
            epoch: self.bootstrap.context().epoch,
            mapping_epoch: actor.mapping_epoch,
            image: measured.image,
            descriptor: measured.descriptor,
        };
        if !service.valid() {
            return Err(());
        }
        Ok(service)
    }
    pub(super) fn workspace_file_support(
        &mut self,
    ) -> Result<ev_userspace_contract::file_v2::Support, ()> {
        let service = self.workspace_service_identity()?;
        self.workspace.file_support_for(service)
    }
    #[inline(never)]
    pub(super) fn negotiate_workspace_file_contract_and_packages(&mut self) {
        let service = self
            .workspace_service_identity()
            .unwrap_or_else(|_| rt::exit(1667));
        let token = self.bootstrap.context().epoch;
        let cut = deadline(v5::resources::FILE_TRANSACTION_TICKS);
        self.workspace
            .probe_file_contract(service, token, cut)
            .unwrap_or_else(|_| rt::exit(1667));
        let file = self
            .workspace_file_support()
            .unwrap_or_else(|_| rt::exit(1667));
        // The A1 adapter is part of this executable; File support instead came
        // from the actual live Workspace reply above, never its source constant.
        let loaded = ev_workspace_root::requirements::LoadedContracts {
            semantic_tree: true,
            file: Some(file),
        };
        for (kind, expected) in self.catalogue.packages() {
            ev_workspace_root::requirements::catalogue_package(
                self.package_bytes(expected),
                expected,
                kind.image(),
                &loaded,
            )
            .unwrap_or_else(|_| rt::exit(1666));
        }
        require(self.workspace_file_support().is_ok(), 1667);
    }
    /// Metadata requirements are rechecked against the current actual service
    /// before binding. This creates no Kernel44 authority or release proof.
    pub(super) fn bind_workspace_file(
        &mut self,
        index: usize,
        bind: ev_workspace_service::control::Bind,
        cut: u64,
    ) -> Result<ev_workspace_service::control::Response, ()> {
        use ev_workspace_service::control::{Command, FileRequirement};
        if !matches!(index, 1 | 2) || usize::from(bind.slot) != index {
            return Err(());
        }
        let actor = self.actor(app_child(index).ok_or(())?);
        if (
            bind.target_process,
            bind.target_thread,
            bind.target_registered_token,
        ) != (
            actor.identity.process,
            actor.identity.thread,
            actor.identity.registered,
        ) {
            return Err(());
        }
        let service = self.workspace_service_identity()?;
        let file = self.workspace.file_support_for(service)?;
        let loaded = ev_workspace_root::requirements::LoadedContracts {
            semantic_tree: true,
            file: Some(file),
        };
        if !self.development_file_allowed(
            index,
            bind.rights == ev_workspace_service::Rights::ReadWrite,
        ) {
            return Err(());
        }
        if let Some((bytes, expected, _)) = self.development_software(index)? {
            let support = ev_workspace_root::requirements::PrivateDataContracts::new(
                &loaded,
                self.app_data_available(),
            );
            let checked = ev_workspace_root::requirements::private_file_app(bytes, &support)
                .map_err(|_| ())?;
            if ev_workspace_root::development::Source::of(checked.package()) != expected {
                return Err(());
            }
            let contract = checked
                .package()
                .app()
                .contracts()
                .find(|c| c.name == ev_userspace_contract::file_v2::INTERFACE && c.major == 2)
                .ok_or(())?;
            let requirement = FileRequirement {
                minimum_minor: contract.minimum_minor,
                features: contract.features,
            };
            return self
                .workspace
                .bind_contract_until(service, bind, requirement, cut);
        }
        let (kind, expected) = self
            .catalogue
            .packages()
            .find(|(kind, _)| *kind == v5::catalogue::PackageKind::Editor)
            .ok_or(())?;
        let checked = ev_workspace_root::requirements::catalogue_package(
            self.package_bytes(expected),
            expected,
            kind.image(),
            &loaded,
        )
        .map_err(|_| ())?;
        let contract = checked
            .package()
            .app()
            .contracts()
            .find(|c| c.name == ev_userspace_contract::file_v2::INTERFACE && c.major == 2)
            .ok_or(())?;
        let requirement = FileRequirement {
            minimum_minor: contract.minimum_minor,
            features: contract.features,
        };
        if requirement.minimum_minor != 0 || requirement.features != 0 {
            self.workspace
                .bind_contract_until(service, bind, requirement, cut)
        } else {
            self.workspace
                .control_until(service.endpoint, Command::Bind(bind), cut)
        }
    }
}
