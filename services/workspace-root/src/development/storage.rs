//! The actual protected installer storage core, shared by native Root and tests.
//! An exclusive Root owner, independently captured approval and exact immutable
//! package are required. Refusal never formats, resets ownership or retries.
use super::{Approval, Intent, Source};
use crate::{
    app_data::{Owner, Region, descriptor},
    requirements::PrivateDataContracts,
};
use ev_app_registry::{Change, Packages, Policy, Prepared, Registry};
use ev_block_service::store_io::{Window, Wire};
use ev_store::{BootPolicy, SectorIo, Store};
use ev_zion::Package;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Refused,
    NotInstalled,
    Retained,
}
struct OnePackage<'a> {
    package: Package<'a>,
}
impl Packages for OnePackage<'_> {
    fn resolve(&self, id: [u8; 32]) -> Option<&[u8]> {
        (id == self.package.id().bytes()).then_some(self.package.bytes())
    }
    fn parsed(&self, id: [u8; 32]) -> Option<&Package<'_>> {
        (id == self.package.id().bytes()).then_some(&self.package)
    }
}
fn policy(package: &Package<'_>) -> Policy {
    Policy {
        app: package.app().claimed_app,
        abi: package.app().abi,
        platform: crate::requirements::PLATFORM,
    }
}
fn checked<'a>(
    bytes: &'a [u8],
    contracts: &PrivateDataContracts<'_>,
    approval: &Approval,
    intent: Intent,
) -> Result<OnePackage<'a>, Failure> {
    if approval.intent() != intent {
        return Err(Failure::Refused);
    }
    let checked =
        crate::requirements::private_file_app(bytes, contracts).map_err(|_| Failure::Refused)?;
    super::private_profile(checked.package()).map_err(|_| Failure::Refused)?;
    if Source::of(checked.package()) != approval.facts().source {
        return Err(Failure::Refused);
    }
    Ok(OnePackage {
        package: Package::parse(bytes).map_err(|_| Failure::Refused)?,
    })
}
fn rejected<D: SectorIo>(
    rejected: ev_app_registry::Rejected<D>,
    pending: &mut Option<Prepared>,
) -> Failure {
    if rejected.pending.is_none()
        && matches!(
            rejected.error,
            ev_app_registry::Error::Store(ev_store::Error::Unformatted)
        )
    {
        Failure::NotInstalled
    } else {
        *pending = rejected.pending;
        Failure::Retained
    }
}
/// Explicitly allocate the one supported fresh pair. Both complete regions
/// must be blank before the first mutation. Once mutation starts, any failure
/// retains that original attempt; this API offers no cleanup or retry path.
pub fn allocate<T: Wire, W: Window>(
    owner: &mut Owner<T, W>,
    bytes: &[u8],
    contracts: &PrivateDataContracts<'_>,
    approval: &Approval,
    started: &mut bool,
    pending: &mut Option<Prepared>,
) -> Result<(), Failure> {
    if *started || pending.is_some() {
        return Err(Failure::Retained);
    }
    let resolver = checked(bytes, contracts, approval, Intent::Install)?;
    let descriptor =
        descriptor::Descriptor::for_enrolled_app(resolver.package.app().claimed_app, 1)
            .ok_or(Failure::Refused)?;
    let cut = approval.cut();
    for region in [Region::ExternalRegistry, Region::ExternalAppData] {
        let mut device = owner.read_only(region);
        let mut sector = [0; 512];
        for lba in 0..ev_store::REQUIRED_SECTORS {
            device
                .read(lba, &mut sector, cut)
                .map_err(|_| Failure::Retained)?;
            if sector.iter().any(|b| *b != 0) {
                return Err(Failure::Refused);
            }
        }
    }
    let initial = ev_app_registry::app_data::AppDataEnvelope::initial(descriptor.app(), 1, 0)
        .map_err(|_| Failure::Refused)?
        .encode();
    *started = true;
    Store::format_new(
        owner.read_write(Region::ExternalAppData),
        descriptor::data_creation(),
        &initial,
        BootPolicy::new(1).unwrap(),
        cut,
    )
    .map_err(|_| Failure::Retained)?;
    let mut registry = Registry::format_new(
        owner.read_write(Region::ExternalRegistry),
        policy(&resolver.package),
        descriptor::registry_creation(),
        cut,
    )
    .map_err(|e| rejected(e, pending))?;
    let operation = registry
        .prepare(
            registry.expected().map_err(|_| Failure::Retained)?,
            Change::Install {
                package: resolver.package.id().bytes(),
                data_epoch: 1,
            },
            &resolver,
            contracts,
        )
        .map_err(|_| Failure::Retained)?;
    if registry
        .publish(operation, &resolver, contracts, cut)
        .is_err()
    {
        *pending = registry.into_parts().2;
        return Err(Failure::Retained);
    }
    Ok(())
}
/// Reopen/recover only the independently known allocation and exact approved
/// package. Durable Activate records selected software; it proves no process
/// CREATE/START, enrollment, application health or native execution.
pub fn registry<T: Wire, W: Window>(
    owner: &mut Owner<T, W>,
    bytes: &[u8],
    contracts: &PrivateDataContracts<'_>,
    approval: &Approval,
    activate: bool,
    pending: &mut Option<Prepared>,
) -> Result<(), Failure> {
    if pending.is_some() {
        return Err(Failure::Retained);
    }
    let resolver = checked(bytes, contracts, approval, Intent::Run)?;
    let rp = policy(&resolver.package);
    let cut = approval.cut();
    let result = Registry::with_open_checked(
        owner.read_write(Region::ExternalRegistry),
        rp,
        &descriptor::registry_creation(),
        &resolver,
        contracts,
        cut,
        |registry| {
            let record = registry
                .record()?
                .ok_or(ev_app_registry::Error::MissingPackage)?;
            let id = resolver.package.id().bytes();
            if !record.installed()
                || record.app() != rp.app
                || record.data_epoch() != 1
                || record.active().is_some_and(|r| r.digest() != id)
                || record.staged().is_some_and(|r| r.digest() != id)
                || record.active().is_none() && record.staged().is_none()
            {
                return Err(ev_app_registry::Error::Identity);
            }
            if activate && record.active().is_none() {
                let operation = registry.prepare(
                    registry.expected()?,
                    Change::Activate,
                    &resolver,
                    contracts,
                )?;
                registry.publish(operation, &resolver, contracts, cut)?;
            }
            Ok(())
        },
    );
    result.map(|_| ()).map_err(|e| rejected(e, pending))
}

#[cfg(test)]
mod tests;
