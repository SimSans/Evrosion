//! Closed new fixture cases; nominal no-App and V3 session goals stay separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Goal {
    AppDenial,
    Destination,
    DriverStop,
    ServiceStop,
    LinkLoss,
    Endurance,
}
impl Goal {
    pub(crate) const fn fixture(self) -> &'static str {
        "m6-network-negative"
    }
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::AppDenial => "network-authority-probe",
            Self::Destination => "network-destination-probe",
            Self::DriverStop => "network-driver-stop-probe",
            Self::ServiceStop => "network-service-stop-probe",
            Self::LinkLoss => "network-link-loss-probe",
            Self::Endurance => "network-endurance-probe",
        }
    }
}
