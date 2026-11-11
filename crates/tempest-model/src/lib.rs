//! Shared static scenario model. No AWS client or authorization evaluator.
pub mod capability;
pub mod policy;
pub mod scenario;
pub mod validation;

pub use scenario::{ScenarioInput, ValidatedScenario};
pub use validation::Diagnostic;
