use anyhow::{Result, anyhow};
use tracing::info;

use crate::pipeline::cancellation::{CancellationToken, Cancelled};
use crate::pipeline::outcome::{
    ControllerKind, PayloadPlanProvenance, PayloadProviderAttempt, PayloadProviderAttemptCode,
    PayloadProviderAttemptOutcome, PayloadProviderStage, SelectedPayloadStream,
};

use super::DecryptedImage;
use super::controller::{self, ControllerFinalizer, ControllerProbeOutcome, ControllerProposal};

use super::evidence;
use super::records::PayloadBlockTable;
use super::replay::{
    AuthenticatedPayloadPlan, PayloadMaterializationPlan, PayloadPlanAuthenticationError,
    PayloadRouteError, PayloadRouteErrorKind, authenticate_payload_plan,
};
use super::source::BoundPayloadSource;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderPolicy {
    Automatic,
    EvidenceOnly,
}

struct ControllerSuccess {
    controller: ControllerKind,
    plan: PayloadMaterializationPlan,
    recovered: DecryptedImage,
}

fn diagnostic(error: &anyhow::Error) -> String {
    error
        .chain()
        .take(4)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn controller_attempt(
    controller: ControllerKind,
    outcome: PayloadProviderAttemptOutcome,
    stage: PayloadProviderStage,
    code: Option<PayloadProviderAttemptCode>,
    diagnostic: Option<String>,
) -> PayloadProviderAttempt {
    PayloadProviderAttempt {
        provenance: PayloadPlanProvenance::Controller,
        controller: Some(controller),
        outcome,
        stage,
        code,
        diagnostic,
    }
}

fn evidence_attempt(
    outcome: PayloadProviderAttemptOutcome,
    code: Option<PayloadProviderAttemptCode>,
    diagnostic: Option<String>,
) -> PayloadProviderAttempt {
    PayloadProviderAttempt {
        provenance: PayloadPlanProvenance::EvidenceSearch,
        controller: None,
        outcome,
        stage: PayloadProviderStage::EvidenceSearch,
        code,
        diagnostic,
    }
}

fn cancellation_checkpoint(cancellation: Option<&CancellationToken>) -> Result<()> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    Ok(())
}

fn is_cancelled(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Cancelled>().is_some()
}

fn cancellation_route_error(
    source: &BoundPayloadSource<'_>,
    attempts: Vec<PayloadProviderAttempt>,
    error: anyhow::Error,
) -> anyhow::Error {
    PayloadRouteError::new(
        PayloadRouteErrorKind::Cancelled,
        error,
        selected_stream(source),
        attempts,
    )
    .into()
}

#[derive(Clone, Copy)]
struct ProviderFailureClass {
    outcome: PayloadProviderAttemptOutcome,
    code: PayloadProviderAttemptCode,
    route_kind: PayloadRouteErrorKind,
    terminal: bool,
}

fn classify_provider_failure(
    stage: PayloadProviderStage,
    error: &anyhow::Error,
) -> ProviderFailureClass {
    match error.downcast_ref::<PayloadPlanAuthenticationError>() {
        Some(PayloadPlanAuthenticationError::NoCandidate { .. }) => ProviderFailureClass {
            outcome: PayloadProviderAttemptOutcome::Rejected,
            code: PayloadProviderAttemptCode::NoAuthenticatedPlan,
            route_kind: PayloadRouteErrorKind::Unsupported,
            terminal: false,
        },
        None if matches!(
            stage,
            PayloadProviderStage::Probe | PayloadProviderStage::Recovery
        ) =>
        {
            ProviderFailureClass {
                outcome: PayloadProviderAttemptOutcome::Rejected,
                code: PayloadProviderAttemptCode::StructuralMismatch,
                route_kind: PayloadRouteErrorKind::Unsupported,
                terminal: false,
            }
        }
        None => ProviderFailureClass {
            outcome: PayloadProviderAttemptOutcome::Fatal,
            code: PayloadProviderAttemptCode::InternalFailure,
            route_kind: PayloadRouteErrorKind::Internal,
            terminal: true,
        },
    }
}

fn route_error(
    kind: PayloadRouteErrorKind,
    source: &BoundPayloadSource<'_>,
    attempts: Vec<PayloadProviderAttempt>,
    error: anyhow::Error,
) -> anyhow::Error {
    PayloadRouteError::new(kind, error, selected_stream(source), attempts).into()
}

fn classify_evidence_failure(error: &anyhow::Error) -> ProviderFailureClass {
    if error
        .downcast_ref::<super::replay::PayloadPlanSelectionError>()
        .is_some()
        || matches!(
            error.downcast_ref::<PayloadPlanAuthenticationError>(),
            Some(PayloadPlanAuthenticationError::NoCandidate { .. })
        )
    {
        return ProviderFailureClass {
            outcome: PayloadProviderAttemptOutcome::Rejected,
            code: PayloadProviderAttemptCode::EvidenceSearchRejected,
            route_kind: PayloadRouteErrorKind::Unsupported,
            terminal: true,
        };
    }
    ProviderFailureClass {
        outcome: PayloadProviderAttemptOutcome::Fatal,
        code: PayloadProviderAttemptCode::InternalFailure,
        route_kind: PayloadRouteErrorKind::Internal,
        terminal: true,
    }
}

struct AuthenticatedControllerProposal {
    block_table: PayloadBlockTable,
    finalizer: ControllerFinalizer,
    authenticated: AuthenticatedPayloadPlan,
    identity: PayloadMaterializationPlan,
}

fn authenticate_controller_proposal(
    source: &BoundPayloadSource<'_>,
    proposal: ControllerProposal,
    cancellation: Option<&CancellationToken>,
) -> Result<AuthenticatedControllerProposal> {
    let ControllerProposal {
        base_image,
        block_table,
        candidate,
        finalizer,
    } = proposal;
    let authenticated = authenticate_payload_plan(
        source.payload_source,
        &base_image,
        &block_table,
        candidate,
        cancellation,
    )?;
    let identity = authenticated.plan().clone();
    Ok(AuthenticatedControllerProposal {
        block_table,
        finalizer,
        authenticated,
        identity,
    })
}
fn retain_controller_success(
    retained: &mut Option<ControllerSuccess>,
    controller: ControllerKind,
    plan: PayloadMaterializationPlan,
    recovered: DecryptedImage,
) -> std::result::Result<(), (ControllerKind, ControllerKind)> {
    if let Some(first) = retained {
        if first.plan.semantically_eq(&plan) && first.recovered.image == recovered.image {
            return Ok(());
        }
        return Err((first.controller, controller));
    }
    *retained = Some(ControllerSuccess {
        controller,
        plan,
        recovered,
    });
    Ok(())
}

fn selected_stream(source: &BoundPayloadSource<'_>) -> SelectedPayloadStream {
    SelectedPayloadStream {
        locator_file_offset: source.stream.locator_file_offset,
        base_file_offset: source.stream.base_file_offset,
        gap_after_outer_source: source.stream.gap_after_outer_source,
    }
}

fn finish_controller(
    mut success: ControllerSuccess,
    attempts: Vec<PayloadProviderAttempt>,
    source: &BoundPayloadSource<'_>,
) -> DecryptedImage {
    info!(
        provenance = "controller",
        controller = ?success.controller,
        "selected payload-plan provider"
    );
    success.recovered.decryption_details.plan_provenance = Some(PayloadPlanProvenance::Controller);
    success.recovered.decryption_details.selected_stream = Some(selected_stream(source));
    success.recovered.decryption_details.provider_attempts = attempts;
    success.recovered
}

fn finish_evidence(
    mut recovered: DecryptedImage,
    attempts: Vec<PayloadProviderAttempt>,
    source: &BoundPayloadSource<'_>,
) -> DecryptedImage {
    info!(
        provenance = "evidence_search",
        controller = tracing::field::Empty,
        "selected payload-plan provider"
    );
    recovered.decryption_details.plan_provenance = Some(PayloadPlanProvenance::EvidenceSearch);
    recovered.decryption_details.selected_stream = Some(selected_stream(source));
    recovered.decryption_details.provider_attempts = attempts;
    recovered
}

pub(super) fn recover_payload(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<DecryptedImage> {
    recover_payload_automatically(source, cancellation)
}

#[cfg(test)]
pub(crate) fn recover_payload_with_policy(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
    policy: ProviderPolicy,
) -> Result<DecryptedImage> {
    match policy {
        ProviderPolicy::Automatic => recover_payload_automatically(source, cancellation),
        ProviderPolicy::EvidenceOnly => recover_evidence_only(source, cancellation),
    }
}

fn recover_payload_automatically(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<DecryptedImage> {
    let mut attempts = Vec::new();
    if let Err(error) = cancellation_checkpoint(cancellation) {
        return Err(cancellation_route_error(source, attempts, error));
    }
    let mut controller_success = None;

    for registration in controller::REGISTRY {
        let kind = registration.kind;
        let probe = match controller::probe(registration, source, cancellation) {
            ControllerProbeOutcome::NotApplicable => {
                attempts.push(controller_attempt(
                    kind,
                    PayloadProviderAttemptOutcome::NotApplicable,
                    PayloadProviderStage::Probe,
                    None,
                    None,
                ));
                continue;
            }
            ControllerProbeOutcome::Applicable(probe) => probe,
            ControllerProbeOutcome::Cancelled(error) => {
                return Err(cancellation_route_error(source, attempts, error));
            }
            ControllerProbeOutcome::Rejected(error) if is_cancelled(&error) => {
                return Err(cancellation_route_error(source, attempts, error));
            }
            ControllerProbeOutcome::Rejected(error) => {
                let class = classify_provider_failure(PayloadProviderStage::Probe, &error);
                attempts.push(controller_attempt(
                    kind,
                    class.outcome,
                    PayloadProviderStage::Probe,
                    Some(class.code),
                    Some(diagnostic(&error)),
                ));
                if class.terminal {
                    return Err(route_error(class.route_kind, source, attempts, error));
                }
                continue;
            }
        };

        if let Err(error) = cancellation_checkpoint(cancellation) {
            return Err(cancellation_route_error(source, attempts, error));
        }
        let proposal = match controller::recover(source, probe, cancellation) {
            Ok(proposal) => proposal,
            Err(error) if is_cancelled(&error) => {
                return Err(cancellation_route_error(source, attempts, error));
            }
            Err(error) => {
                let class = classify_provider_failure(PayloadProviderStage::Recovery, &error);
                attempts.push(controller_attempt(
                    kind,
                    class.outcome,
                    PayloadProviderStage::Recovery,
                    Some(class.code),
                    Some(diagnostic(&error)),
                ));
                if class.terminal {
                    return Err(route_error(class.route_kind, source, attempts, error));
                }
                continue;
            }
        };

        let proposal = match authenticate_controller_proposal(source, proposal, cancellation) {
            Ok(proposal) => proposal,
            Err(error) if is_cancelled(&error) => {
                return Err(cancellation_route_error(source, attempts, error));
            }
            Err(error) => {
                let class = classify_provider_failure(PayloadProviderStage::Authentication, &error);
                attempts.push(controller_attempt(
                    kind,
                    class.outcome,
                    PayloadProviderStage::Authentication,
                    Some(class.code),
                    Some(diagnostic(&error)),
                ));
                if class.terminal {
                    return Err(route_error(class.route_kind, source, attempts, error));
                }
                continue;
            }
        };

        let AuthenticatedControllerProposal {
            block_table,
            finalizer,
            authenticated,
            identity,
        } = proposal;
        let recovered = match controller::finalize(
            registration.finalizer_profile,
            source,
            block_table,
            finalizer,
            authenticated,
        ) {
            Ok(recovered) => recovered,
            Err(error) if is_cancelled(&error) => {
                return Err(cancellation_route_error(source, attempts, error));
            }
            Err(error) => {
                let class = classify_provider_failure(PayloadProviderStage::Finalization, &error);
                attempts.push(controller_attempt(
                    kind,
                    class.outcome,
                    PayloadProviderStage::Finalization,
                    Some(class.code),
                    Some(diagnostic(&error)),
                ));
                return Err(route_error(class.route_kind, source, attempts, error));
            }
        };
        attempts.push(controller_attempt(
            kind,
            PayloadProviderAttemptOutcome::Authenticated,
            PayloadProviderStage::Finalization,
            None,
            None,
        ));
        if let Err((first, second)) =
            retain_controller_success(&mut controller_success, kind, identity, recovered)
        {
            let error =
                anyhow!("controllers {first:?} and {second:?} authenticated conflicting payloads");
            let conflicting = attempts
                .last_mut()
                .expect("current controller success was just recorded");
            conflicting.outcome = PayloadProviderAttemptOutcome::Ambiguous;
            conflicting.stage = PayloadProviderStage::Authentication;
            conflicting.code = Some(PayloadProviderAttemptCode::AmbiguousPlans);
            conflicting.diagnostic = Some(diagnostic(&error));
            return Err(route_error(
                PayloadRouteErrorKind::Ambiguous,
                source,
                attempts,
                error,
            ));
        }
    }
    if let Err(error) = cancellation_checkpoint(cancellation) {
        return Err(cancellation_route_error(source, attempts, error));
    }

    if let Some(success) = controller_success {
        return Ok(finish_controller(success, attempts, source));
    }

    if let Err(error) = cancellation_checkpoint(cancellation) {
        return Err(cancellation_route_error(source, attempts, error));
    }
    match evidence::recover(source, cancellation) {
        Ok(recovered) => {
            attempts.push(evidence_attempt(
                PayloadProviderAttemptOutcome::Authenticated,
                None,
                None,
            ));
            Ok(finish_evidence(recovered, attempts, source))
        }
        Err(error) if is_cancelled(&error) => {
            Err(cancellation_route_error(source, attempts, error))
        }
        Err(error) => {
            let class = classify_evidence_failure(&error);
            attempts.push(evidence_attempt(
                class.outcome,
                Some(class.code),
                Some(diagnostic(&error)),
            ));
            let provider_diagnostics = attempts
                .iter()
                .filter_map(|attempt| attempt.diagnostic.as_deref())
                .collect::<Vec<_>>()
                .join("; ");
            let error = error.context(format!(
                "all payload-plan providers rejected the input ({provider_diagnostics})"
            ));
            Err(route_error(class.route_kind, source, attempts, error))
        }
    }
}

#[cfg(test)]
fn recover_evidence_only(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<DecryptedImage> {
    cancellation_checkpoint(cancellation)?;
    let recovered = evidence::recover(source, cancellation)?;
    Ok(finish_evidence(
        recovered,
        vec![evidence_attempt(
            PayloadProviderAttemptOutcome::Authenticated,
            None,
            None,
        )],
        source,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_failure_classification_preserves_terminal_semantics() {
        let rejected = anyhow::Error::new(PayloadPlanAuthenticationError::NoCandidate {
            diagnostics: vec!["candidate rejected".to_owned()],
        });
        let rejected = classify_provider_failure(PayloadProviderStage::Authentication, &rejected);
        assert_eq!(rejected.outcome, PayloadProviderAttemptOutcome::Rejected);
        assert_eq!(
            rejected.code,
            PayloadProviderAttemptCode::NoAuthenticatedPlan
        );
        assert_eq!(rejected.route_kind, PayloadRouteErrorKind::Unsupported);
        assert!(!rejected.terminal);

        let fatal = anyhow!("unexpected authentication invariant");
        let fatal = classify_provider_failure(PayloadProviderStage::Authentication, &fatal);
        assert_eq!(fatal.outcome, PayloadProviderAttemptOutcome::Fatal);
        assert_eq!(fatal.code, PayloadProviderAttemptCode::InternalFailure);
        assert_eq!(fatal.route_kind, PayloadRouteErrorKind::Internal);
        assert!(fatal.terminal);

        let structural = anyhow!("controller marker mismatch");
        let structural = classify_provider_failure(PayloadProviderStage::Recovery, &structural);
        assert_eq!(structural.outcome, PayloadProviderAttemptOutcome::Rejected);
        assert_eq!(
            structural.code,
            PayloadProviderAttemptCode::StructuralMismatch
        );
        assert!(!structural.terminal);
    }

    #[test]
    fn evidence_failure_classification_distinguishes_rejection_and_internal_failure() {
        let rejected = super::super::replay::PayloadPlanSelectionError::for_test(
            Default::default(),
            "no authenticated chain",
        );
        let rejected = classify_evidence_failure(&anyhow::Error::new(rejected));
        assert_eq!(rejected.outcome, PayloadProviderAttemptOutcome::Rejected);
        assert_eq!(
            rejected.code,
            PayloadProviderAttemptCode::EvidenceSearchRejected
        );
        assert_eq!(rejected.route_kind, PayloadRouteErrorKind::Unsupported);

        let fatal = anyhow!("mapped image invariant failed");
        let fatal = classify_evidence_failure(&fatal);
        assert_eq!(fatal.outcome, PayloadProviderAttemptOutcome::Fatal);
        assert_eq!(fatal.code, PayloadProviderAttemptCode::InternalFailure);
        assert_eq!(fatal.route_kind, PayloadRouteErrorKind::Internal);
    }

    #[test]
    fn conflicting_controller_success_records_the_conflicting_attempt() {
        let source = SelectedPayloadStream {
            locator_file_offset: 0x40,
            base_file_offset: 0x200,
            gap_after_outer_source: 0x10,
        };
        let error = anyhow!("controllers authenticated conflicting payloads");
        let attempts = vec![
            controller_attempt(
                ControllerKind::ShellDirectoryManifest,
                PayloadProviderAttemptOutcome::Authenticated,
                PayloadProviderStage::Finalization,
                None,
                None,
            ),
            controller_attempt(
                ControllerKind::CodecRelocation,
                PayloadProviderAttemptOutcome::Ambiguous,
                PayloadProviderStage::Authentication,
                Some(PayloadProviderAttemptCode::AmbiguousPlans),
                Some(diagnostic(&error)),
            ),
        ];
        let route =
            PayloadRouteError::new(PayloadRouteErrorKind::Ambiguous, error, source, attempts);

        assert_eq!(route.kind, PayloadRouteErrorKind::Ambiguous);
        let conflicting_attempt = route
            .decryption_details
            .provider_attempts
            .iter()
            .find(|attempt| attempt.controller == Some(ControllerKind::CodecRelocation))
            .expect("conflicting controller attempt must be retained");
        assert_eq!(
            conflicting_attempt.outcome,
            PayloadProviderAttemptOutcome::Ambiguous
        );
        assert_eq!(
            conflicting_attempt.code,
            Some(PayloadProviderAttemptCode::AmbiguousPlans)
        );
    }

    #[test]
    fn route_error_preserves_selection_details_and_provider_attempts() {
        let source = SelectedPayloadStream {
            locator_file_offset: 0x40,
            base_file_offset: 0x200,
            gap_after_outer_source: 0x10,
        };
        let selection_details = crate::pipeline::outcome::DecryptionDetails {
            block_count: 7,
            ..Default::default()
        };
        let selection = super::super::replay::PayloadPlanSelectionError::for_test(
            selection_details,
            "no authenticated chain",
        );
        let attempts = vec![evidence_attempt(
            PayloadProviderAttemptOutcome::Rejected,
            Some(PayloadProviderAttemptCode::EvidenceSearchRejected),
            Some("no authenticated chain".to_owned()),
        )];

        let route = PayloadRouteError::new(
            PayloadRouteErrorKind::Unsupported,
            anyhow::Error::new(selection),
            source,
            attempts,
        );

        assert_eq!(route.decryption_details.block_count, 7);
        let evidence_attempt = route
            .decryption_details
            .provider_attempts
            .iter()
            .find(|attempt| attempt.provenance == PayloadPlanProvenance::EvidenceSearch)
            .expect("evidence-search attempt must be retained");
        assert_eq!(
            evidence_attempt.code,
            Some(PayloadProviderAttemptCode::EvidenceSearchRejected)
        );
    }
}
