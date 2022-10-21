use axum::{response::{IntoResponse, Response}, Json};
use http::StatusCode;
use kzg_ceremony_crypto::{CeremoniesError, CeremonyError};
use serde_json::json;

struct CeremoniesErrorFormatter(CeremoniesError);

impl IntoResponse for CeremoniesErrorFormatter {
    fn into_response(self) -> Response {
        let error = format!("contribution invalid: {}", self.0);

        let code = match self.0 {
            CeremoniesError::UnexpectedNumContributions(_, _) => {
                "CeremoniesError::UnexpectedNumContributions"
            },
            CeremoniesError::InvalidCeremony(_, err) => {
                match err {
                    CeremonyError::UnsupportedNumG1Powers(_) =>
                        "CeremonyError::UnsupportedNumG1Powers",
                    CeremonyError::UnsupportedNumG2Powers(_) =>
                        "CeremonyError::UnsupportedNumG2Powers",
                    CeremonyError::UnexpectedNumG1Powers(_, _) =>
                        "CeremonyError::UnexpectedNumG1Powers",
                    CeremonyError::UnexpectedNumG2Powers(_, _) =>
                        "CeremonyError::UnexpectedNumG2Powers",
                    CeremonyError::InconsistentNumG1Powers(_, _) =>
                        "CeremonyError::InconsistentNumG1Powers",
                    CeremonyError::InconsistentNumG2Powers(_, _) =>
                        "CeremonyError::InconsistentNumG2Powers",
                    CeremonyError::UnsupportedMoreG2Powers(_, _) =>
                        "CeremonyError::UnsupportedMoreG2Powers",
                    CeremonyError::InvalidG1Power(_, _) =>
                        "CeremonyError::InvalidG1Power",
                    CeremonyError::InvalidG2Power(_, _) =>
                        "CeremonyError::InvalidG2Power",
                    CeremonyError::ParserError(_) =>
                        "CeremonyError::ParserError",
                    CeremonyError::InvalidPubKey(_) =>
                        "CeremonyError::InvalidPubKey",
                    CeremonyError::InvalidWitnessProduct(_, _) =>
                        "CeremonyError::InvalidWitnessProduct",
                    CeremonyError::InvalidWitnessPubKey(_, _) =>
                        "CeremonyError::InvalidWitnessPubKey",
                    CeremonyError::PubKeyPairingFailed =>
                        "CeremonyError::PubKeyPairingFailed",
                    CeremonyError::G1PairingFailed =>
                        "CeremonyError::G1PairingFailed",
                    CeremonyError::G2PairingFailed =>
                        "CeremonyError::G2PairingFailed",
                    CeremonyError::ZeroPubkey =>
                        "CeremonyError::ZeroPubkey",
                    CeremonyError::ZeroG1(_) =>
                        "CeremonyError::ZeroG1",
                    CeremonyError::ZeroG2(_) =>
                        "CeremonyError::ZeroG2",
                    CeremonyError::InvalidG1FirstValue =>
                        "CeremonyError::InvalidG1FirstValue",
                    CeremonyError::InvalidG2FirstValue =>
                        "CeremonyError::InvalidG2FirstValue",
                    CeremonyError::InvalidG1One(_) =>
                        "CeremonyError::InvalidG1One",
                    CeremonyError::InvalidG2One(_) =>
                        "CeremonyError::InvalidG2One",
                    CeremonyError::InvalidG2Pubkey(_) =>
                        "CeremonyError::InvalidG2Pubkey",
                    CeremonyError::DuplicateG1(_, _) =>
                        "CeremonyError::DuplicateG1",
                    CeremonyError::DuplicateG2(_, _) =>
                        "CeremonyError::DuplicateG2",
                    CeremonyError::ContributionNoEntropy =>
                        "CeremonyError::ContributionNoEntropy",
                    CeremonyError::WitnessLengthMismatch(_, _) =>
                        "CeremonyError::WitnessLengthMismatch",
                }
            }
        };
        
        let body = Json(json!({
            "code": code,
            "error" : error
        }));

        (StatusCode::BAD_REQUEST, body).into_response()
    }
}