use crate::keys::{Keys, Signature, SignatureError};
use kzg_ceremony_crypto::{signature::identity::Identity, G2};
use serde::Serialize;

// Receipt for contributor that sequencer has
// included their contribution
#[derive(Serialize)]
pub struct Receipt {
    pub(crate) identity: Identity,
    pub witness:         Vec<G2>,
}

impl Receipt {
    pub async fn sign(&self, keys: &Keys) -> Result<(String, Signature), SignatureError> {
        let receipt_message = serde_json::to_string(self).unwrap();
        keys.sign(&receipt_message)
            .await
            .map(|sig| (receipt_message, sig))
    }
}
