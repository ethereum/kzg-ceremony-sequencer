use crate::{
    keys::{Keys, Signature, SignatureError},
    sessions::IdToken,
};
use kzg_ceremony_crypto::G2;
use serde::Serialize;

// Receipt for contributor that sequencer has
// included their contribution
#[derive(Serialize)]
pub struct Receipt {
    pub(crate) id_token: IdToken,
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
