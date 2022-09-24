use crate::{
    keys::{Keys, Signature, SignatureError},
    sessions::IdToken,
};
use serde::Serialize;

// Receipt for contributor that sequencer has
// included their contribution
#[derive(Serialize)]
pub struct Receipt<T> {
    pub(crate) id_token: IdToken,
    pub witness:         T,
}

impl<T: Serialize + Send + Sync> Receipt<T> {
    pub async fn sign(&self, keys: &Keys) -> Result<Signature, SignatureError> {
        let receipt_message = serde_json::to_string(self).unwrap();
        keys.sign(&receipt_message).await
    }
}
