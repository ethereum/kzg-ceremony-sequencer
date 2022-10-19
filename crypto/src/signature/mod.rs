//! Implements the binding the contribution to participants.
//! https://github.com/ethereum/kzg-ceremony-specs/blob/master/docs/cryptography/contributionSigning.md
//! https://github.com/gakonst/ethers-rs/blob/e89c7a378bba6587e3f525982785c59a33c14d9b/ethers-core/ethers-derive-eip712/tests/derive_eip712.rs

pub mod identity;

use crate::{
    hex_format::{bytes_to_hex, optional_hex_to_bytes},
    signature::identity::Identity,
    BatchContribution, Engine, Tau, F, G1, G2,
};
use ethers::types::transaction::eip712::{EIP712Domain, Eip712, Eip712Error, TypedData};
use secrecy::ExposeSecret;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsSignature(pub Option<G1>);

impl BlsSignature {
    pub fn empty() -> Self {
        Self(None)
    }

    pub fn prune<E: Engine>(&self, message: &[u8], pk: G2) -> Self {
        Self(self.0.and_then(|sig| {
            if E::verify_signature(sig, message, pk) {
                Some(sig)
            } else {
                None
            }
        }))
    }

    pub fn sign<E: Engine>(message: &[u8], sk: &Tau) -> Self {
        Self(E::sign_message(sk, message))
    }
}

impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            Some(sig) => sig.serialize(serializer),
            None => serializer.serialize_str(""),
        }
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        optional_hex_to_bytes::<_, 48>(deserializer)
            .map(|bytes_opt| BlsSignature(bytes_opt.map(G1)))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EcdsaSignature(pub Option<ethers::types::Signature>);

impl EcdsaSignature {
    pub fn empty() -> Self {
        Self(None)
    }

    pub fn prune<T: Eip712>(&self, identity: &Identity, data: T) -> Self {
        Self(self.0.as_ref().and_then(|sig| {
            if let Identity::Ethereum { address } = identity {
                sig.verify(data.encode_eip712().ok()?, address).ok()?;
                Some(sig.clone())
            } else {
                None
            }
        }))
    }
}

impl Serialize for EcdsaSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0 {
            Some(sig) => {
                let bytes = <[u8; 65]>::from(sig);
                bytes_to_hex::<_, 65, 132>(serializer, bytes)
            }
            None => serializer.serialize_str(""),
        }
    }
}

impl<'de> Deserialize<'de> for EcdsaSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        optional_hex_to_bytes::<_, 65>(deserializer).map(|bytes_opt| {
            EcdsaSignature(bytes_opt.map(|bytes| {
                ethers::types::Signature::try_from(&bytes[..])
                    .expect("Impossible, input is guaranteed correct")
            }))
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PubkeyTypedData {
    num_g1_powers: usize,
    num_g2_powers: usize,
    pot_pubkey:    G2,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContributionTypedData {
    pot_pubkeys: Vec<PubkeyTypedData>,
}

impl From<&BatchContribution> for ContributionTypedData {
    fn from(contribution: &BatchContribution) -> Self {
        Self {
            pot_pubkeys: contribution
                .contributions
                .iter()
                .map(|c| PubkeyTypedData {
                    num_g1_powers: c.powers.g1.len(),
                    num_g2_powers: c.powers.g2.len(),
                    pot_pubkey:    c.pot_pubkey.clone(),
                })
                .collect(),
        }
    }
}

impl From<ContributionTypedData> for TypedData {
    fn from(contrib: ContributionTypedData) -> Self {
        let json = json!({
            "types": {
                "EIP712Domain": [
                    {"name":"name", "type":"string"},
                    {"name":"version", "type":"string"},
                    {"name":"chainId", "type":"uint256"}
                ],
                "contributionPubkey": [
                    {"name": "numG1Powers", "type": "uint256"},
                    {"name": "numG2Powers", "type": "uint256"},
                    {"name": "potPubkey", "type": "bytes"}
                ],
                "PoTPubkeys": [
                    { "name": "potPubkeys", "type": "contributionPubkey[]"}
                ]
            },
            "primaryType": "PoTPubkeys",
            "domain": {
                "name": "Ethereum KZG Ceremony",
                "version": "1.0",
                "chainId": 1
            },
            "message": contrib
        });
        return serde_json::from_value(json)
            .expect("Impossible, constructed from a literal and therefore must be valid json");
    }
}

impl Eip712 for ContributionTypedData {
    type Error = Eip712Error;

    fn domain(&self) -> Result<EIP712Domain, Self::Error> {
        TypedData::from(self.clone()).domain()
    }

    fn type_hash() -> Result<[u8; 32], Self::Error> {
        TypedData::type_hash()
    }

    fn struct_hash(&self) -> Result<[u8; 32], Self::Error> {
        TypedData::from(self.clone()).struct_hash()
    }
}

#[cfg(all(test, feature = "arkworks", feature = "blst"))]
mod tests {
    use crate::{
        engine::tests::arb_f, signature::BlsSignature, Arkworks, Engine, Entropy, BLST, F, G2,
    };
    use proptest::proptest;
    use rand::{thread_rng, Rng};
    use secrecy::Secret;

    #[test]
    fn test_bls_prune_after_encode() {
        proptest!(|(f in arb_f(), msg in ".*")| {
            let bytes = msg.as_bytes();
            let tau = Secret::new(f);
            let signed = BlsSignature::sign::<BLST>(bytes, &tau);
            assert!(signed.0.is_some());
            // use the Arkworks engine to cross-check with BLST
            let mut tmp = vec![G2::one(), G2::one()];
            Arkworks::add_tau_g2(&tau, &mut tmp).unwrap();
            let pubkey = tmp[1];
            let recovered = signed.prune::<BLST>(&bytes, pubkey);
            assert_eq!(signed, recovered);
        })
    }

    #[test]
    fn test_bls_prune_wrong_msg() {
        let message = "git|1234|foobar".as_bytes();
        let wrong_msg = "git|4567|bazbaz".as_bytes();
        let tau = Secret::new(F::one());
        let signed = BlsSignature::sign::<BLST>(message, &tau);
        assert!(signed.0.is_some());
        let mut tmp = vec![G2::one(), G2::one()];
        Arkworks::add_tau_g2(&tau, &mut tmp).unwrap();
        let pubkey = tmp[1];
        let recovered = signed.prune::<BLST>(wrong_msg, pubkey);
        assert_eq!(recovered, BlsSignature(None));
    }

    #[test]
    fn test_bls_prune_wrong_sig() {
        let message = "git|1234|foobar".as_bytes();
        let tau = Arkworks::generate_tau(&Entropy::new(thread_rng().gen()));
        let wrong_tau = Arkworks::generate_tau(&Entropy::new(thread_rng().gen()));
        let signed = BlsSignature::sign::<BLST>(message, &tau);
        assert!(signed.0.is_some());
        let mut tmp = vec![G2::one(), G2::one()];
        Arkworks::add_tau_g2(&wrong_tau, &mut tmp).unwrap();
        let wrong_pubkey = tmp[1];
        let recovered = signed.prune::<BLST>(message, wrong_pubkey);
        assert_eq!(recovered, BlsSignature(None));
    }
}
