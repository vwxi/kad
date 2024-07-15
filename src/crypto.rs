use crate::util::{Addr, Hash, RpcArgs, RpcContext, RpcOp, timestamp};
use rsa::pkcs1::{self, DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

const KEY_BITS: usize = 2048;

pub(crate) struct Crypto {
    pub(crate) private: RsaPrivateKey,
    pub(crate) public: RsaPublicKey,
    pub(crate) signing: SigningKey<Sha256>,

    // hash -> (key, last contacted (for pruning))
    pub(crate) keystore: BTreeMap<Hash, (RsaPublicKey, u64)>,
}

impl Crypto {
    // randomly generate key
    pub(crate) fn new() -> Result<Self, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, KEY_BITS)?;
        let public_key = RsaPublicKey::from(private_key.clone());

        Ok(Crypto {
            private: private_key.clone(),
            public: public_key,
            signing: SigningKey::<Sha256>::new(private_key),
            keystore: BTreeMap::new(),
        })
    }

    pub(crate) fn from_file(priv_file: &str, pub_file: &str) -> Result<Self, Box<dyn Error>> {
        let (priv_path, pub_path) = (Path::new(priv_file), Path::new(pub_file));
        let (private_key, public_key) = (
            RsaPrivateKey::read_pkcs1_pem_file(priv_path)?,
            RsaPublicKey::read_public_key_pem_file(pub_path)?,
        );

        Ok(Crypto {
            private: private_key.clone(),
            public: public_key,
            signing: SigningKey::<Sha256>::new(private_key),
            keystore: BTreeMap::new(),
        })
    }

    pub(crate) fn public_key_as_string(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.public.to_pkcs1_pem(pkcs1::LineEnding::LF)?)
    }

    pub(crate) fn to_file(&self, priv_file: &str, pub_file: &str) -> Result<(), Box<dyn Error>> {
        self.private
            .write_pkcs1_pem_file(Path::new(priv_file), pkcs1::LineEnding::LF)?;
        self.public
            .write_pkcs1_pem_file(Path::new(pub_file), pkcs1::LineEnding::LF)?;

        Ok(())
    }

    pub(crate) fn sign(&self, data: &str) -> String {
        let mut rng = rand::thread_rng();
        self.signing
            .sign_with_rng(&mut rng, data.as_bytes())
            .to_string()
    }

    pub(crate) fn verify(&mut self, id: Hash, data: &str, sig: &str) -> bool {
        if self.keystore.contains_key(&id) {
            let entry = self.keystore.get_mut(&id).unwrap();
            let ver_key = VerifyingKey::<Sha256>::new(entry.0.clone());
            entry.1 = timestamp();

            match Signature::try_from(sig.as_bytes()) {
                Ok(signature) => ver_key.verify(data.as_bytes(), &signature).is_ok(),
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub(crate) fn args(&self, i: Hash, o: RpcOp, a: Addr, ts: u64) -> RpcArgs {
        let ctx = RpcContext {
            id: i,
            op: o,
            addr: a,
            timestamp: ts,
        };

        let sign = self.sign(serde_json::to_string(&ctx).unwrap().as_str());

        (ctx, sign)
    }
}
