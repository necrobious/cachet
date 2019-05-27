use sodiumoxide::crypto::sign::ed25519::{self, SecretKey, PublicKey,Signature};
use trustchain::v2::{TrustChain, TrustError, RootKeysStore, trust_chain, SIGNATUREBYTES};
use byteorder::{BigEndian, WriteBytesExt};
use std::fmt;
use nom::{be_u16,be_u32,IResult};

#[derive(Clone,Debug,PartialEq)]
pub struct Cachet {
    signature: Signature,
    trust_chain:TrustChain,
    data: Vec<u8>,
}

named!(signature<Signature>, do_parse!(
    bytes: take!(SIGNATUREBYTES) >>
    sig: expr_opt!(Signature::from_slice(bytes)) >>
    (sig)
));


fn clone (input: &[u8]) -> IResult<&[u8],&[u8]> {
    Ok( (input.clone(), input) )
}

named_args!(pub cachet(root_keys:Box<RootKeysStore>)<Cachet>, do_parse!(
    _tag: tag!(b"CT") >>
    _ver: verify!(be_u16, |ver:u16| ver == 1) >>
    // unverified signature over the trustchain's bytes, the 4-byte length of the data that follows, and the data bytes.
    sig: signature >>
    // need to duplicate the bytes that are under signature, they contain the trustchain we need to verify the
    // parsed signature with.
    copy_of_signed_bytes: clone >>    // Is input always the entire body of bytes to be parsed?! we assume yes,
                                      // if not, signatue verification will fail!
    chain: verify!(
        // derive trust in the parsed trust chain if it's root key is in our trusted root keys store.
        call!(trust_chain,root_keys), // NOTE: trust_chain must fail if root key in the parsed trust chain
                                      //       is not in the given root keys store!
        // Trust Chain is untamperd, now use the chain's end key to verify the given signature over
        // the trustchain's own bytes, followed by the 4-byte length of the data payload, and then finally,
        // the the data payload bytes.
        |trusted_chain:TrustChain| trusted_chain.verify_data(&sig, &copy_of_signed_bytes).is_ok()
    ) >>
    // signature, trustchain, and data can be trusted at this point, parsing should have failed at
    // this point if we detected that the the data had been altered.
    data: length_data!(be_u32) >>
    (Cachet { signature:sig, trust_chain: chain, data: data.to_vec() })
));

#[derive(Clone,Debug,PartialEq)]
pub enum CachetError {
    SigningFailed
}

impl Cachet {
    pub fn new(data: Vec<u8>, chain:&TrustChain, skey:&SecretKey) -> Result<Cachet,CachetError> {
        let mut chain_bytes = chain.as_bytes();
        let mut data_bytes = data.clone();

        let mut signed_bytes:Vec<u8> = Vec::with_capacity(
            chain_bytes.len() + // trustchain, N bytes
            4                 + // data length, u32, 4 bytes
            data.len()          // data, N bytes
        );
        signed_bytes.append(&mut chain_bytes);
        signed_bytes.write_u32::<BigEndian>(data.len() as u32).unwrap();
        signed_bytes.append(&mut data_bytes);

        let sig = ed25519::sign_detached(&signed_bytes, skey);

        Ok(Cachet {
            signature: sig,
            trust_chain: *chain,
            data: data,
        })

    }

    pub fn as_bytes (&self) -> Vec<u8> {
        let mut header:Vec<u8> = [0x43,0x54,0x00,0x01].to_vec();
        let mut chain_bytes = self.trust_chain.clone().as_bytes();
        let mut data = self.data.clone();
        let mut v:Vec<u8> = Vec::with_capacity(
            2+ // TAG "EV", 2 bytes
            2+ // Format Version, u16, 2 bytes
            SIGNATUREBYTES+ // signatuere, 32bytes
            chain_bytes.len()+ // trustchain, N bytes
            4+ // data length, u32, 4 bytes
            self.data.len()// data, N bytes
            );
        v.append(&mut header);
        v.append(&mut self.signature.0.clone().to_vec());
        v.append(&mut chain_bytes);
        v.write_u32::<BigEndian>(data.len() as u32).unwrap();
        v.append(&mut data);
        v
    }
}

fn fixture () -> (SecretKey, PublicKey, SecretKey, PublicKey, Box<RootKeysStore>, TrustChain) {
    let (root_pkey, root_skey) = ed25519::gen_keypair();
    let (end_pkey, end_skey) = ed25519::gen_keypair();
    let root_key_store = Box::new(vec!(root_pkey));
    let key_sig = ed25519::sign_detached(&end_pkey.0, &root_skey);

    let chain_res = TrustChain::two_link_chain(
        root_pkey,
        end_pkey,
        key_sig,
        root_key_store.clone()
    );

    assert!(chain_res.is_ok());

    (root_skey, root_pkey, end_skey, end_pkey, root_key_store, chain_res.unwrap())
}

#[test]
fn cachet_should_construct () {
    let (root_skey, root_pkey, end_skey, end_pkey, root_key_store, chain) = fixture();

    let test_data = b"test data".to_vec();
    let cachet_res = Cachet::new(test_data, &chain, &end_skey);

    assert!(cachet_res.is_ok());

    let env = cachet_res.unwrap();

    let ser_bytes = env.clone().as_bytes();

    let parsed_env_res = cachet(&ser_bytes, root_key_store);

    assert!(parsed_env_res.is_ok());

    let parsed_env = parsed_env_res.unwrap().1;

    assert_eq!(parsed_env.clone(), env);
}

#[test]
fn cachet_should_fail_to_parse_with_bad_tag  () {
    let (root_skey, root_pkey, end_skey, end_pkey, root_key_store, chain) = fixture();

    let test_data = b"test data".to_vec();
    let cachet_res = Cachet::new(test_data, &chain, &end_skey);

    assert!(cachet_res.is_ok());

    let env = cachet_res.unwrap();

    let mut ser_bytes = env.clone().as_bytes();

    ser_bytes[0] = 0x00; //damage the tag

    let parsed_env_res = cachet(&ser_bytes, root_key_store);

    assert!(parsed_env_res.is_err());
}

#[test]
fn cachet_should_fail_to_parse_with_bad_trustchain  () {
    let (root_skey, root_pkey, end_skey, end_pkey, root_key_store, chain) = fixture();

    let test_data = b"test data".to_vec();
    let cachet_res = Cachet::new(test_data, &chain, &end_skey);

    assert!(cachet_res.is_ok());

    let env = cachet_res.unwrap();

    let mut ser_bytes = env.clone().as_bytes();
    ser_bytes[73] = 0x00; //damage the trustchain's root key
    ser_bytes[74] = 0x00; //damage the trustchain's root key

    let parsed_env_res = cachet(&ser_bytes, root_key_store);

    assert!(parsed_env_res.is_err());
}

#[test]
fn cachet_should_fail_to_parse_with_untrusted_signature () {
    let (root_skey, root_pkey, end_skey, end_pkey, root_key_store, chain) = fixture();

    let test_data = b"test data".to_vec();
    let cachet_res = Cachet::new(test_data, &chain, &end_skey);

    assert!(cachet_res.is_ok());

    let env = cachet_res.unwrap();

    let mut ser_bytes = env.clone().as_bytes();

    ser_bytes[5] = 0x00; //damage the signature

    let parsed_env_res = cachet(&ser_bytes, root_key_store);

    assert!(parsed_env_res.is_err());
}
