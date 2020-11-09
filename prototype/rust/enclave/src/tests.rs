extern crate hex;

use crypto;
use error::CryptoError;

use crate::interface::*;
use crate::sgx_tunittest::*;
use crate::sgx_types;
use crate::std::prelude::v1::*;

use sgx_types::sgx_status_t;

pub fn test_all() -> sgx_status_t {
    // rsgx_unit_tests!(test_agg_msg);
    // rsgx_unit_tests!(scheduler_tests);
    // rsgx_unit_tests!(test_dc_msg);
    // rsgx_unit_tests!(kdf);
    rsgx_unit_tests!(xor);
    rsgx_unit_tests!(sign);
    sgx_status_t::SGX_SUCCESS
}

fn xor() {
    let a: Vec<u8> = vec![1, 2, 3];

    assert_eq!(a, crypto::xor(&a, &vec![0, 0, 0]).unwrap().to_vec());

    let b: Vec<u8> = vec![5, 6, 7];
    let c: Vec<u8> = vec![1 ^ 5, 2 ^ 6, 3 ^ 7];

    let d = crypto::xor(&a, &b).unwrap().into_vec();

    assert_eq!(c, d);

    let b = vec![4, 5];
    assert!(crypto::xor(&a, &b).is_err());
}

fn kdf() {
    let server_secret = ServerSecret::default();
    let r0 = "49920a3d19cb8c62032b34bce702735f633b2ddca2751b37720d8ca8e3f963d681d4796ae9cc7d6bcaff0d570ee919df035824ef570f01eb2b803da675b91bcb5c5ce9d44c8b68fcb3b1a5615b29f72dacfbeb08e68b0c353ef39c26032ff5c5ac180b7fbe7d46e34594f56ed50e6c15d33740ac5edb095d6748acd473b365251d10b42a795476f5d1e69e67688dfa1a33bc0e2ecc54e916837555792588bf14720cb5e6ba8d04e16f6af132d33d95c7b457bb0415030c3016e22419f5e8eea90c65d330a107bcae1f18828dff02e26dab61d2f48b1192ac0f6fbf1a10be539dd237153f89b8b50e2de5eaf10a65f6564c62eb0c69c1b9fb660384935d160c390e020cec58d34ff9b703951ccb4022c306b25fbed6533a4c262b07d715f4ae77430ce51fd82521f34c8587a699187bda934343c164a74b7bd77513840d268a426bffc5b7de6a5e066448aab9d5b8cb1429f07d29f6a6908f0989c79a179c5aaa8948146cce7e347a66ce37ee206b032e8323c2f32f32866ef879540bee9755b5cb21d1160002f32ee97fb70b49e81a68c787aec4e601e05f5c1d518dfd65069f7c8eba30885120c84ca05b999db87942f3d9d8ee98cb9ef0716e1a32d16b5f20af2d1f763acc3a787064efce442ab3f6cf1ae034ce53ba223de6b1873ff2e1cc535cf7bd19abd60a03a5deaa1a57ae453dc0809aa428e0797dc1796aa93b46a1b40992c7a2c720f03013c6de0903de9e0b4c2bc7f7d6a8cbe38767c3e81161d4f0ace3f5874a34af786221800b64701ffd5f9342ad60a2f8d55d3915927b39d304147cbc761ba73ea15f1fb93d5e8c261e4e336ea19bde943cc1d3299be9e2d485a1cfe66529efcbe9183710b78cc688d849695211e45b975f806c7acb216c7b685bb9666c7a9e1adc4e002df83a80665a289b067ed1c2993a1c6cf26aeb919baf551f599dbad477dc1101bbb3d4c876708bf5c21405e3d58d22a0810788d320222bf217b24fd18589dc5d10f6b1198b5d0a8827378bf1ce62981fce9f162f3237a091b625844891d008852f930d52df5356d6dd0b26a784b142a9b926b1bf7ca4c2d117989a401726cd7d2db23fd083cfb4ff94d41850f73f04c0c1e7b5902fa5295a3c68018aef7f5cba1ec02ac8aecd6bbba616c8ae11cc6cf798970193963d967c521844fc77e00b4118c86b8368ed795e422302dab9433aeb714f9d5a1c4ada39a5addd865d03c289e2b40a7729bbe993ccdf0d00832d8b4b8a85a284fcb115e2c419c167fee261c5a81508c4e7092805c148fc51f38ccf01b3b75ce848820b858546e7606f69f01eb505f93cb4a41760ce6c0b7dc022cfff7dbdbadc37fe667cb93a5e8eb9c7186988ad37ccdc4e204c24f0b93de7c284ab637d345699f8b11dc74ed20c4486d607d3626d35ebc4582927671136422debba5d7886256d";
    let r1 = "a56436e51af7221f6dfb555288dd342096fba6f41b8b570d65ca78ca811c6b3431c19c39f50d2a6799120ac8d9683086f7f3f36179a415c56961c69edc9dffb541502ca5674fb830050202f2beea3484e049c1b136b63750c544f390f72768ab9c145ca2f04e06f54ba99f2d37bd6206390e8a56e181b23f89182aee6c9621d69dc56bf196bc3e4ea6a7dc1c30bf787c2046645f9a85137d1aced16bf3ec0b1f0065578ff4b625fde681e4a5017cc3a493d891bdeb3c9c5e263e9ddd7b6a248a59885c4c634ae0f3e7bb63e72858815b812a3d00d9bb929aa469fd65f479561e3bedaeb03cbf881a744e68e380f554c4a1139fcbf618d38ea7b75a79d9fb0a2d0183ef34324966d2b84111f379850be730380be3ccab5b7d728f4bf0020d20882d95f55509205de23fbc627854bc408ca9bb88cc446c124e0856b6b258187c9882d46776df09a1bb89ca5fe2920917ca39a04fbe3586d2877a01d3a6f72f6f17384776bd6b8a46dbb0020af0f376a05c0e68f1ece62bd8f1e6f37518bc91eae01c6884d4e1e16ff822df134c40d02d594f579319e2bd7fb7271de5c96cd9feba67e9ee3662f8a7008b8a530e805842c0e46a6137aa930610953f00b531987565bd729d1bde21eb06daba23dedf57f7bf65a65d6ad526474d51acac1566873a9c128a478ac30d2abcef7958153ec8c792c3e0414e8140ac1ac353be00d435cf01674f582ba30047008de9e4d85cbd4160dda11730f4f7492f9a1af387354a8d734f2c19234a235d5b60e5d529464d020e4118c42522e58ce4c74c6c6a621eb719ac6dfbcb28c2f3880bd9d9d7f2a04443ae7daf4498b61fc6dc6187d5be361a35bb5d6aa145a61b9c47e05c3e5c51200936ce5f48f248002e2edc83a5dc24b2a22819801087a0bc82f459a8248dc807509bccba3f62d24462c1732d5baf55d47de7d4bf7a365a2982fe0fb6d889aa3d707caa754683ef4c1d3b560558c3d0be8027b64ea185d33c0313ae45d0d606e5f7099b74285528cf381c4f46ccc949813ec3d1ef40a3039a1e0f07915d15b6d85d6e631c8f709b4eacedb4b94bcc406d61bd861441a074dd6fb792acc362cd3b37dd0e78c1f776a131d9862a623702705e52af123f2ba0b3aab8f5c79bd64bdba4d63323823d164d5e8fef5a54f440b80605961aba588e5a871a20f851419ae0284309f163c2048620a6082df3b4e8c23006cbe0eaa0d24c0f17a2230eaf566965f1b4d43d8ea462d2a5c68d5430a3117967ad619e09e50705a4bc7347580ab7f4501823131d58735d348822d0228b2fb5355626513181aa92740c2539fd233dc955723b05a3bef58aedadbc72d852a6544a3c40e408f209d049f6774d46249c4b8d08bb41c512400499c8a845a6b8c894bf9a7be0cf212f88252f1a2b67e8e4db3dad12e7da306a5040f00b593a5180c9";
    let refs = [r0, r1];
    for round in 0..1 {
        let round_secret = crypto::kdf_hmac(&server_secret, round).unwrap();
        assert_eq!(
            round_secret.secret.to_vec(),
            hex::decode(refs[round as usize]).unwrap()
        );
    }
}

fn test_keypair() -> crypto::CryptoResult<KeyPair> {
    let handle = sgx_tcrypto::SgxEccHandle::new();
    handle.open().unwrap();
    match handle.create_key_pair() {
        Ok(pair) => Ok(KeyPair {
            prv_key: PrvKey::from(pair.0),
            pub_key: PubKey::from(pair.1),
        }),
        Err(e) => Err(CryptoError::SgxCryptoError(e)),
    }
}

fn sign() {
    let keypair = test_keypair().unwrap();

    let mutable = SignedUserMessage {
        round: 100,
        message: test_raw_msg(),
        tee_sig: Default::default(),
        tee_pk: Default::default(),
    };

    let signed = crypto::sign_dc_message(&mutable, keypair.prv_key).unwrap();

    assert_eq!(signed.tee_pk, keypair.pub_key);
    assert!(crypto::verify_dc_message(&signed).unwrap());
}

fn round() {
    // xor in server's key and xor them out
    unimplemented!()
}
