// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

extern crate sgx_types;
extern crate sgx_urts;

use sgx_types::*;

extern crate interface;
extern crate serde_cbor;

mod client;
mod enclave_wrapper;

use enclave_wrapper::*;
use interface::*;

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

fn main() {
    pretty_env_logger::init();

    let dc_enclave = match DcNetEnclave::init("enclave.signed.so") {
        Ok(r) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let send_request = SendRequest {
        user_id: UserId::default(),
        message: [9 as u8; DC_NET_MESSAGE_LENGTH],
        round: 0,
        server_keys: vec![ServerSecret::gen_test(1), ServerSecret::gen_test(2)],
    };

    let sgx_key = vec![1_u8; 128];

    match dc_enclave.client_submit(&send_request, &sgx_key) {
        Ok(m) => println!("{:?}", m),
        Err(e) => println!("Err {}", e),
    }

    dc_enclave.destroy();
}
