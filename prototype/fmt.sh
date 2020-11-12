#!/usr/bin/env bash

set -euo pipefail

rustfmt ./app/src/main.rs
rustfmt ./enclave/src/lib.rs
rustfmt ./interface/src/lib.rs
