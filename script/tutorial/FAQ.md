# FAQ
1. `slot length` has to be divisible by 4, or otherwise there are `cbor problem`.
2. Encountering following problem:
```shell
# problem
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0664 for './pem_key/ss1.pem' are too open.

# solution
chmod 400 ./pem_key/ss1.pem
```