## Easy Approach
`./run_tests.sh` provide an easy approach of run ZIPNet:
```shell
./run_tests.sh
```

## Normal Approach
Steps are basically same with [HowToEvaluate.md](HowToEvaluate.md). Only set the `EVALUATION_FLAG = false` in [interface/src/params.rs](../../interface/src/params.rs) and `is_EVALUATION=0` in [script/dc-net-control.sh](../dc-net-control.sh). 