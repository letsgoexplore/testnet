#ifndef SGX_DC_NETS_ERROR_CODE_H
#define SGX_DC_NETS_ERROR_CODE_H

const int INVALID_INPUT = -0x0001;
const int EXCEPT_CAUGHT = -0x0002;
const int GOOD = 0;

const int SCHEDULE_FAILED = -0xFFFF;
const int SCHEDULE_CONTINUE = 1;
const int SCHEDULE_DONE = 0;

#endif  // SGX_DC_NETS_ERROR_CODE_H
