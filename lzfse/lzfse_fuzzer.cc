#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "lzfse.h"

#define OP_DECODE 0
#define OP_ENCODE 1

static int test_one_input(int op, const uint8_t *data, size_t size) {
    size_t bufsz = ( op == OP_ENCODE ) ? size + 1 : size * 4 + 1;
    size_t retsz = 0;
    int loop = 6;
    void *newp = NULL;
    uint8_t *buf = (uint8_t *)malloc(bufsz);

    while (loop--) {
        if (op == OP_DECODE)
            retsz = lzfse_decode_buffer(buf, bufsz, data, size, NULL);
        else
            retsz = lzfse_encode_buffer(buf, bufsz, data, size, NULL);

        if (retsz == bufsz) {
            bufsz <<= 1;
            newp = realloc(buf, bufsz);
            if (newp == NULL) {
                perror("realloc");
                free(buf);
                return -1;
            } else {
                buf = (uint8_t *)newp;
                continue;
            }
        }
        break;
    }
    free(buf);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { 
    test_one_input(OP_DECODE, data, size);
    test_one_input(OP_ENCODE, data, size);
    return 0;
}
