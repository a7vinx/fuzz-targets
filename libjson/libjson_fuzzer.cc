#include <stdint.h>
#include <stdio.h>

#include "json.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    json_parser parser;
    if (json_parser_init(&parser, NULL, NULL, NULL)) {
        fprintf(stderr, "something wrong happened during init\n");
        return -1;
    }
    json_parser_string(&parser, (char *)Data, (int)Size, NULL);
    json_parser_free(&parser);
    return 0;
}
