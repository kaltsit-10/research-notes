#include <stdio.h>
#include "net.h"
int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <file.parambin>\n", argv[0]); return 2; }
    ncnn::Net net;
    int ret = net.load_param_bin(argv[1]);
    fprintf(stderr, "load_param_bin ret=%d\n", ret);
    return 0;
}
