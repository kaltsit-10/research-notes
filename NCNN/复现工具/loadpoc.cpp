#include "net.h"
#include <cstdio>
int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: %s <parambin>\n", argv[0]); return 1; }
    ncnn::Net net;
    int ret = net.load_param_bin(argv[1]);
    printf("load_param_bin ret=%d\n", ret);
    return 0;
}
