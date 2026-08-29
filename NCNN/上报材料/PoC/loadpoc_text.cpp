#include "net.h"
#include <cstdio>
int main(int argc, char** argv) {
    ncnn::Net net;
    int ret = net.load_param(argv[1]);
    printf("load_param ret=%d\n", ret);
    return 0;
}
