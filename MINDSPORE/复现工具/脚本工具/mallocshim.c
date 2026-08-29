/* LD_PRELOAD malloc shim：打印 size==0 的分配（0字节缓冲）及之后的小分配，重建堆布局。
 * 用法: LD_PRELOAD=/tmp/mallocshim.so python run_mval.py xxx.ckpt */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

static void *(*real_malloc)(size_t) = NULL;
static int n = 0;

void *malloc(size_t sz) {
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    void *p = real_malloc(sz);
    /* 打印 size==0 及后续 60 个小分配（用于定位 0 字节缓冲后的相邻对象） */
    if (sz == 0 || (n < 60 && sz <= 256)) {
        fprintf(stderr, "[SHIM] malloc(%zu)=%p n=%d\n", sz, p, n);
        n++;
    }
    return p;
}
