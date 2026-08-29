// ncnn param fuzz harness (libFuzzer + ASan)
//
// Target surface:
//   1. text .param  -> Net::load_param_mem()  -> load_param(DataReader)
//      (magic "7767517", layer header top_count parsing, ParamDict::load_param)
//   2. binary .parambin -> Net::load_param_bin(FILE*) via fmemopen
//      (magic 0x7685DD LE, array length fields, Mat::create sizes)
//
// Same input is fed to BOTH parsers so the shared corpus serves both paths.
//
// Known pre-existing crashes (duplicates to dedup during triage):
//   - bin: 96B NULL-deref (Mat::create(INT32_MIN)) -- CVE-nnnn, master unpatched
//   - text/bin: huge allocation OOM -- DoS class
// Any NEW crash (OOB read/write, UAF, null deref on fresh path) is the finding.
//
// Usage: ./fuzz_param -dict=ncnn_param.dict -close_fd_mask=3 -max_len=262144 corpus/

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include "net.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // 256KB cap: bigger inputs only buy OOM-doom / slow scan, not new bugs.
    if (size < 4 || size > 262144)
        return 0;

    // ---- known-DoS guard (dedup, not a new finding) ----
    // BOTH parsers read layer_count/blob_count and do
    // `layers.resize(layer_count)` / `blobs.resize(blob_count)` with NO
    // sanity check (net.cpp:1707).  A crafted huge count makes resize()
    // try GBs -> libFuzzer out-of-memory (the already-reported CWE-789 DoS
    // class).  Skip so the fuzzer lives to explore the deeper parsing
    // surface instead of dying on it.
    const bool bin_magic = size >= 12 && data[0] == 0xDD && data[1] == 0x85 && data[2] == 0x76 && data[3] == 0x00;
    if (bin_magic)
    {
        uint32_t layer_count = 0;
        uint32_t blob_count = 0;
        memcpy(&layer_count, data + 4, 4);
        memcpy(&blob_count, data + 8, 4);
        if (layer_count > 65536 || blob_count > 65536)
            return 0;   // known-DoS input (bin)
    }
    // text: magic "7767517" then "<layer_count> <blob_count>".
    // Mirror scanf's exact behavior (glibc): whitespace = space \t \n \v \f \r,
    // and out-of-range ints wrap mod 2^32, so e.g. "-2340366766" becomes a
    // POSITIVE 1954600530 that defeats the parser's "<= 0" check and makes
    // blobs.resize() allocate ~250GB.  Reject any count whose effective
    // int32 value exceeds 65536 (the already-reported CWE-789 DoS class).
    auto skip_ws = [&](size_t& p)
    {
        while (p < size && (data[p] == ' ' || data[p] == '\t' || data[p] == '\n' ||
                            data[p] == '\v' || data[p] == '\f' || data[p] == '\r')) p++;
    };
    auto parse_int32 = [&](size_t& p) -> int32_t
    {
        skip_ws(p);
        bool neg = false;
        if (p < size && (data[p] == '-' || data[p] == '+')) { neg = (data[p] == '-'); p++; }
        uint64_t mag = 0;
        while (p < size && data[p] >= '0' && data[p] <= '9')
        {
            mag = (mag * 10 + (uint64_t)(data[p] - '0')) & 0xFFFFFFFFULL;  // low 32 bits == scanf %d wrap
            p++;
        }
        const uint32_t raw = neg ? (uint32_t)((0x100000000ULL - mag) & 0xFFFFFFFFULL) : (uint32_t)mag;
        return (int32_t)raw;
    };
    // magic is also scanf %d -> may carry leading '+'/'-', e.g. "+7767517".
    size_t p = 0;
    skip_ws(p);
    const int32_t magic = parse_int32(p);
    if (magic == 7767517)
    {
        const int32_t lc = parse_int32(p);
        const int32_t bc = parse_int32(p);
        if (lc > 65536 || bc > 65536)
            return 0;   // known-DoS input (text): resize() to a huge vector
    }

    // path 1: text .param (needs NUL terminator for the token scanner)
    {
        ncnn::Net net;
        net.opt.num_threads = 1;             // determinism + speed
        net.opt.use_vulkan_compute = false;
        net.opt.use_fp16_packed = false;
        net.opt.use_fp16_storage = false;

        std::vector<char> buf(data, data + size);
        buf.push_back('\0');
        net.load_param_mem(buf.data());
    }

    // path 2: binary .parambin (fresh Net, same input bytes)
    {
        FILE* fp = fmemopen((void*)data, size, "rb");
        if (fp)
        {
            ncnn::Net netb;
            netb.opt.num_threads = 1;
            netb.opt.use_vulkan_compute = false;
            netb.opt.use_fp16_packed = false;
            netb.opt.use_fp16_storage = false;
            netb.load_param_bin(fp);
            fclose(fp);
        }
    }

    return 0;
}
