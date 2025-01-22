#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 64);
} XSK SEC(".maps");

volatile const __u32 TEST_PORT = 7777;
volatile const __u64 SOCKET_COUNT = 0;
__hidden __u64 COUNTER = 0;

SEC("xdp")
int socket_router(struct xdp_md *ctx)
{
    __u64 index = __sync_fetch_and_add(&COUNTER, 1);
    __u32 mindex = index % SOCKET_COUNT;
    // COUNTER++;
    // __u32 mindex = COUNTER % SOCKET_COUNT;

    return bpf_redirect_map(&XSK, mindex, XDP_DROP);
}
