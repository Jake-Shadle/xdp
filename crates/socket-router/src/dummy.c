struct xdp_md {};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

__attribute__((section("xdp"), used))
int socket_router(struct xdp_md *ctx)
{
    return XDP_PASS;
}
