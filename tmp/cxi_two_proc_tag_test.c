/* cxi_two_proc_tag_test.c — deterministic overflow/search-on-append race
 * reproducer for CXI hardware tag matching.
 *
 * Question under test: does unexpected_hdr_disable actually suppress
 * Cassini's search-on-append matching of an overflow-buffered message
 * against a LATER-posted priority LE? Two competing hypotheses:
 *   (a) it means "don't register this OVF arrival in the unexpected-header
 *       tracker" (so a later APPEND's search-on-append finds nothing) --
 *       set on the OVERFLOW LE (UCX_CXI_TAG_TEST_OVF_UHD=1).
 *   (b) it means "don't have THIS priority LE's append search the overflow
 *       list at all" -- set on the PRIORITY LE (UCX_CXI_TAG_TEST_PRI_UHD=1).
 * Run with each combination via env vars (both default in cxi_tag.c match
 * current committed state: OVF=1, PRI=0 unless overridden).
 *
 * Deterministic ordering (not a narrow timing race -- we WAIT for
 * explicit confirmation at each step, using our own eager_cb as the
 * in-band "the message has definitely landed unexpected" signal):
 *
 *   Rank 1 (receiver): opens iface with REAL eager_cb/rndv_cb (required
 *     for the tag PTE to open at all), does NOT post a receive yet.
 *   Rank 0 (sender): sends ONE tag_eager_short message for a well-known
 *     tag.
 *   Rank 1: polls progress until its own eager_cb fires (proof the
 *     message physically landed in the overflow ring and was processed
 *     as unexpected -- this is uct_cxi_iface_tag_handle_ovf_arrival()
 *     calling back into us, synchronously, from inside uct_iface_progress).
 *   Rank 1: ONLY NOW posts uct_iface_tag_recv_zcopy() for the same tag --
 *     guaranteed too late for a direct match, by construction.
 *   Rank 1: polls progress for a bounded window watching for
 *     completed_cb to fire on this late-posted context.
 *     - If it fires with real data -> hardware DID retroactively match
 *       (search-on-append still found it despite the flag).
 *     - If it never fires -> call uct_iface_tag_recv_cancel() and confirm
 *       completed_cb(..., UCS_ERR_CANCELED) fires cleanly -> the LE sat
 *       unmatched, confirming search-on-append was suppressed.
 *
 * Watch the debug log output (UCX_LOG_LEVEL=debug) for the
 * [OVF-ARRIVAL]/[PRI-LE-POST]/[OVF-MATCHED]/[DIRECT-MATCH]/[UNLINK]
 * markers added to cxi_tag.c -- this program's own stdout gives the
 * high-level verdict, the debug log gives the exact event sequence.
 *
 * Usage:
 *   bash ucx/tmp/test_cxi_tag_race.sh --build
 *   UCX_CXI_TAG_TEST_OVF_UHD=1 UCX_CXI_TAG_TEST_PRI_UHD=0 \
 *       sbatch ucx/tmp/test_cxi_tag_race.sh
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/mman.h>

#include <uct/api/uct.h>
#include <uct/api/v2/uct_v2.h>
#include <ucs/time/time.h>

#define BUF_SIZE          256
#define TCP_PORT          17924
#define RDV_DIR           "/cosmos/nfs/home/jadhicks/ucx/tmp"
#define POLL_USEC         10000
#define WAIT_TIMEOUT_SEC  8.0
#define TEST_TAG          0x1234567890ABCDEFULL

typedef struct {
    uint32_t dev_addr_len;
    uint32_t iface_addr_len;
    uint8_t  dev_addr[64];
    uint8_t  iface_addr[64];
} peer_info_t;

static int rank;

#define DIE(fmt, ...) \
    do { fprintf(stderr, "rank %d: " fmt "\n", rank, ##__VA_ARGS__); \
         exit(1); } while (0)

#define CHECK_STATUS(st, msg) \
    do { if ((st) != UCS_OK) \
             DIE("%s: %s", (msg), ucs_status_string(st)); } while (0)

#define CHECK_RET(r, msg) \
    do { if ((int)(r) < 0) DIE("%s: %s", (msg), strerror(errno)); } while (0)

/* ------------------------------------------------------------------- */
static void tcp_send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        CHECK_RET(n, "send");
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static void tcp_recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n == 0) DIE("tcp_recv_all: peer closed connection");
        CHECK_RET(n, "recv");
        p += (size_t)n;
        len -= (size_t)n;
    }
}

static int rendezvous(const char *job_id)
{
    char rdv_path[256];
    snprintf(rdv_path, sizeof(rdv_path), "%s/cxi_rdv_tag_%s", RDV_DIR, job_id);
    int conn_fd;

    if (rank == 0) {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));

        FILE *f = fopen(rdv_path, "w");
        if (!f) DIE("fopen(%s): %s", rdv_path, strerror(errno));
        fprintf(f, "%s\n", hostname);
        fclose(f);

        int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        CHECK_RET(listen_fd, "socket");
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(TCP_PORT);

        CHECK_RET(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)), "bind");
        CHECK_RET(listen(listen_fd, 1), "listen");

        printf("rank 0: listening on %s:%d\n", hostname, TCP_PORT);
        fflush(stdout);

        conn_fd = accept(listen_fd, NULL, NULL);
        CHECK_RET(conn_fd, "accept");
        close(listen_fd);
        unlink(rdv_path);
    } else {
        char r0_host[256] = {0};
        FILE *f = NULL;
        while (!f) {
            f = fopen(rdv_path, "r");
            if (!f) usleep(POLL_USEC);
        }
        if (!fgets(r0_host, sizeof(r0_host), f))
            DIE("empty rendezvous file");
        fclose(f);
        r0_host[strcspn(r0_host, "\n")] = '\0';

        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TCP_PORT);

        while (getaddrinfo(r0_host, port_str, &hints, &res) != 0)
            usleep(POLL_USEC);

        int tries = 50;
        conn_fd = -1;
        while (tries-- > 0) {
            conn_fd = socket(res->ai_family, res->ai_socktype, 0);
            CHECK_RET(conn_fd, "socket");
            if (connect(conn_fd, res->ai_addr, res->ai_addrlen) == 0)
                break;
            close(conn_fd);
            conn_fd = -1;
            usleep(POLL_USEC * 5);
        }
        freeaddrinfo(res);
        if (conn_fd < 0) DIE("could not connect to %s:%d", r0_host, TCP_PORT);

        printf("rank 1: connected to %s:%d\n", r0_host, TCP_PORT);
        fflush(stdout);
    }

    return conn_fd;
}

/* ------------------------------------------------------------------- *
 * Tag callbacks -- eager_cb doubles as our "message physically landed
 * unexpected" signal (see file header).
 * ------------------------------------------------------------------- */
static volatile int      g_unexp_fired  = 0;
static volatile uint64_t g_unexp_tag    = 0;
static volatile size_t   g_unexp_len    = 0;

static ucs_status_t
test_eager_cb(void *arg, void *data, size_t length, unsigned flags,
             uct_tag_t stag, uint64_t imm, void **context)
{
    g_unexp_tag   = stag;
    g_unexp_len   = length;
    g_unexp_fired = 1;
    printf("rank %d: [TEST] eager_cb FIRED -- message landed unexpected, "
           "tag=0x%lx len=%zu\n", rank, (unsigned long)stag, length);
    fflush(stdout);
    return UCS_OK;
}

static ucs_status_t
test_rndv_cb(void *arg, unsigned flags, uint64_t stag, const void *header,
            unsigned header_length, uint64_t remote_addr, size_t length,
            const void *rkey_buf)
{
    return UCS_OK;
}

/* Priority-recv completion context. uct_tag_context_t must be first. */
typedef struct {
    uct_tag_context_t   super;
    volatile int         consumed;
    volatile int         completed;
    volatile ucs_status_t status;
    uint64_t              stag;
    size_t                length;
} recv_ctx_t;

static void test_consumed_cb(uct_tag_context_t *self)
{
    recv_ctx_t *ctx = (recv_ctx_t *)self;
    ctx->consumed = 1;
    printf("rank %d: [TEST] tag_consumed_cb fired (late-posted recv)\n", rank);
    fflush(stdout);
}

static void test_completed_cb(uct_tag_context_t *self, uct_tag_t stag,
                              uint64_t imm, size_t length, void *inline_data,
                              ucs_status_t status)
{
    recv_ctx_t *ctx = (recv_ctx_t *)self;
    ctx->stag      = stag;
    ctx->length    = length;
    ctx->status    = status;
    ctx->completed = 1;
    printf("rank %d: [TEST] completed_cb fired -- status=%s tag=0x%lx "
           "len=%zu\n", rank, ucs_status_string(status),
           (unsigned long)stag, length);
    fflush(stdout);
}

/* ------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *dev_name = (argc > 1) ? argv[1] : "cxi0";
    const char *proc_id  = getenv("SLURM_PROCID");
    const char *job_id   = getenv("SLURM_JOB_ID");
    rank = proc_id ? atoi(proc_id) : 0;
    if (!job_id) job_id = "0";

    printf("rank %d: node=%s device=%s OVF_UHD=%s PRI_UHD=%s\n",
           rank,
           getenv("SLURMD_NODENAME") ? getenv("SLURMD_NODENAME") : "unknown",
           dev_name,
           getenv("UCX_CXI_TAG_TEST_OVF_UHD") ?
               getenv("UCX_CXI_TAG_TEST_OVF_UHD") : "(default=1)",
           getenv("UCX_CXI_TAG_TEST_PRI_UHD") ?
               getenv("UCX_CXI_TAG_TEST_PRI_UHD") : "(default=0)");
    fflush(stdout);

    ucs_status_t     status;
    uct_component_h *components;
    unsigned         num_components;

    status = uct_query_components(&components, &num_components);
    CHECK_STATUS(status, "uct_query_components");

    uct_component_h cxi_comp = NULL;
    for (unsigned i = 0; i < num_components; i++) {
        uct_component_attr_t attr;
        memset(&attr, 0, sizeof(attr));
        attr.field_mask = UCT_COMPONENT_ATTR_FIELD_NAME;
        uct_component_query(components[i], &attr);
        if (!strcmp(attr.name, "cxi")) {
            cxi_comp = components[i];
            break;
        }
    }
    uct_release_component_list(components);
    if (!cxi_comp) DIE("CXI component not found");

    uct_md_config_t *md_config;
    status = uct_md_config_read(cxi_comp, NULL, NULL, &md_config);
    CHECK_STATUS(status, "uct_md_config_read");

    uct_md_h md;
    status = uct_md_open(cxi_comp, dev_name, md_config, &md);
    CHECK_STATUS(status, "uct_md_open");
    uct_config_release(md_config);

    ucs_async_context_t *async;
    status = ucs_async_context_create(UCS_ASYNC_MODE_POLL, &async);
    CHECK_STATUS(status, "ucs_async_context_create");

    uct_worker_h worker;
    status = uct_worker_create(async, UCS_THREAD_MODE_SINGLE, &worker);
    CHECK_STATUS(status, "uct_worker_create");

    uct_iface_config_t *iface_config;
    status = uct_md_iface_config_read(md, "cxi", NULL, NULL, &iface_config);
    CHECK_STATUS(status, "uct_md_iface_config_read");

    /* Both ranks supply real eager_cb/rndv_cb -- required for the tag PTE
     * to open at all (see uct_cxi_iface_open_tag_pte), and the sender
     * needs its own iface's tag capability advertised to call
     * uct_ep_tag_eager_short at all. */
    uct_iface_params_t iface_params;
    memset(&iface_params, 0, sizeof(iface_params));
    iface_params.field_mask           = UCT_IFACE_PARAM_FIELD_OPEN_MODE |
                                        UCT_IFACE_PARAM_FIELD_DEVICE |
                                        UCT_IFACE_PARAM_FIELD_HW_TM_EAGER_CB |
                                        UCT_IFACE_PARAM_FIELD_HW_TM_RNDV_CB;
    iface_params.open_mode            = UCT_IFACE_OPEN_MODE_DEVICE;
    iface_params.mode.device.tl_name  = "cxi";
    iface_params.mode.device.dev_name = dev_name;
    iface_params.eager_cb             = test_eager_cb;
    iface_params.eager_arg            = NULL;
    iface_params.rndv_cb              = test_rndv_cb;
    iface_params.rndv_arg             = NULL;

    uct_iface_h iface;
    status = uct_iface_open(md, worker, &iface_params, iface_config, &iface);
    CHECK_STATUS(status, "uct_iface_open");
    uct_config_release(iface_config);

    uct_iface_attr_t iface_attr;
    memset(&iface_attr, 0, sizeof(iface_attr));
    status = uct_iface_query(iface, &iface_attr);
    CHECK_STATUS(status, "uct_iface_query");

    if (!(iface_attr.cap.flags & UCT_IFACE_FLAG_TAG_EAGER_SHORT)) {
        DIE("tag PTE did not open (TAG_EAGER_SHORT not advertised) -- "
            "check UCX_CXI_TAG_ENABLE / config");
    }

    uint8_t *buf = (uint8_t *)mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) DIE("mmap: %s", strerror(errno));
    memset(buf, 0xCD, BUF_SIZE);

    uct_md_mem_reg_params_t reg_params;
    memset(&reg_params, 0, sizeof(reg_params));
    reg_params.field_mask = UCT_MD_MEM_REG_FIELD_FLAGS;
    reg_params.flags      = UCT_MD_MEM_ACCESS_RMA;

    uct_mem_h memh = UCT_MEM_HANDLE_NULL;
    status = uct_md_mem_reg_v2(md, buf, BUF_SIZE, &reg_params, &memh);
    CHECK_STATUS(status, "uct_md_mem_reg_v2");

    peer_info_t my_info;
    memset(&my_info, 0, sizeof(my_info));
    my_info.dev_addr_len   = (uint32_t)iface_attr.device_addr_len;
    my_info.iface_addr_len = (uint32_t)iface_attr.iface_addr_len;

    status = uct_iface_get_device_address(iface,
                  (uct_device_addr_t *)my_info.dev_addr);
    CHECK_STATUS(status, "uct_iface_get_device_address");
    status = uct_iface_get_address(iface,
                  (uct_iface_addr_t *)my_info.iface_addr);
    CHECK_STATUS(status, "uct_iface_get_address");

    int sock = rendezvous(job_id);

    peer_info_t peer;
    tcp_send_all(sock, &my_info, sizeof(my_info));
    tcp_recv_all(sock, &peer,    sizeof(peer));

    uct_ep_params_t ep_params;
    memset(&ep_params, 0, sizeof(ep_params));
    ep_params.field_mask = UCT_EP_PARAM_FIELD_IFACE    |
                           UCT_EP_PARAM_FIELD_DEV_ADDR  |
                           UCT_EP_PARAM_FIELD_IFACE_ADDR;
    ep_params.iface      = iface;
    ep_params.dev_addr   = (const uct_device_addr_t *)peer.dev_addr;
    ep_params.iface_addr = (const uct_iface_addr_t  *)peer.iface_addr;

    uct_ep_h ep;
    status = uct_ep_create(&ep_params, &ep);
    CHECK_STATUS(status, "uct_ep_create");

    /* Barrier: both sides have opened iface + ep. */
    {   uint8_t go = 1;
        tcp_send_all(sock, &go, 1);
        tcp_recv_all(sock, &go, 1);
    }

    if (rank == 0) {
        /* --- Sender: fire one eager_short for TEST_TAG, nothing else --- */
        printf("rank 0: sending tag_eager_short tag=0x%lx\n",
               (unsigned long)TEST_TAG);
        fflush(stdout);

        status = uct_ep_tag_eager_short(ep, TEST_TAG, buf, 32);
        CHECK_STATUS(status, "tag_eager_short");

        /* Drain our own progress so the send actually leaves the NIC. */
        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (ucs_get_time() < deadline) {
            uct_iface_progress(iface);
            usleep(1000);
        }

        printf("rank 0: waiting for rank 1's verdict...\n");
        fflush(stdout);

        char verdict[256] = {0};
        tcp_recv_all(sock, verdict, sizeof(verdict));
        printf("rank 0: rank 1 reports: %s\n", verdict);
        fflush(stdout);

    } else {
        /* --- Receiver: do NOT post a receive until eager_cb confirms
         * the message has already landed unexpected. --- */
        printf("rank 1: waiting for unexpected arrival (no receive posted "
               "yet)...\n");
        fflush(stdout);

        ucs_time_t deadline = ucs_get_time() +
                              ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!g_unexp_fired && (ucs_get_time() < deadline)) {
            uct_iface_progress(iface);
        }

        char verdict[256];

        if (!g_unexp_fired) {
            snprintf(verdict, sizeof(verdict),
                     "TIMEOUT -- message never arrived unexpected at all");
            printf("rank 1: %s\n", verdict);
            fflush(stdout);
            tcp_send_all(sock, verdict, sizeof(verdict));
            goto cleanup;
        }

        /* Now, deliberately late, post the receive for the same tag. */
        recv_ctx_t rctx;
        memset(&rctx, 0, sizeof(rctx));
        rctx.super.tag_consumed_cb = test_consumed_cb;
        rctx.super.completed_cb    = test_completed_cb;
        rctx.super.rndv_cb         = NULL;

        printf("rank 1: eager_cb already fired -- NOW posting late "
               "tag_recv_zcopy for tag=0x%lx\n", (unsigned long)TEST_TAG);
        fflush(stdout);

        uct_iov_t iov;
        iov.buffer = buf;
        iov.length = BUF_SIZE;
        iov.memh   = memh;
        iov.stride = 0;
        iov.count  = 1;

        status = uct_iface_tag_recv_zcopy(iface, TEST_TAG, UINT64_MAX,
                                          &iov, 1, &rctx.super);
        CHECK_STATUS(status, "tag_recv_zcopy (late)");

        /* Watch for a retroactive match. */
        deadline = ucs_get_time() + ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!rctx.completed && (ucs_get_time() < deadline)) {
            uct_iface_progress(iface);
        }

        if (rctx.completed) {
            if (rctx.status == UCS_OK) {
                snprintf(verdict, sizeof(verdict),
                         "MATCHED -- hardware retroactively matched the "
                         "late-posted LE via search-on-append (status=OK, "
                         "len=%zu) -- unexpected_hdr_disable did NOT "
                         "suppress it in this configuration",
                         rctx.length);
            } else {
                snprintf(verdict, sizeof(verdict),
                         "COMPLETED with unexpected status: %s",
                         ucs_status_string(rctx.status));
            }
            printf("rank 1: %s\n", verdict);
            fflush(stdout);
            tcp_send_all(sock, verdict, sizeof(verdict));
            goto cleanup;
        }

        /* No retroactive match within the window -- explicitly cancel and
         * confirm it comes back cleanly (LE sat unmatched). */
        printf("rank 1: no match within %.1fs -- issuing explicit cancel "
               "to confirm LE sat unmatched\n", WAIT_TIMEOUT_SEC);
        fflush(stdout);

        status = uct_iface_tag_recv_cancel(iface, &rctx.super, 0);
        CHECK_STATUS(status, "tag_recv_cancel");

        deadline = ucs_get_time() + ucs_time_from_sec(WAIT_TIMEOUT_SEC);
        while (!rctx.completed && (ucs_get_time() < deadline)) {
            uct_iface_progress(iface);
        }

        if (rctx.completed && (rctx.status == UCS_ERR_CANCELED)) {
            snprintf(verdict, sizeof(verdict),
                     "NOT-MATCHED -- late LE never matched, clean "
                     "UCS_ERR_CANCELED confirms search-on-append was "
                     "suppressed for this configuration");
        } else if (rctx.completed) {
            snprintf(verdict, sizeof(verdict),
                     "AMBIGUOUS -- cancel raced a late match, status=%s",
                     ucs_status_string(rctx.status));
        } else {
            snprintf(verdict, sizeof(verdict),
                     "HUNG -- cancel itself never completed (real bug, "
                     "not a search-on-append answer)");
        }
        printf("rank 1: %s\n", verdict);
        fflush(stdout);
        tcp_send_all(sock, verdict, sizeof(verdict));
    }

cleanup:
    close(sock);

    uct_md_mem_dereg_params_t dereg_params;
    memset(&dereg_params, 0, sizeof(dereg_params));
    dereg_params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
    dereg_params.memh       = memh;
    uct_md_mem_dereg_v2(md, &dereg_params);

    uct_ep_destroy(ep);
    uct_iface_close(iface);
    uct_worker_destroy(worker);
    ucs_async_context_destroy(async);
    uct_md_close(md);

    printf("rank %d: done\n", rank);
    return 0;
}
