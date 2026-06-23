/* Author - Claude Sonnet 4.6
 * cxi_two_proc_test.c — two-process cross-node CXI UCT data-integrity test.
 *
 * Usage (build once, then via SLURM):
 *   bash ucx/tmp/test_cxi_rdma.sh --build
 *   sbatch ucx/tmp/test_cxi_rdma.sh
 *
 * What it tests:
 *
 *   Phase A — PUT:
 *     Rank 0 fills its buffer with 0xAB and posts ep_put_zcopy to rank 1.
 *     Rank 0 flushes, waiting for the C_EVENT_ACK (data committed to rank 1).
 *
 *   Phase B — GET:
 *     Rank 0 zeros its buffer, then posts ep_get_zcopy reading back from
 *     rank 1's buffer (which still holds 0xAB from Phase A).
 *     Rank 0 flushes, waiting for the C_EVENT_REPLY (data written locally).
 *     Rank 0 verifies its buffer contains 0xAB.
 *
 *   Rank 0 then sends a single "done" signal to rank 1.  Rank 1 verifies
 *   its own buffer still holds 0xAB from the PUT, then both tear down.
 *
 * There is no intermediate synchronisation between PUT and GET: the PUT
 * flush guarantees rank 1's buffer is written before the GET is posted,
 * so rank 0 can proceed directly.  Rank 1 simply keeps its iface open
 * until the done signal arrives.
 *
 * Bootstrap:
 *   Rank 0 publishes its hostname on NFS; rank 1 polls and connects via TCP.
 *   One uint8_t "done" signal is sent from rank 0 to rank 1 at the end.
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

#include <uct/api/uct.h>
#include <uct/api/v2/uct_v2.h>
#include <ucs/time/time.h>

/* -------------------------------------------------------------------------
 * Constants
 * -------------------------------------------------------------------------
 */

#define BUF_SIZE          (4 * 1024)    /* bytes to transfer                  */
#define FILL_BYTE         0xAB          /* pattern rank 0 writes in Phase A   */
#define TCP_PORT          17923         /* rendezvous port                    */
#define RDV_DIR           "/cosmos/nfs/home/jadhicks/ucx/tmp"
#define POLL_USEC         10000         /* 10 ms NFS file poll interval       */
#define FLUSH_TIMEOUT_SEC 10.0

/* -------------------------------------------------------------------------
 * Peer-info packet exchanged over TCP.
 * -------------------------------------------------------------------------
 */
typedef struct {
    uint32_t dev_addr_len;
    uint32_t iface_addr_len;
    uint32_t rkey_len;
    uint32_t _pad;
    uint64_t buf_va;
    uint8_t  dev_addr[64];
    uint8_t  iface_addr[64];
    uint8_t  rkey[64];
} peer_info_t;

/* -------------------------------------------------------------------------
 * Globals
 * -------------------------------------------------------------------------
 */
static int rank;

/* -------------------------------------------------------------------------
 * Error macros
 * -------------------------------------------------------------------------
 */
#define DIE(fmt, ...) \
    do { fprintf(stderr, "rank %d: " fmt "\n", rank, ##__VA_ARGS__); \
         exit(1); } while (0)

#define CHECK_STATUS(st, msg) \
    do { if ((st) != UCS_OK) \
             DIE("%s: %s", (msg), ucs_status_string(st)); } while (0)

#define CHECK_RET(r, msg) \
    do { if ((int)(r) < 0) DIE("%s: %s", (msg), strerror(errno)); } while (0)

/* -------------------------------------------------------------------------
 * TCP helpers
 * -------------------------------------------------------------------------
 */
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

/* -------------------------------------------------------------------------
 * flush_ep — poll progress until the EP drains or timeout.
 * -------------------------------------------------------------------------
 */
static void flush_ep(uct_iface_h iface, uct_ep_h ep, const char *label)
{
    ucs_time_t   deadline = ucs_get_time() +
                            ucs_time_from_sec(FLUSH_TIMEOUT_SEC);
    ucs_status_t status;

    do {
        uct_iface_progress(iface);
        status = uct_ep_flush(ep, 0, NULL);
    } while (status == UCS_INPROGRESS && ucs_get_time() < deadline);

    if (status != UCS_OK)
        DIE("%s flush timed out: %s", label, ucs_status_string(status));
}

/* -------------------------------------------------------------------------
 * rendezvous() — publish hostname on NFS, connect via TCP.
 * -------------------------------------------------------------------------
 */
static int rendezvous(const char *job_id)
{
    char rdv_path[256];
    snprintf(rdv_path, sizeof(rdv_path), "%s/cxi_rdv_%s", RDV_DIR, job_id);

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

/* -------------------------------------------------------------------------
 * main
 * -------------------------------------------------------------------------
 */
int main(int argc, char **argv)
{
    const char *dev_name = (argc > 1) ? argv[1] : "cxi0";
    const char *proc_id  = getenv("SLURM_PROCID");
    const char *job_id   = getenv("SLURM_JOB_ID");
    rank = proc_id ? atoi(proc_id) : 0;
    if (!job_id) job_id = "0";

    printf("rank %d: node=%s device=%s\n",
           rank,
           getenv("SLURMD_NODENAME") ? getenv("SLURMD_NODENAME") : "unknown",
           dev_name);
    fflush(stdout);

    /* ------------------------------------------------------------------
     * 1. Find the CXI component.
     * ------------------------------------------------------------------ */
    uct_component_h *components;
    unsigned         num_components;
    ucs_status_t     status;

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

    if (!cxi_comp)
        DIE("CXI component not found — is libuct_cxi.so in the plugin path?");

    /* ------------------------------------------------------------------
     * 2. Open the memory domain.
     * ------------------------------------------------------------------ */
    uct_md_config_t *md_config;
    status = uct_md_config_read(cxi_comp, NULL, NULL, &md_config);
    CHECK_STATUS(status, "uct_md_config_read");

    uct_md_h md;
    status = uct_md_open(cxi_comp, dev_name, md_config, &md);
    CHECK_STATUS(status, "uct_md_open");
    uct_config_release(md_config);

    uct_md_attr_v2_t md_attr;
    memset(&md_attr, 0, sizeof(md_attr));
    md_attr.field_mask = UINT64_MAX;
    status = uct_md_query_v2(md, &md_attr);
    CHECK_STATUS(status, "uct_md_query_v2");

    /* ------------------------------------------------------------------
     * 3. Create worker and open iface.
     * ------------------------------------------------------------------ */
    ucs_async_context_t *async;
    status = ucs_async_context_create(UCS_ASYNC_MODE_POLL, &async);
    CHECK_STATUS(status, "ucs_async_context_create");

    uct_worker_h worker;
    status = uct_worker_create(async, UCS_THREAD_MODE_SINGLE, &worker);
    CHECK_STATUS(status, "uct_worker_create");

    uct_iface_config_t *iface_config;
    status = uct_md_iface_config_read(md, "cxi", NULL, NULL, &iface_config);
    CHECK_STATUS(status, "uct_md_iface_config_read");

    uct_iface_params_t iface_params;
    memset(&iface_params, 0, sizeof(iface_params));
    iface_params.field_mask           = UCT_IFACE_PARAM_FIELD_OPEN_MODE |
                                        UCT_IFACE_PARAM_FIELD_DEVICE;
    iface_params.open_mode            = UCT_IFACE_OPEN_MODE_DEVICE;
    iface_params.mode.device.tl_name  = "cxi";
    iface_params.mode.device.dev_name = dev_name;

    uct_iface_h iface;
    status = uct_iface_open(md, worker, &iface_params, iface_config, &iface);
    CHECK_STATUS(status, "uct_iface_open");
    uct_config_release(iface_config);

    uct_iface_attr_t iface_attr;
    memset(&iface_attr, 0, sizeof(iface_attr));
    status = uct_iface_query(iface, &iface_attr);
    CHECK_STATUS(status, "uct_iface_query");

    /* ------------------------------------------------------------------
     * 4. Allocate and register buffer.
     *
     * Rank 0: pre-filled with FILL_BYTE (source for PUT; zeroed for GET).
     * Rank 1: zeroed (sink for PUT; stays FILL_BYTE as source for GET).
     * ------------------------------------------------------------------ */
    static uint8_t buf[BUF_SIZE];
    memset(buf, (rank == 0) ? FILL_BYTE : 0x00, BUF_SIZE);

    uct_md_mem_reg_params_t reg_params;
    memset(&reg_params, 0, sizeof(reg_params));
    reg_params.field_mask = UCT_MD_MEM_REG_FIELD_FLAGS;
    reg_params.flags      = UCT_MD_MEM_ACCESS_RMA;

    uct_mem_h memh = UCT_MEM_HANDLE_NULL;
    status = uct_md_mem_reg_v2(md, buf, BUF_SIZE, &reg_params, &memh);
    CHECK_STATUS(status, "uct_md_mem_reg_v2");

    /* ------------------------------------------------------------------
     * 5. Collect addressing information.
     * ------------------------------------------------------------------ */
    peer_info_t my_info;
    memset(&my_info, 0, sizeof(my_info));
    my_info.dev_addr_len   = (uint32_t)iface_attr.device_addr_len;
    my_info.iface_addr_len = (uint32_t)iface_attr.iface_addr_len;
    my_info.rkey_len       = (uint32_t)md_attr.rkey_packed_size;
    my_info.buf_va         = (uint64_t)(uintptr_t)buf;

    status = uct_iface_get_device_address(iface,
                  (uct_device_addr_t *)my_info.dev_addr);
    CHECK_STATUS(status, "uct_iface_get_device_address");

    status = uct_iface_get_address(iface,
                  (uct_iface_addr_t *)my_info.iface_addr);
    CHECK_STATUS(status, "uct_iface_get_address");

    uct_md_mkey_pack_params_t pack_params;
    memset(&pack_params, 0, sizeof(pack_params));
    pack_params.field_mask = 0;
    status = uct_md_mkey_pack_v2(md, memh, buf, BUF_SIZE,
                                  &pack_params, my_info.rkey);
    CHECK_STATUS(status, "uct_md_mkey_pack_v2");

    /* ------------------------------------------------------------------
     * 6. Rendezvous — exchange peer_info in both directions.
     * ------------------------------------------------------------------ */
    int sock = rendezvous(job_id);

    peer_info_t peer;
    tcp_send_all(sock, &my_info, sizeof(my_info));
    tcp_recv_all(sock, &peer,    sizeof(peer));

    printf("rank %d: peer buf_va=0x%016lx dev_addr_len=%u rkey_len=%u\n",
           rank, (unsigned long)peer.buf_va,
           peer.dev_addr_len, peer.rkey_len);
    fflush(stdout);

    /* ------------------------------------------------------------------
     * 7. Rank 0: Phase A (PUT) then Phase B (GET), then signal rank 1.
     *
     * PUT flush guarantees rank 1's buffer holds FILL_BYTE before the GET
     * is posted, so no intermediate signaling is needed.
     * ------------------------------------------------------------------ */
    if (rank == 0) {
        uct_ep_params_t ep_params;
        memset(&ep_params, 0, sizeof(ep_params));
        ep_params.field_mask  = UCT_EP_PARAM_FIELD_IFACE     |
                                UCT_EP_PARAM_FIELD_DEV_ADDR  |
                                UCT_EP_PARAM_FIELD_IFACE_ADDR;
        ep_params.iface       = iface;
        ep_params.dev_addr    = (const uct_device_addr_t *)peer.dev_addr;
        ep_params.iface_addr  = (const uct_iface_addr_t  *)peer.iface_addr;

        uct_ep_h ep;
        status = uct_ep_create(&ep_params, &ep);
        CHECK_STATUS(status, "uct_ep_create");

        uct_rkey_bundle_t rkey_bundle;
        status = uct_rkey_unpack(cxi_comp, peer.rkey, &rkey_bundle);
        CHECK_STATUS(status, "uct_rkey_unpack");

        uct_iov_t iov;
        iov.stride = 0;
        iov.count  = 1;
        iov.length = BUF_SIZE;
        iov.memh   = memh;

        /* ---- Phase A: PUT buf (0xAB) → rank 1's buf ---- */
        iov.buffer = buf;
        status = uct_ep_put_zcopy(ep, &iov, 1,
                                   peer.buf_va, rkey_bundle.rkey, NULL);
        if (status != UCS_INPROGRESS)
            DIE("[PUT] ep_put_zcopy: %s", ucs_status_string(status));

        printf("rank 0: [PUT] posted %zu bytes, flushing...\n",
               (size_t)BUF_SIZE);
        fflush(stdout);

        flush_ep(iface, ep, "PUT");
        printf("rank 0: [PUT] ACK received\n");
        fflush(stdout);

        /* ---- Phase B: GET rank 1's buf (0xAB) → local buf ---- */
        memset(buf, 0x00, BUF_SIZE);
        iov.buffer = buf;

        status = uct_ep_get_zcopy(ep, &iov, 1,
                                   peer.buf_va, rkey_bundle.rkey, NULL);
        if (status != UCS_INPROGRESS)
            DIE("[GET] ep_get_zcopy: %s", ucs_status_string(status));

        printf("rank 0: [GET] posted %zu bytes, flushing...\n",
               (size_t)BUF_SIZE);
        fflush(stdout);

        flush_ep(iface, ep, "GET");

        /* Verify GET result. */
        size_t first_bad = SIZE_MAX;
        for (size_t i = 0; i < BUF_SIZE; i++) {
            if (buf[i] != (uint8_t)FILL_BYTE) { first_bad = i; break; }
        }
        if (first_bad == SIZE_MAX)
            printf("rank 0: [GET] PASS — %zu bytes verified (all 0x%02x)\n",
                   (size_t)BUF_SIZE, (unsigned)FILL_BYTE);
        else
            printf("rank 0: [GET] FAIL — byte %zu: got 0x%02x expected 0x%02x\n",
                   first_bad, buf[first_bad], (unsigned)FILL_BYTE);
        fflush(stdout);

        /* Signal rank 1 that both phases are done; it can verify and exit. */
        uint8_t done = 1;
        tcp_send_all(sock, &done, sizeof(done));

        uct_rkey_release(cxi_comp, &rkey_bundle);
        uct_ep_destroy(ep);
    }

    /* ------------------------------------------------------------------
     * 8. Rank 1: wait for done signal, verify PUT result.
     * ------------------------------------------------------------------ */
    if (rank == 1) {
        uint8_t done = 0;
        tcp_recv_all(sock, &done, sizeof(done));

        size_t first_bad = SIZE_MAX;
        for (size_t i = 0; i < BUF_SIZE; i++) {
            if (buf[i] != (uint8_t)FILL_BYTE) { first_bad = i; break; }
        }
        if (first_bad == SIZE_MAX)
            printf("rank 1: [PUT] PASS — %zu bytes verified (all 0x%02x)\n",
                   (size_t)BUF_SIZE, (unsigned)FILL_BYTE);
        else
            printf("rank 1: [PUT] FAIL — byte %zu: got 0x%02x expected 0x%02x\n",
                   first_bad, buf[first_bad], (unsigned)FILL_BYTE);
        fflush(stdout);
    }

    /* ------------------------------------------------------------------
     * 9. Cleanup
     * ------------------------------------------------------------------ */
    close(sock);

    uct_md_mem_dereg_params_t dereg_params;
    memset(&dereg_params, 0, sizeof(dereg_params));
    dereg_params.field_mask = UCT_MD_MEM_DEREG_FIELD_MEMH;
    dereg_params.memh       = memh;
    uct_md_mem_dereg_v2(md, &dereg_params);

    uct_iface_close(iface);
    uct_worker_destroy(worker);
    ucs_async_context_destroy(async);
    uct_md_close(md);

    printf("rank %d: done\n", rank);
    return 0;
}
