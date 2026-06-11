/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
# include <libgen.h>
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/getopt.h"
# include "perflib/basename.h"
#endif /* _WIN32 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "perflib/perflib.h"

/*
 * This test simulates a server handling many short-lived TLS connections,
 * such as a webserver handling HTTP/1.1 "Connection: close" requests. For
 * each simulated connection a brand new SSL object pair is created, a full
 * TLS handshake is performed, a single small "request" and "response" are
 * exchanged, and the connection is then shut down and freed. This exercises
 * the per-connection setup/teardown costs of the record layer (as opposed to
 * "handshake" which does not exchange any application data, and "writeread"
 * which only measures steady state read/write performance on a single
 * long-lived connection).
 *
 * In addition to the overall per-connection time, the time spent in the
 * SSL object that plays the *server* role (SSL_new, SSL_accept, SSL_read,
 * SSL_write, SSL_shutdown and SSL_free) is tracked separately. A real
 * webserver such as nginx only ever acts as the TLS server, so this
 * "server-side" figure is the one most comparable to the throughput of a
 * webserver handling many short-lived connections from a client whose own
 * TLS stack is unaffected (e.g. a load generator built against a different
 * OpenSSL version).
 */

#define RUN_TIME 5
#define MAXLOOPS 1000000

int err = 0;

static SSL_CTX *sctx = NULL, *cctx = NULL;
static int share_ctx = 1;
static char *cert = NULL;
static char *privkey = NULL;

static int threadcount;
static int req_size = 256;
static int resp_size = 1024;
static char *server_groups = NULL;
static char *client_groups = NULL;
static int max_version = 0;

size_t *counts;
OSSL_TIME *server_time;
OSSL_TIME max_time;

static void do_shortconn(size_t num)
{
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CTX *lsctx = NULL, *lcctx = NULL;
    int ret = 1;
    OSSL_TIME time, t0, t1;
    char *reqbuf, *respbuf;

    reqbuf = OPENSSL_malloc(req_size);
    respbuf = OPENSSL_malloc(resp_size);
    if (reqbuf == NULL || respbuf == NULL) {
        fprintf(stderr, "Failed to allocate request/response buffers\n");
        err = 1;
        OPENSSL_free(reqbuf);
        OPENSSL_free(respbuf);
        return;
    }
    memset(reqbuf, 0xab, req_size);
    memset(respbuf, 0xcd, resp_size);

    if (share_ctx == 1) {
        lsctx = sctx;
        lcctx = cctx;
    }

    counts[num] = 0;
    server_time[num] = ossl_time_zero();

    do {
        BIO *s_to_c_bio = NULL, *c_to_s_bio = NULL;
        int written, readbytes, i;
        int retc = -1, rets = -1, sslerr, abortctr = 0;
        int clienterr = 0, servererr = 0;
        unsigned char dummy;

        if (share_ctx == 0) {
            if (!perflib_create_ssl_ctx_pair(TLS_server_method(),
                                             TLS_client_method(),
                                             0, 0, &lsctx, &lcctx, cert,
                                             privkey)) {
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
                ret = 0;
                break;
            }
            if ((server_groups != NULL && !SSL_CTX_set1_groups_list(lsctx, server_groups))
                    || (client_groups != NULL && !SSL_CTX_set1_groups_list(lcctx, client_groups))) {
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "%s:%d: Failed to set groups list\n", __FILE__, __LINE__);
                ret = 0;
                break;
            }
            if (max_version != 0
                    && (!SSL_CTX_set_max_proto_version(lsctx, max_version)
                        || !SSL_CTX_set_max_proto_version(lcctx, max_version))) {
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "%s:%d: Failed to set max proto version\n", __FILE__, __LINE__);
                ret = 0;
                break;
            }
        }

        clientssl = SSL_new(lcctx);

        t0 = ossl_time_now();
        serverssl = SSL_new(lsctx);
        t1 = ossl_time_now();
        server_time[num] = ossl_time_add(server_time[num], ossl_time_subtract(t1, t0));

        ret = (clientssl != NULL && serverssl != NULL);

        if (ret) {
            s_to_c_bio = BIO_new(BIO_s_mem());
            c_to_s_bio = BIO_new(BIO_s_mem());
            ret = (s_to_c_bio != NULL && c_to_s_bio != NULL);
        }
        if (ret) {
            /* Set Non-blocking IO behaviour */
            BIO_set_mem_eof_return(s_to_c_bio, -1);
            BIO_set_mem_eof_return(c_to_s_bio, -1);

            /* Up ref these as we are passing them to two SSL objects */
            SSL_set_bio(serverssl, c_to_s_bio, s_to_c_bio);
            BIO_up_ref(s_to_c_bio);
            BIO_up_ref(c_to_s_bio);
            SSL_set_bio(clientssl, s_to_c_bio, c_to_s_bio);
        } else {
            BIO_free(s_to_c_bio);
            BIO_free(c_to_s_bio);
        }

        /* Perform the handshake, timing only the server (SSL_accept) side */
        while (ret && (retc <= 0 || rets <= 0)) {
            sslerr = SSL_ERROR_WANT_WRITE;
            while (!clienterr && retc <= 0 && sslerr == SSL_ERROR_WANT_WRITE) {
                retc = SSL_connect(clientssl);
                if (retc <= 0)
                    sslerr = SSL_get_error(clientssl, retc);
            }
            if (!clienterr && retc <= 0 && sslerr != SSL_ERROR_WANT_READ)
                clienterr = 1;

            sslerr = SSL_ERROR_WANT_WRITE;
            while (!servererr && rets <= 0 && sslerr == SSL_ERROR_WANT_WRITE) {
                t0 = ossl_time_now();
                rets = SSL_accept(serverssl);
                t1 = ossl_time_now();
                server_time[num] = ossl_time_add(server_time[num],
                                                  ossl_time_subtract(t1, t0));
                if (rets <= 0)
                    sslerr = SSL_get_error(serverssl, rets);
            }
            if (!servererr && rets <= 0
                    && sslerr != SSL_ERROR_WANT_READ
                    && sslerr != SSL_ERROR_WANT_X509_LOOKUP)
                servererr = 1;

            if (clienterr || servererr || ++abortctr == MAXLOOPS) {
                ret = 0;
                break;
            }
        }

        /*
         * Drain any TLSv1.3 NewSessionTicket messages on the client side, to
         * mirror what perflib_create_ssl_connection() does.
         */
        for (i = 0; ret && i < 2; i++) {
            readbytes = SSL_read(clientssl, &dummy, sizeof(dummy));
            if (readbytes >= 0) {
                if (readbytes != 0)
                    ret = 0;
            } else if (SSL_get_error(clientssl, 0) != SSL_ERROR_WANT_READ) {
                ret = 0;
            }
        }

        /* Client sends a "request" which the server reads */
        if (ret) {
            written = SSL_write(clientssl, reqbuf, req_size);
            ret = (written == req_size);
        }
        if (ret) {
            t0 = ossl_time_now();
            readbytes = SSL_read(serverssl, reqbuf, req_size);
            t1 = ossl_time_now();
            server_time[num] = ossl_time_add(server_time[num],
                                              ossl_time_subtract(t1, t0));
            ret = (readbytes == req_size);
        }

        /* Server sends a "response" which the client reads */
        if (ret) {
            t0 = ossl_time_now();
            written = SSL_write(serverssl, respbuf, resp_size);
            t1 = ossl_time_now();
            server_time[num] = ossl_time_add(server_time[num],
                                              ossl_time_subtract(t1, t0));
            ret = (written == resp_size);
        }
        if (ret) {
            readbytes = SSL_read(clientssl, respbuf, resp_size);
            ret = (readbytes == resp_size);
        }

        /* Shut down the connection: client first (untimed), then server */
        SSL_shutdown(clientssl);
        t0 = ossl_time_now();
        SSL_shutdown(serverssl);
        t1 = ossl_time_now();
        server_time[num] = ossl_time_add(server_time[num], ossl_time_subtract(t1, t0));

        SSL_free(clientssl);
        t0 = ossl_time_now();
        SSL_free(serverssl);
        t1 = ossl_time_now();
        server_time[num] = ossl_time_add(server_time[num], ossl_time_subtract(t1, t0));

        serverssl = clientssl = NULL;

        if (share_ctx == 0) {
            SSL_CTX_free(lsctx);
            SSL_CTX_free(lcctx);
            lsctx = lcctx = NULL;
        }

        if (!ret)
            break;

        counts[num]++;
        time = ossl_time_now();
    } while (time.t < max_time.t);

    if (!ret)
        err = 1;

    OPENSSL_free(reqbuf);
    OPENSSL_free(respbuf);
}

void usage(const char *progname)
{
    printf("Usage: %s [options] certsdir threadcount\n", progname);
    printf("-t - terse output\n");
    printf("-s - disable context sharing (create a new SSL_CTX pair per connection)\n");
    printf("-q size - size in bytes of the simulated request (Default: 256)\n");
    printf("-b size - size in bytes of the simulated response (Default: 1024)\n");
    printf("-g groups - colon separated list of groups for the server SSL_CTX\n");
    printf("-G groups - colon separated list of groups for the client SSL_CTX\n");
    printf("-2 - restrict negotiation to a maximum of TLSv1.2\n");
    printf("-V - print version information and exit\n");
}

int main(int argc, char * const argv[])
{
    double persec;
    OSSL_TIME duration, total_server_time;
    size_t total_count = 0;
    double avcalltime, avservertime;
    int ret = EXIT_FAILURE;
    int i;
    int terse = 0;
    int opt;

    while ((opt = getopt(argc, argv, "tsq:b:g:G:2V")) != -1) {
        switch (opt) {
        case 't':
            terse = 1;
            break;
        case 's':
            share_ctx = 0;
            break;
        case 'q':
            req_size = atoi(optarg);
            if (req_size < 1) {
                fprintf(stderr, "Request size must be > 0\n");
                return EXIT_FAILURE;
            }
            break;
        case 'b':
            resp_size = atoi(optarg);
            if (resp_size < 1) {
                fprintf(stderr, "Response size must be > 0\n");
                return EXIT_FAILURE;
            }
            break;
        case 'g':
            server_groups = optarg;
            break;
        case 'G':
            client_groups = optarg;
            break;
        case '2':
            max_version = TLS1_2_VERSION;
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            usage(basename(argv[0]));
            return EXIT_FAILURE;
        }
    }

    if (argv[optind] == NULL) {
        printf("certsdir is missing\n");
        goto err;
    }
    cert = perflib_mk_file_path(argv[optind], "servercert.pem");
    privkey = perflib_mk_file_path(argv[optind], "serverkey.pem");
    if (cert == NULL || privkey == NULL) {
        printf("Failed to allocate cert/privkey\n");
        goto err;
    }
    optind++;

    if (argv[optind] == NULL) {
        printf("threadcount argument missing\n");
        goto err;
    }
    threadcount = atoi(argv[optind]);
    if (threadcount < 1) {
        printf("threadcount must be > 0\n");
        goto err;
    }

    counts = OPENSSL_malloc(sizeof(size_t) * threadcount);
    server_time = OPENSSL_malloc(sizeof(OSSL_TIME) * threadcount);
    if (counts == NULL || server_time == NULL) {
        printf("Failed to create counts arrays\n");
        goto err;
    }

    max_time = ossl_time_add(ossl_time_now(), ossl_seconds2time(RUN_TIME));

    if (share_ctx == 1) {
        if (!perflib_create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                                         0, 0, &sctx, &cctx, cert, privkey)) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "%s:%d: Failed to create SSL_CTX pair\n", __FILE__, __LINE__);
            goto err;
        }
        if ((server_groups != NULL && !SSL_CTX_set1_groups_list(sctx, server_groups))
                || (client_groups != NULL && !SSL_CTX_set1_groups_list(cctx, client_groups))) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "%s:%d: Failed to set groups list\n", __FILE__, __LINE__);
            goto err;
        }
        if (max_version != 0
                && (!SSL_CTX_set_max_proto_version(sctx, max_version)
                    || !SSL_CTX_set_max_proto_version(cctx, max_version))) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "%s:%d: Failed to set max proto version\n", __FILE__, __LINE__);
            goto err;
        }
    }

    if (!perflib_run_multi_thread_test(do_shortconn, threadcount, &duration)) {
        printf("Failed to run the test\n");
        goto err;
    }

    if (err) {
        printf("Error during test\n");
        goto err;
    }

    total_server_time = ossl_time_zero();
    for (i = 0; i < threadcount; i++) {
        total_count += counts[i];
        total_server_time = ossl_time_add(total_server_time, server_time[i]);
    }

    avcalltime = (double)RUN_TIME * 1e6 * threadcount / total_count;
    persec = (double)total_count / RUN_TIME;
    avservertime = (double)ossl_time2us(total_server_time) / total_count;

    if (terse) {
        printf("%lf %lf\n", avcalltime, avservertime);
    } else {
        printf("Average time per connection: %lfus\n", avcalltime);
        printf("Connections per second: %lf\n", persec);
        printf("Average server-side time per connection: %lfus\n", avservertime);
    }

    ret = EXIT_SUCCESS;
 err:
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(counts);
    OPENSSL_free(server_time);
    if (share_ctx == 1) {
        SSL_CTX_free(sctx);
        SSL_CTX_free(cctx);
    }
    return ret;
}
