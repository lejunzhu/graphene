#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <time.h>
#include <ctype.h>

#define SGX_REPORT_DATA_SIZE    64
#define SGX_QUOTE_MAX_SIZE      8192

/*
 * To load libsgx_dcap_quoteverify.so, it needs some symbols which are normally
 * provided by libsgx_urts.so (or libsgx_urts_sim.so). To use it in Graphene,
 * there are two workarounds to solve this: 1) load libsgx_urts.so or 2) create
 * dummy functions and always return failure. In this example we use 2).
 */

#define DUMMY_FUNCTION(f)       int f() {return /*SGX_ERROR_UNEXPECTED*/1;}

/* Provide these dummies since we are not using libsgx_urts.so. */
DUMMY_FUNCTION(sgx_create_enclave)
DUMMY_FUNCTION(sgx_destroy_enclave)
DUMMY_FUNCTION(sgx_ecall)
/* ocalls in sgx_tstdc.edl */
DUMMY_FUNCTION(sgx_oc_cpuidex)
DUMMY_FUNCTION(sgx_thread_set_untrusted_event_ocall)
DUMMY_FUNCTION(sgx_thread_setwait_untrusted_events_ocall)
DUMMY_FUNCTION(sgx_thread_set_multiple_untrusted_events_ocall)
DUMMY_FUNCTION(sgx_thread_wait_untrusted_event_ocall)

enum { SUCCESS = 0, FAILURE = -1 };

static ssize_t rw_file(const char* path, char* buf, size_t bytes, bool do_write) {
    size_t rv = 0;
    size_t ret = 0;

    FILE* f = fopen(path, do_write ? "wb" : "rb");
    if (!f) {
        fprintf(stderr, "opening %s failed\n", path);
        return -1;
    }

    while (bytes > rv) {
        if (do_write)
            ret = fwrite(buf + rv, /*size=*/1, /*nmemb=*/bytes - rv, f);
        else
            ret = fread(buf + rv, /*size=*/1, /*nmemb=*/bytes - rv, f);

        if (ret > 0) {
            rv += ret;
        } else {
            if (feof(f)) {
                if (rv) {
                    /* read some bytes from file, success */
                    break;
                }
                assert(rv == 0);
                fprintf(stderr, "%s failed: unexpected end of file\n", do_write ? "write" : "read");
                fclose(f);
                return -1;
            }

            assert(ferror(f));

            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }

            fprintf(stderr, "%s failed: %s\n", do_write ? "write" : "read", strerror(errno));
            fclose(f);
            return -1;
        }
    }

    int close_ret = fclose(f);
    if (close_ret) {
        fprintf(stderr, "closing %s failed\n", path);
        return -1;
    }
    return rv;
}

static int generate_quote(uint8_t *buf, ssize_t *sz)
{
    const char *user_data_str = "This is a sample string";
    uint8_t user_data[SGX_REPORT_DATA_SIZE];
    ssize_t bytes;

    /* Set user data */
    memset(user_data, 0, sizeof(user_data));
    strncpy((char *)user_data, user_data_str, sizeof(user_data));
    bytes = rw_file("/dev/attestation/user_report_data", (char*)user_data,
                    sizeof(user_data), /*do_write=*/true);
    if (bytes != sizeof(user_data)) {
        return FAILURE;
    }

    /* read`quote */
    bytes = rw_file("/dev/attestation/quote", (char*)buf, *sz,
                    /*do_write=*/false);
    if (bytes < 0) {
        return FAILURE;
    }

    if (*(uint16_t*)&buf[/*version*/0] != /*DCAP*/3) {
        fprintf(stderr, "The quote type is not DCAP.\n");
        return FAILURE;
    }

    *sz = bytes;
    return SUCCESS;
}

typedef int (*get_quote_supplemental_data_size_t)(uint32_t *p_data_size);
typedef int (*verify_quote_t)(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const void *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    uint32_t *p_quote_verification_result,
    void *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data);

static get_quote_supplemental_data_size_t get_quote_supplemental_data_size_f;
static verify_quote_t verify_quote_f;

static int load_dcap_libs()
{
    void *qvl = NULL;

    qvl = dlopen("libsgx_dcap_quoteverify.so", RTLD_LAZY);
    if (!qvl) {
        fprintf(stderr, "Cannot load libsgx_dcap_quoteverify.so: %s\n", dlerror());
        return FAILURE;
    }

    get_quote_supplemental_data_size_f = (get_quote_supplemental_data_size_t)
        dlsym(qvl, "sgx_qv_get_quote_supplemental_data_size");
    verify_quote_f = (verify_quote_t)dlsym(qvl, "sgx_qv_verify_quote");
    if (!get_quote_supplemental_data_size_f || !verify_quote_f) {
        fprintf(stderr, "Cannot find symbols.\n");
        return FAILURE;
    }

    return SUCCESS;
}

static int verify_quote(uint8_t *quote, ssize_t bytes)
{
    int ret = 0;
    uint32_t supplemental_data_size = 0;
    uint32_t collateral_expiration_status = 1;
    uint32_t quote_verification_result = /*SGX_QL_QV_RESULT_UNSPECIFIED*/0xa006;
    uint8_t *p_supplemental_data = NULL;
    time_t current_time;

    if (!get_quote_supplemental_data_size_f || !verify_quote_f) {
        fprintf(stderr, "Need to load libsgx_dcap_quoteverify.so first.\n");
        return FAILURE;
    }

    ret = get_quote_supplemental_data_size_f(&supplemental_data_size);
    if (ret != 0) {
        fprintf(stderr, "sgx_qv_get_quote_supplemental_data_size returns %u.\n", ret);
        return FAILURE;
    }

    current_time = time(NULL);

    if (supplemental_data_size > 0) {
        p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    }

    ret = verify_quote_f(quote, bytes, NULL, current_time,
        &collateral_expiration_status, &quote_verification_result,
        NULL, supplemental_data_size, p_supplemental_data);

    if (p_supplemental_data) {
        free(p_supplemental_data);
    }

    if (ret != 0) {
        fprintf(stderr, "sgx_qv_verify_quote returns %u.\n", ret);
        return FAILURE;
    }

    if (quote_verification_result != 0) {
        fprintf(stderr, "quote_verification_result is 0x%x.\n", quote_verification_result);
        return FAILURE;
    }

    return SUCCESS;
}

int main()
{
    uint8_t quote[SGX_QUOTE_MAX_SIZE];
    ssize_t sz = sizeof(quote);

    if (getenv("LC_ALL") == NULL) {
        printf("LC_ALL must be set, for verification to work.\n");
        return 1;
    }

    if (load_dcap_libs() != SUCCESS) {
        printf("Cannot load dynamic libraries.\n");
        return 1;
    }

    printf("Generating quote...");
    if (generate_quote(quote, &sz) != SUCCESS) {
        printf("failed\n");
        return 1;
    }
    printf("success\n");
    fflush(stdout);

    printf("Verifying quote...");
    if (verify_quote(quote, sz) != SUCCESS) {
        printf("failed\n");
        return 1;
    }
    printf("success\n");
    fflush(stdout);

    printf("Verifying invalid quote (expect error code 0xa004)...\n");
    fflush(stdout);
    quote[/*cpusvn*/48]++;
    if (verify_quote(quote, sz) == SUCCESS) {
        printf("Should not succeed.\n");
        return 1;
    }

    return 0;
}
