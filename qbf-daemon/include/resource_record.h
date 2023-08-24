#ifndef __RESOURCE_RECORD__

#define __RESOURCE_RECORD__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct ResourceRecord {
    char *name;
    uint16_t type;
    uint16_t clas;
    uint32_t ttl;
    uint16_t rdsize;
    unsigned char *rdata;
    unsigned char *name_bytes;
    size_t name_byte_len;
} ResourceRecord;


int
bytes_to_dnsname(unsigned char *in, char **name, size_t *name_len, size_t *bytes_processed, size_t in_len);

int
dnsname_to_bytes(char *name, size_t name_len, unsigned char **out, size_t *out_len);

int
destroy_rr(ResourceRecord **rr);

int
create_rr(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type,
          uint16_t clas, uint32_t ttl, uint16_t rdsize, unsigned char *rdata);

int
create_rr_f(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type,
            uint16_t clas, uint32_t ttl, uint16_t rdsize, unsigned char *rdata, int sig_start_idx, int sig_end_idx,
            int pk_start_idx, int pk_end_idx);

int
combine_rr(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type,
           uint16_t clas, uint32_t ttl, uint16_t rdsize1, unsigned char *rdata1, uint16_t rdsize2,
           unsigned char *rdata2);


int
bytes_to_rr(unsigned char *in, size_t in_len, size_t *bytes_processed, ResourceRecord **out);

int
rr_to_bytes(ResourceRecord *in, unsigned char **out, size_t *out_len);

int
clone_rr(ResourceRecord *in, ResourceRecord **out);

bool
rr_is_equal(ResourceRecord *lhs, ResourceRecord *rhs);

char *
rr_to_string(ResourceRecord *rr);

int calc_num_sig_bytes(uint16_t rdsize, unsigned char *rdata);

int get_alg_sig_pk_size(uint16_t type, unsigned char *rdata);

#endif // __RESOURCE_RECORD__
