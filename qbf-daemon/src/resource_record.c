#include <resource_record.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <assert.h>
#include <constants.h>

int
bytes_to_dnsname(unsigned char *in, char **name, size_t *name_len, size_t *bytes_processed, size_t in_len) {
    int i = 0;
    char *_name = NULL;
    size_t label_len = 0;
    char *tmp_name = NULL;
    size_t name_size = in_len + 1;
    tmp_name = malloc(name_size);
    if (tmp_name == NULL) {
        printf("Failed to malloc tmp_name\n");
        fflush(stdout);
        return -1;
    }
    while ((i < in_len) && in[i] != 0) {
        label_len = in[i];
        if (label_len + i > in_len) {
            free(tmp_name);
            // Is a pointer name, so fill our struct with a human readable name
            int j = 0;
            while (in[j] != 0) j++;
//            printf("\nPrinting 2B pointer...\n");
//            for (int i = 0; i < j; i++)
//                printf("%02x", in[i]);
//            printf("\nDone!");
            *name = malloc(strlen("POINTER NAME") + 1);
            strcpy(*name, "POINTER NAME");
            *bytes_processed = j;
            return 0;
        }
        for (size_t j = 0; j < label_len; j++) {
            tmp_name[i + j] = in[i + j + 1];
        }
        tmp_name[i + label_len] = '.';
        i += label_len + 1;
    }
    if (i > in_len) {
        printf("i > in_len\n");
        fflush(stdout);
        return -1;
    }
    if (i == 0) {
        tmp_name[i] = '.';
    } else if ((in_len - i) != 0) {
        _name = tmp_name;
        tmp_name = malloc((i * sizeof(char)) + 1);
        if (tmp_name == NULL) {
            printf("failed to reallocate tmp_name\n");
            fflush(stdout);
            return -1;
        }
        strncpy(tmp_name, _name, i);
        free(_name);
    }
    *name_len = i + 1;
    *bytes_processed = i + 1;
    if (i == 0) {
        i++;
    }
    tmp_name[i] = '\0';
    *name = tmp_name;
    return 0;
}


int
dnsname_to_bytes(char *name, size_t name_len, unsigned char **out, size_t *out_len) {
    size_t i = 0;
    size_t label_len = 0;
    unsigned char *tmp_out = NULL;
    tmp_out = malloc(name_len * sizeof(unsigned char) + 1);
    while (i < name_len) {
        size_t j = i;
        while (j < name_len) {
            if (name[j] == '.') {
                break;
            }
            j++;
        }
        label_len = j - i;
        if (label_len == 0) {
            goto exit;
        }
        tmp_out[i] = label_len;
        i++;
        for (size_t k = i; k < j + 1; k++) {
            tmp_out[k] = name[k - 1];
        }
        i += label_len;
    }
    exit:
    tmp_out[i] = 0;
    *out_len = ++i;
    *out = tmp_out;
    return 0;
}


int
destroy_rr(ResourceRecord **rr) {
    if (rr == NULL) {
        return 0;
    }
    ResourceRecord *_rr = *rr;
    if (_rr == NULL) {
        return 0;
    }
    if (_rr->name != NULL)
        free(_rr->name);
    if (_rr->name_bytes != NULL)
        free(_rr->name_bytes);
    if (_rr->rdata != NULL)
        free(_rr->rdata);
    free(_rr);
    *rr = NULL;
    return 0;
}

int
create_rr(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type,
          uint16_t clas, uint32_t ttl, uint16_t rdsize, unsigned char *rdata) {
    ResourceRecord *rr = malloc(sizeof(ResourceRecord));
    if (rr == NULL) {
        return -1;
    }
    size_t name_len = strlen(name);
    rr->name = malloc((sizeof(char) * name_len) + 1);
    if (rr->name == NULL) {
        printf("rrname malloc error\n");
        destroy_rr(&rr);
        return -1;
    }
    memcpy(rr->name, name, name_len + 1);
    rr->name_bytes = malloc(name_byte_len);
    memcpy(rr->name_bytes, name_bytes, name_byte_len);
    rr->name_byte_len = name_byte_len;
    rr->type = type;
    rr->clas = clas;
    rr->ttl = ttl;
    rr->rdsize = rdsize;
    rr->rdata = malloc(rr->rdsize);
    if (rr->rdata == NULL) {
        printf("rdata malloc error\n");
        destroy_rr(&rr);
        return -1;
    }
    memcpy(rr->rdata, rdata, rdsize);
    *out = rr;
    return 0;
}

int
create_rr_f(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type,
            uint16_t clas, uint32_t ttl, uint16_t rdsize, unsigned char *rdata, int sig_start_idx, int sig_end_idx,
            int pk_start_idx, int pk_end_idx) {
    ResourceRecord *rr = malloc(sizeof(ResourceRecord));
    if (rr == NULL) {
        return -1;
    }
    size_t name_len = strlen(name);
    rr->name = malloc((sizeof(char) * name_len) + 1);
    if (rr->name == NULL) {
        printf("rrname malloc error\n");
        destroy_rr(&rr);
        return -1;
    }
    memcpy(rr->name, name, name_len + 1);
    rr->name_bytes = malloc(name_byte_len);
    memcpy(rr->name_bytes, name_bytes, name_byte_len);
    rr->name_byte_len = name_byte_len;
    rr->type = type;
    rr->clas = clas;
    rr->ttl = ttl;

    if (rr->type == 46) {
//        const char SIG_ALG = rdata[2];;
        int SIG_SIZE = get_alg_sig_pk_size(rr->type, rdata);;
        if (!((0 <= sig_start_idx) && (sig_start_idx <= sig_end_idx) && (sig_end_idx < SIG_SIZE))) {
            rr->rdsize = 0;
            *out = rr;
            return 0;
        }
        printf("\nFragmenting rdata->signature...");

        /* The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
        1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
        TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
        Inception field, a 2 octet Key tag, the Signer's Name field, and the
        Signature field. */

        int i = 18;
        while (rdata[i] != 0) { //signer's name
            i++;
        }
        i++;
        int i_copy = i;


        unsigned char *sig = malloc(SIG_SIZE);

        // raw sig bytes
        int j = 0;
        while (i < rdsize) {
            sig[j] = rdata[i];
            i++;
            j++;
        }

        int sig_size_f = sig_end_idx - sig_start_idx + 1;
        unsigned char *sig_f = malloc(sig_size_f);

        j = 0;
        for (int i = sig_start_idx; i <= sig_end_idx; i++) {
            sig_f[j] = sig[i];
            j++;
        }

        rr->rdsize = rdsize - SIG_SIZE + sig_size_f;
        rr->rdata = malloc(rr->rdsize);

        if (rr->rdata == NULL) {
            printf("rdata malloc error\n");
            destroy_rr(&rr);
            return -1;
        }

        memcpy(rr->rdata, rdata, i_copy);
        memcpy((rr->rdata) + i_copy, sig_f, sig_size_f);
        *out = rr;
        return 0;

    } else if (rr->type == 48) {
//        const char PK_ALG = rdata[3];;
        int PK_SIZE = get_alg_sig_pk_size(rr->type, rdata);
        if (!((0 <= pk_start_idx) && (pk_start_idx <= pk_end_idx) && (pk_end_idx < PK_SIZE))) {
            rr->rdsize = 0;
            *out = rr;
            return 0;
        }

        printf("\nFragmenting its rdata->public key...");
        unsigned char *pk = malloc(PK_SIZE);

        /* The RDATA for a DNSKEY RR consists of a 2 octet Flags Field, a 1
        octet Protocol Field, a 1 octet Algorithm Field, and the Public Key
        Field. */

        // raw pk bytes
        int i = 4;
        int j = 0;
        while (i < rdsize) {
            pk[j] = rdata[i];
            i++;
            j++;
        }

        int pk_size_f = pk_end_idx - pk_start_idx + 1;
        unsigned char *pk_f = malloc(pk_size_f);

        j = 0;
        for (int i = pk_start_idx; i <= pk_end_idx; i++) {
            pk_f[j] = pk[i];
            j++;
        }

        rr->rdsize = rdsize - PK_SIZE + pk_size_f;
        rr->rdata = malloc(rr->rdsize);

        if (rr->rdata == NULL) {
            printf("rdata malloc error\n");
            destroy_rr(&rr);
            return -1;
        }

        memcpy(rr->rdata, rdata, 4);
        memcpy((rr->rdata) + 4, pk_f, pk_size_f);
        *out = rr;
        return 0;
    }
    return -1;
}

int calc_num_sig_bytes(uint16_t rdsize, unsigned char *rdata) {
    /* The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
    1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
    TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
    Inception field, a 2 octet Key tag, the Signer's Name field, and the
    Signature field. */

    int i = 18;
    while (rdata[i] != 0) { //signer's name
        i++;
    }
    i++;

    return rdsize - i;
}

int get_alg_sig_pk_size(uint16_t type, unsigned char *rdata) {
    if (type == 46) {
        const char SIG_ALG = rdata[2];;
        int SIG_SIZE = 0;

        if (SIG_ALG == FALCON_512_ALG) {
            printf("\nFALCON 512 RRSIG RR Found.");
            SIG_SIZE = FALCON_512_SIG_SIZE;
        } else if (SIG_ALG == DILITHIUM_ALG) {
            printf("\nDILITHIUM RRSIG RR Found.");
            SIG_SIZE = DILITHIUM_SIG_SIZE;
        } else if (SIG_ALG == SPHINCS_PLUS_SHA256_128S_ALG) {
            printf("\nSPHINCS_PLUS_SHA256_128S RRSIG RR Found.");
            SIG_SIZE = SPHINCS_PLUS_SHA256_128S_SIG_SIZE;
        }
        return SIG_SIZE;
    } else if (type == 48) {
        const char PK_ALG = rdata[3];;
        int PK_SIZE = 0;

        if (PK_ALG == FALCON_512_ALG) {
            printf("\nFALCON 512 DNSKEY RR Found.");
            PK_SIZE = FALCON_512_PK_SIZE;
        } else if (PK_ALG == DILITHIUM_ALG) {
            printf("\nDILITHIUM DNSKEY RR Found.");
            PK_SIZE = DILITHIUM_PK_SIZE;
        } else if (PK_ALG == SPHINCS_PLUS_SHA256_128S_ALG) {
            printf("\nSPHINCS_PLUS_SHA256_128S DNSKEY RR Found.");
            PK_SIZE = SPHINCS_PLUS_SHA256_128S_PK_SIZE;
        }
        return PK_SIZE;
    }
    return -1;
}


int
combine_rr(ResourceRecord **out, char *name, unsigned char *name_bytes, size_t name_byte_len, uint16_t type,
           uint16_t clas, uint32_t ttl, uint16_t rdsize1, unsigned char *rdata1, uint16_t rdsize2,
           unsigned char *rdata2) {
    ResourceRecord *rr = malloc(sizeof(ResourceRecord));
    if (rr == NULL) {
        return -1;
    }
    size_t name_len = strlen(name);
    rr->name = malloc((sizeof(char) * name_len) + 1);
    if (rr->name == NULL) {
        printf("rrname malloc error\n");
        destroy_rr(&rr);
        return -1;
    }
    memcpy(rr->name, name, name_len + 1);
    rr->name_bytes = malloc(name_byte_len);
    memcpy(rr->name_bytes, name_bytes, name_byte_len);
    rr->name_byte_len = name_byte_len;
    rr->type = type;
    rr->clas = clas;
    rr->ttl = ttl;

    if (rr->type == 46) {

        /* The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
        1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
        TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
        Inception field, a 2 octet Key tag, the Signer's Name field, and the
        Signature field. */

        int i = 18;
        while (rdata1[i] != 0) { //signer's name
            i++;
        }
        i++;

        // first check if we're combining correct fragments
        for (int j = 0; j < i; j++) {
            if (rdata1[j] != rdata2[j])
                return 1;
        }

        printf("\nMatching RRSIG fragment found. Combining fragments...");

        int i_copy = i;

        int num_sig_bytes_in_rr1 = rdsize1 - i;
        int num_sig_bytes_in_rr2 = rdsize2 - i;

        unsigned char *sig = malloc(num_sig_bytes_in_rr1 + num_sig_bytes_in_rr2);

        // combine signature

        int j = 0;
        while (i < rdsize1) {
            sig[j] = rdata1[i];
            i++;
            j++;
        }
        i = i_copy;
        while (i < rdsize2) {
            sig[j] = rdata2[i];
            i++;
            j++;
        }

        rr->rdsize = i_copy + num_sig_bytes_in_rr1 + num_sig_bytes_in_rr2;
        rr->rdata = malloc(rr->rdsize);
        if (rr->rdata == NULL) {
            printf("rdata malloc error\n");
            destroy_rr(&rr);
            return -1;
        }
        memcpy(rr->rdata, rdata1, i_copy);
        memcpy((rr->rdata) + i_copy, sig, num_sig_bytes_in_rr1 + num_sig_bytes_in_rr2);
        *out = rr;
        return 0;
    } else if (rr->type == 48) {

        /* The RDATA for a DNSKEY RR consists of a 2 octet Flags Field, a 1
        octet Protocol Field, a 1 octet Algorithm Field, and the Public Key
        Field. */

        int i = 4;

        // first check if we're combining correct fragments
        for (int j = 0; j < i; j++) {
            if (rdata1[j] != rdata2[j])
                return 1;
        }

        printf("\nMatching DNSKEY fragment found. Combining fragments...");
        int num_pk_bytes_in_rr1 = rdsize1 - i;
        int num_pk_bytes_in_rr2 = rdsize2 - i;

        unsigned char *pk = malloc(num_pk_bytes_in_rr1 + num_pk_bytes_in_rr2);

        // combine pk
        int j = 0;
        while (i < rdsize1) {
            pk[j] = rdata1[i];
            i++;
            j++;
        }
        i = 4;
        while (i < rdsize2) {
            pk[j] = rdata2[i];
            i++;
            j++;
        }

        rr->rdsize = 4 + num_pk_bytes_in_rr1 + num_pk_bytes_in_rr2;
        rr->rdata = malloc(rr->rdsize);
        if (rr->rdata == NULL) {
            printf("rdata malloc error\n");
            destroy_rr(&rr);
            return -1;
        }
        memcpy(rr->rdata, rdata1, 4);
        memcpy((rr->rdata) + 4, pk, num_pk_bytes_in_rr1 + num_pk_bytes_in_rr2);
        *out = rr;
        return 0;
    }
    return -1;
}


int
bytes_to_rr(unsigned char *in, size_t in_len, size_t *bytes_processed, ResourceRecord **out) {
    int rc = 0;
    ResourceRecord *rr = malloc(sizeof(ResourceRecord));
    char *name;
    size_t name_len = 0;
    unsigned char *cur_pos = in;
    // get name
    // find the length of the byte field
    size_t name_byte_len = 0;
    while (in[name_byte_len] != 0) {
        name_byte_len++;
    }
    name_byte_len += 1;
    rc = bytes_to_dnsname(cur_pos, &name, &name_len, bytes_processed, name_byte_len);
    if (rc != 0) {
        printf("Failed to make bytename\n");
        fflush(stdout);
        goto end;
    }
    rr->name = name;

    if (*bytes_processed != 0) {
        rr->name_bytes = malloc(*bytes_processed);
        memcpy(rr->name_bytes, in, *bytes_processed);
    } else {
        assert("Should never happen\n");
    }
    rr->name_byte_len = *bytes_processed;
    cur_pos = cur_pos + *bytes_processed;
    in_len = in_len - *bytes_processed;
    // get type
    rr->type = *(uint16_t *) cur_pos;
    rr->type = ntohs(rr->type);

    cur_pos = cur_pos + 2;
    in_len = in_len - 2;
    *bytes_processed += 2;
    // get class
    rr->clas = *(uint16_t *) cur_pos;
    rr->clas = ntohs(rr->clas);
    cur_pos = cur_pos + 2;
    in_len = in_len - 2;
    *bytes_processed += 2;
    // get ttl
    rr->ttl = *(uint32_t *) cur_pos;
    rr->ttl = ntohl(rr->ttl);
    cur_pos = cur_pos + 4;
    in_len = in_len - 4;
    *bytes_processed += 4;

    // get rdsize
    rr->rdsize = *(uint16_t *) cur_pos;
    rr->rdsize = ntohs(rr->rdsize);
    cur_pos = cur_pos + 2;
    in_len = in_len - 2;
    *bytes_processed += 2;

    if (rr->rdsize > in_len) {
        printf("rr->rdsize: %hu, in_len: %lu flipped rdsize:%hu\n", rr->rdsize, in_len, ntohs(rr->rdsize));
        printf("ERROR: rdsize larger than supplied bytes\n");
        rc = -1;
        goto end;
    }

    // get rdata
    rr->rdata = malloc(sizeof(unsigned char) * rr->rdsize);
    memcpy(rr->rdata, cur_pos, rr->rdsize);
    *bytes_processed += rr->rdsize;
    *out = rr;
    end:
    return rc;
}

int
rr_to_bytes(ResourceRecord *in, unsigned char **out, size_t *out_len) {
    int rc = 0;
    unsigned char *bytes = NULL;
    unsigned char *cur_pos = NULL;
    unsigned char *name = NULL;
    uint16_t type = 0;
    uint16_t clas = 0;
    uint32_t ttl = 0;
    uint16_t rdsize = 0;
    bytes = malloc(in->name_byte_len + 2 + 2 + 4 + 2 + in->rdsize);
    if (bytes == NULL) {
        rc = -1;
        goto end;
    }
    cur_pos = bytes;
    memcpy(cur_pos, in->name_bytes, in->name_byte_len);
    cur_pos = cur_pos + in->name_byte_len;

    type = htons(in->type);
    memcpy(cur_pos, &type, 2);
    cur_pos = cur_pos + 2;

    clas = htons(in->clas);
    memcpy(cur_pos, &clas, 2);
    cur_pos = cur_pos + 2;

    ttl = htonl(in->ttl);
    memcpy(cur_pos, &ttl, 4);
    cur_pos = cur_pos + 4;

    rdsize = htons(in->rdsize);
    memcpy(cur_pos, &rdsize, 2);
    cur_pos = cur_pos + 2;
    if (in->rdsize != 0) {
        memcpy(cur_pos, in->rdata, in->rdsize);
        *out_len = in->name_byte_len + 2 + 2 + 4 + 2 + in->rdsize;
    } else {
        *out_len = in->name_byte_len + 2 + 2 + 4 + 2;
    }
    *out = bytes;
    free(name);
    end:
    return rc;

}


int
clone_rr(ResourceRecord *in, ResourceRecord **out) {
    int rc = 0;
    ResourceRecord *res = malloc(sizeof(ResourceRecord));
    if (res == NULL) {
        printf("Failed to malloc for res in clone rr\n");
        fflush(stdout);
        exit(-1);
    }
    res->name = malloc((sizeof(char) * strlen(in->name)) + 1);
    if (res->name == NULL) {
        printf("Failed to malloc for res->name in clone rr\n");
        exit(-1);
    }
    strcpy(res->name, in->name);
    res->name_bytes = malloc(in->name_byte_len);
    memcpy(res->name_bytes, in->name_bytes, in->name_byte_len);
    res->name_byte_len = in->name_byte_len;
    res->type = in->type;
    res->clas = in->clas;
    res->ttl = in->ttl;
    res->rdsize = in->rdsize;
    res->rdata = malloc(sizeof(unsigned char) * res->rdsize);
    memcpy(res->rdata, in->rdata, res->rdsize);
    *out = res;
    return rc;
}

bool
rr_is_equal(ResourceRecord *lhs, ResourceRecord *rhs) {
    bool nameCheck = true;
    // if the name_bytes are the same, we're happy
    if (lhs->name_byte_len != rhs->name_byte_len) return false;
    for (int i = 0; i < lhs->name_byte_len; i++) {
        nameCheck = nameCheck && (lhs->name_bytes[i] == rhs->name_bytes[i]);
    }
    bool typeCheck = (lhs->type == rhs->type);
    bool classCheck = (lhs->clas == rhs->clas);
    bool ttlCheck = (lhs->ttl == rhs->ttl);
    bool rdsizeCheck = (lhs->rdsize == rhs->rdsize);
    if (!rdsizeCheck) return false;
    bool rdataCheck = (memcmp(lhs->rdata, rhs->rdata, lhs->rdsize) == 0);
    return (nameCheck && typeCheck && classCheck && ttlCheck && rdsizeCheck && rdataCheck);
}

char *
rr_to_string(ResourceRecord *rr) {
    char *res = NULL;
    size_t wanted_to_write = 0;

    if (rr == NULL) return NULL;
    size_t str_len;
    if (rr->type == 41/* OPT */) {
        str_len = snprintf(NULL, 0,
                           "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tExtended RCODE || version: ",
                           rr->name, rr->type, rr->clas);
        str_len += 32;
        str_len += 1;
        str_len += snprintf(NULL, 0, "\trdsize: %hu\n\trdata: ", rr->rdsize);
    } else {
        str_len = snprintf(NULL, 0,
                           "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tTTL: %u\n\tRDSIZE: %hu\n\tRDATA: ",
                           rr->name, rr->type, rr->clas, rr->ttl, rr->rdsize);
    }
    for (int i = 0; i < rr->rdsize; i++) {
        str_len += snprintf(NULL, 0, "%hhX ", rr->rdata[i]);
    }
    str_len = str_len + /* \n */1 + /* \0 */1;
    res = malloc((sizeof(char) * str_len));
    if (res == NULL) {
        printf("Error malloc\n");
        return NULL;
    }
    if (rr->type != 41 /* OPT */) {
        wanted_to_write = snprintf(res, str_len,
                                   "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tTTL: %u\n\tRDSIZE: %hu\n\tRDATA: ",
                                   rr->name, rr->type, rr->clas, rr->ttl, rr->rdsize);
    } else {
        wanted_to_write = snprintf(res, str_len,
                                   "Resource Record:\n\tName: %s\n\tType: %hu\n\tClass: %hu\n\tExtended RCODE || version: ",
                                   rr->name, rr->type, rr->clas);
        uint8_t tmp = rr->ttl;
        uint16_t mask = 1 << 15;
        char bits[33];
        char *cur_bit = bits;
        char tmp_bit[2];
        for (int i = 0; i < 16; i++) {
            int wanted_to_write = snprintf(tmp_bit, 3, "%u ", tmp & mask ? 1 : 0);
            if (wanted_to_write > 3) {
                assert("didn't get to write everything we wanted..." == false);
            }
            tmp = tmp << 1;
            strcat(cur_bit, tmp_bit);
            cur_bit += 2;
        }
        strncat(res, bits, str_len);
        strncat(res, "\n", str_len);
        size_t str_left = str_len - strlen(res);
        char *cur_pos = res + strlen(res);
        snprintf(cur_pos, str_left, "\trdsize: %hu\n\trdata: ", rr->rdsize);

    }
    if (wanted_to_write >= str_len) {
        printf("Not enough space to make the string.\n");
        free(res);
        return NULL;
    }

    for (size_t i = 0; i < rr->rdsize; i++) {
        char byte[4];
        wanted_to_write = snprintf(byte, 4, "%hhX ", rr->rdata[i]);
        if (wanted_to_write >= 4) {
            printf("Ran out of room for rdata, wanted: %lu\n", wanted_to_write);
            free(res);
            return NULL;
        }
        strncat(res, byte, 4);
        str_len -= wanted_to_write;
    }
    if (str_len == 0) {
        printf("Error!\n");
    }

    strncat(res, "\n", 2);
    return res;
}
