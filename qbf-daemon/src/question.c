#include <question.h>
#include <resource_record.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

int
destroy_question(Question **question) {
    if (question == NULL) {
        return 0;
    }
    Question *q = *question;
    if (q == NULL) {
        return 0;
    }
    if (q->qname != NULL)
        free(q->qname);
    free(q);
    *question = NULL;
    return 0;
}

int
create_question(Question **out, char *qname, uint16_t qtype, uint16_t qclass) {
    Question *q = malloc(sizeof(Question));
    size_t str_len = strlen(qname);
    if (q == NULL) {
        return -1;
    }
    q->qname = malloc((sizeof(char) * str_len) + 1);
    if (q->qname == NULL) {
        destroy_question(&q);
        return -1;
    }
    memcpy(q->qname, qname, str_len + 1);
    q->qtype = qtype;
    q->qclass = qclass;
    *out = q;
    return 0;
}


int
bytes_to_question(unsigned char *in, size_t in_len, size_t *bytes_processed, Question **out) {
    Question *res;
    int rc = 0;
    size_t name_len;
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
    unsigned char *cur_pos = in;
    size_t name_byte_len = 0;
    while (name_byte_len < in_len && in[name_byte_len] != 0) {
        name_byte_len++;
    }
    name_byte_len += 1;
    rc = bytes_to_dnsname(in, &qname, &name_len, bytes_processed, name_byte_len);
    if (rc != 0) {
        return -1;
    }

    cur_pos += *bytes_processed;

    qtype = *(uint16_t *) cur_pos;
    qtype = ntohs(qtype);
    cur_pos += 2;

    qclass = *(uint16_t *) cur_pos;
    qclass = ntohs(qclass);
    cur_pos += 2;

    rc = create_question(&res, qname, qtype, qclass);
    if (rc == 0) {
        *out = res;
        *bytes_processed = name_byte_len + 2 + 2;
    } else {
        *bytes_processed = 0;
    }
    free(qname);
    return rc;

}


int
question_to_bytes(Question *in, unsigned char **out, size_t *out_len) {
    unsigned char *bytes;
    int rc = 0;
    unsigned char *qname;
    uint16_t qtype;
    uint16_t qclass;
    unsigned char *cur_pos;
    size_t qname_len;
    rc = dnsname_to_bytes(in->qname, strlen(in->qname), &qname, &qname_len);
    if (rc != 0) {
        *out = NULL;
        return -1;
    }
    bytes = malloc(sizeof(unsigned char) * qname_len + 2 + 2);
    if (bytes == NULL) {
        *out = NULL;
        free(qname);
        return -1;
    }
    cur_pos = bytes;

    memcpy(cur_pos, qname, qname_len);
    cur_pos += qname_len;

    qtype = htons(in->qtype);
    memcpy(cur_pos, &qtype, 2);
    cur_pos += 2;

    qclass = htons(in->qclass);
    memcpy(cur_pos, &qclass, 2);
    cur_pos += 2;

    *out = bytes;
    *out_len = qname_len + 2 + 2;
    return 0;
}


int
clone_question(Question *in, Question **out) {
    Question *q = malloc(sizeof(Question));
    if (q == NULL) return -1;
    q->qname = malloc(strlen(in->qname) + 1);
    if (q->qname == NULL) return -1;
    strcpy(q->qname, in->qname);
    q->qtype = in->qtype;
    q->qclass = in->qclass;
    *out = q;
    return 0;
}

char *
question_to_string(Question *q) {
    char *res = NULL;
    size_t wanted_to_write = 0;

    if (q == NULL) return NULL;
    size_t str_len =
            snprintf(NULL, 0, "Question:\n\tQNAME: %s\n\tQTYPE: %hu\n\tQCLASS: %hu\n", q->qname, q->qtype, q->qclass) +
            1;
    res = malloc((sizeof(char) * str_len));
    wanted_to_write = snprintf(res, str_len, "Question:\n\tQNAME: %s\n\tQTYPE: %hu\n\tQCLASS: %hu\n", q->qname,
                               q->qtype, q->qclass);
    if (wanted_to_write >= str_len) {
        printf("String buffer too small\n");
        free(res);
        res = NULL;
    }
    return res;
}

bool
question_is_equal(Question *lhs, Question *rhs) {
    if (lhs == NULL && rhs != NULL)
        return false;
    if (lhs != NULL && rhs == NULL)
        return false;
    if (strcmp(lhs->qname, rhs->qname) != 0)
        return false;
    return ((lhs->qtype == rhs->qtype) && (lhs->qclass == rhs->qclass));
}
