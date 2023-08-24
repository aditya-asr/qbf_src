#ifndef __QUESTION_H__

#define __QUESTION_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct Question {
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
} Question;

int
destroy_question(Question **question);

int
create_question(Question **out, char *qname, uint16_t qtype, uint16_t qclass);

int
clone_question(Question *in, Question **out);

int
bytes_to_question(unsigned char *in, size_t in_len, size_t *bytes_processed, Question **out);

int
question_to_bytes(Question *in, unsigned char **out, size_t *out_len);

char *
question_to_string(Question *q);

bool
question_is_equal(Question *lhs, Question *rhs);

char *AppendStrings(const char *A, const char *B);

#endif /* __QUESTION_H__ */
