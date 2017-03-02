//
// Created by WeichenZhao on 2017/2/28.
//

#include "service-state.h"
#include "logger.h"
#include "string_s.h"
#include "proto-banner1.h"

struct ServiceStateTable *create_service_state_table(size_t sending_state_count,
                                                     size_t recving_state_count,
                                                     char *filename) {
    struct ServiceStateTable *stateTable;
    stateTable = (struct ServiceStateTable *)malloc(sizeof(*stateTable));
    if (stateTable == NULL)
        exit(1);
    memset(stateTable, 0, sizeof(*stateTable));

    /**
     * init for sending states
     */
    stateTable->sendingStateEntry = (struct SendingState **)
            malloc(sending_state_count * sizeof(*stateTable->sendingStateEntry));
    if (stateTable->sendingStateEntry == NULL) {
        LOG(0, "service state: error in malloc sending states entry\n");
        exit(1);
    }
    memset(stateTable->sendingStateEntry, 0, sending_state_count * sizeof(*stateTable->sendingStateEntry));

    /**
     * init for recving states
     */
    stateTable->recvingStateEntry = (struct RecvingState **)
            malloc(recving_state_count * sizeof(*stateTable->recvingStateEntry));
    if (stateTable->recvingStateEntry == NULL) {
        LOG(0, "service state: error in malloc recving states entry\n");
        exit(1);
    }
    memset(stateTable->recvingStateEntry, 0, recving_state_count * sizeof(*stateTable->recvingStateEntry));

    // FIXME: self testing...
    // service_pattern_init(stateTable, filename);
    selftest_fake_data(stateTable);

    // TODO: state table validation check goes here. eg.: is every sending state has msg? etc.

    return stateTable;
}

/**
 * eg.: r1.patterns = {"Nginx", "Apache"}
 * -> name = r1.patterns
 * -> value = {"Nginx", "Apache"}
 * @param filename
 */
void service_pattern_init(struct ServiceStateTable *stateTable, char *filename) {
    // 1. read pattern file
    FILE *fp;
    errno_t err;
    char line[65536];

    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        trim(line, sizeof(line));

        if (ispunct(line[0] & 0xFF) || line[0] == '\0')
            continue;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;
        trim(name, sizeof(line));
        trim(value, sizeof(line));

        service_pattern_set_parameter(stateTable, name, value);
    }

    fclose(fp);
}

void service_pattern_set_parameter(struct ServiceStateTable *stateTable, char *name, char *value){
    // stateTable[offset] == NULL ? create&init : grab&putting in values
    char *prefix = name;
    char *property = strchr(name, '.');
    char *direction = prefix; // 'r' or 's'
    int offset = atoi(prefix+1);

    LOG(6, "service state: setting parameter - direction = %c, offset = %d\n", *direction, offset);

    // TODO: validation check goes here, eg., if 's' then offset <= MAX_SENDING_STATE_COUNT etc.
    /**
     * Sending state
     */
    if (direction == 's') {
        struct SendingState *s = stateTable->sendingStateEntry[offset];
        if (s == NULL) {
            // FIXME: This should not happen
            LOG(6, "service state: couldn't get this state, may not be inited");
            exit(1);
        }
        if (stateTable->sendingStateEntry[offset] == 0){
            // first time FIXME: maybe useless
            s->id = offset;
        }

        // TODO: Complete it
        if (EQUALS("msg", property)) {

        }
    }

    /**
     * Recving state
     */
    else if (direction == 'r') {

    }
}


void recving_state_pattern_init(struct RecvingState *state, char *smack_name) {
    unsigned short i;

    /*char name[MAX_PATTERN_COUNT + 1]; *//* "+1" for the char 'r', eg. "r12" *//*
    char *pName = name;
    *//*pName = strcpy(name, "r");
    pName = strcpy(name, itoa(state->id));*//*
    LOG(6, "OZZIE: - creating smack %s\n", pName);*/
    state->automaton = smack_create(smack_name, SMACK_CASE_INSENSITIVE);

    for (i = 0; i < state->pattern_count; i++) {
        smack_add_pattern(state->automaton,
                          state->patterns[i].pattern,
                          state->patterns[i].pattern_length,
                          state->patterns[i].id,
                          0);
    }
    smack_compile(state->automaton);
}


void selftest_fake_data(struct ServiceStateTable *stateTable) {
    /**
     * sending states
     */
    char *msg;
    struct SendingState *s;

    // s0
    s = (struct SendingState*)malloc(sizeof(*s));
    memset(s, 0, sizeof(*s));
    msg = "GET / HTTP/1.0\r\nUser-Agent: Patterns 1.0\r\nAccept: */*\r\n\r\n";
    s->id = 0;
    strcpy_s(s->msg, sizeof(s->msg), msg);
    // s->waiting = stateTable->recvingStateEntry[0]; // s.waiting = r0
    s->waiting_id = 0;
    stateTable->sendingStateEntry[0] = s;

    // s1
    s = (struct SendingState*)malloc(sizeof(*s));
    memset(s, 0, sizeof(*s));
    msg = "GET /index.php HTTP/1.0\r\nUser-Agent: Patterns 1.0\r\nAccept: */*\r\n\r\n";
    s->id = 1;
    strcpy_s(s->msg, sizeof(s->msg), msg);
    // s->waiting = stateTable->recvingStateEntry[2];
    s->waiting_id = 2;
    stateTable->sendingStateEntry[1] = s;

    // s2
    s = (struct SendingState*)malloc(sizeof(*s));
    memset(s, 0, sizeof(*s));
    msg = "GET /login HTTP/1.0\r\nUser-Agent: Patterns 1.0\r\nAccept: */*\r\n\r\n";
    s->id = 2;
    strcpy_s(s->msg, sizeof(s->msg), msg);
    // s->waiting = stateTable->recvingStateEntry[3];
    s->waiting_id = 3;
    stateTable->sendingStateEntry[2] = s;

    /**
     * recving states
     */
    struct RecvingState *r;

    // r0
    r = (struct RecvingState *)malloc(sizeof(*r));
    r->id = 0;
    r->is_banner = 1;
    r->pattern_count = 2;
    LOG(0, "r->pattern_count = %u", r->pattern_count);
    struct ServiceStateTable patterns0[] = {
            {"HTTP/1.", 7, 0}, {"200 OK", 6, 1}
    };
    memcpy(r->patterns, patterns0, sizeof(patterns0));
    // r->patterns = patterns;
    recving_state_pattern_init(r, "r0");
    r->goto_offset[0] = -1;
    stateTable->recvingStateEntry[0] = r;

    // r1
    r = (struct RecvingState *)malloc(sizeof(*r));
    r->id = 1;
    r->pattern_count = 2;
    struct ServiceStateTable patterns1[] = {
            {"Nginx", 5, 0}, {"Apache", 6, 1}
    };
    memcpy(r->patterns, patterns1, sizeof(patterns1));
    recving_state_pattern_init(r, "r1");
    r->goto_offset[0] = 1;
    r->goto_offset[1] = 2;
    stateTable->recvingStateEntry[1] = r;

    // r2
    r = (struct RecvingState *)malloc(sizeof(*r));
    r->id = 2;
    r->len_range.min = 400;
    r->len_range.max = INFINITY;
    r->goto_offset[0] = 4;
    stateTable->recvingStateEntry[2] = r;

    // r3
    r = (struct RecvingState *)malloc(sizeof(*r));
    r->id = 3;
    r->pattern_count = 2;
    struct ServiceStateTable patterns3[] = {
            {"HTTP/1.", 7, 0}, {"200 OK", 6, 1}
    };
    memcpy(r->patterns, patterns3, sizeof(patterns3));
    // r->patterns = patterns;
    recving_state_pattern_init(r, "r3");
    r->goto_offset[0] = -5;
    stateTable->recvingStateEntry[3] = r;

    // r4
    r = (struct RecvingState *)malloc(sizeof(*r));
    r->id = 4;
    r->is_banner = 1;
    r->goto_offset[0] = GOTO_FIN;
    stateTable->recvingStateEntry[4] = r;

    // r5
    r = (struct RecvingState *)malloc(sizeof(*r));
    r->id = 5;
    r->is_banner = 1;
    r->goto_offset[0] = GOTO_FIN;
    stateTable->recvingStateEntry[5] = r;
}

/**
 * Copy of main-conf.c's EQUALS()
 */
int EQUALS(const char *lhs, const char *rhs) {
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

void trim(char *line, size_t sizeof_line) {
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);

    while (isspace(*line & 0xFF))
        memmove(line, line+1, sizeof_line--);
    while (*line && isspace(line[sizeof_line-1] & 0xFF))
        line[--sizeof_line] = '\0';
}

/*
struct ProtocolParserStream banner_custom_service = {
    "custom_service"
};*/
