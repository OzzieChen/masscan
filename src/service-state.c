//
// Created by WeichenZhao on 2017/2/28.
//

#include "service-state.h"
#include "logger.h"
#include "string_s.h"
#include "proto-banner1.h"
#include "unusedparm.h"
#include "masscan-app.h"
#include "proto-interactive.h"

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

int service_detect_parse(const struct ServiceStateTable *stateTable,
                         const struct SendingState *s,
                         const unsigned char *px, size_t length,
                         struct BannerOutput *banout,
                         struct InteractiveData *more) {
    struct RecvingState *r;
    int i, goto_offset = 0; /* As for now, "goto_offset = 0" means "haven't matched any patterns" */
    unsigned short is_need_match_all;
    size_t id;
    int state = 0, match_count = 0;

    r = stateTable->recvingStateEntry[s->waiting_id];

    while (1) {
        /**
         * If there is only one "goto" target, then go to this state only if it match
         * every patterns.
         *
         */
        if (r->goto_offset[1] == 0) { is_need_match_all = 1; }
        else {is_need_match_all = 0;} // FIXME: What if goto the '0' state is valid? Fix it

        /* Banner */
        if (r->is_banner) {
            banout_append(banout, PROTO_CUSTOM, px, length);
        }

        /* Patterns */
        if (r->pattern_count) {
            /* Matching */
            for (i = 0; i < length && match_count < r->pattern_count; i++) {
                state = 0;
                id = smack_search_next(r->automaton, &state, px, &i, length);
                i--;
                if (id != SMACK_NOT_FOUND) {
                    match_count++;
                    if (!is_need_match_all) break;
                }
                LOG(6, "service state: matching patterns - i = %d, id = %lu, state = %d, match_count = %d\n",
                    i, id, state, match_count);
            }

            /* Matching result */
            if (is_need_match_all && match_count == r->pattern_count) {
                /* Matched all patterns */
                goto_offset = r->goto_offset[0];
            } else if (!is_need_match_all && match_count) {
                /* Matched one pattern */
                goto_offset = r->goto_offset[id];
            } else {
                LOG(6, "service state: [return]matching failed or finished, turning state from r[%d] to GOTO_FIN\n", r->id);
                return GOTO_FIN; // FIXME: Add a failover function
            }
        } else {
            goto_offset = r->goto_offset[0];
        }

        /* Length */
        if (r->len_range.min != 0 || r->len_range.max != 0) {
            // TODO: Length range validation check goes here
            if (length < r->len_range.min || length > r->len_range.max) {
                LOG(6, "service state: [return]length match failed, turning state from r[%d] to GOTO_FIN\n", r->id);
                return GOTO_FIN; // FIXME: Add a failover function
            }
        }
        if (goto_offset == GOTO_FIN) {
            LOG(6, "service state: [return]matching failed or finished, turning state from r[%d] to GOTO_FIN\n", r->id);
            return GOTO_FIN;
        } else if (goto_offset > 0) {
            /* Sending state, turn into this state and break */
            LOG(6, "service state: [return]finished for matching, turning state from r[%d] to s[%d]\n", r->id,
                goto_offset);
            struct SendingState *new_sending_state = stateTable->sendingStateEntry[goto_offset];
            more->payload = new_sending_state->msg;
            more->length = strlen(new_sending_state->msg);
            return goto_offset;
        } else if (goto_offset < 0) {
            /* Recving state, turn into this new recving state and re-match again */
            LOG(6, "service state: turning state from r[%d] to r[%d]\n", r->id, (-1) * goto_offset);
            r = stateTable->recvingStateEntry[(-1) * goto_offset];
            goto_offset = 0; // FIXME: If we can finally turn to '0' state, please fix here
            match_count = 0;
            continue;
        }
    }

};

int service_detect_selftest(void) {
    struct ServiceStateTable *stateTable;
    stateTable = create_service_state_table(MAX_SENDING_STATE_COUNT, MAX_RECVING_STATE_COUNT, NULL);
    struct SendingState *s = stateTable->sendingStateEntry[0];
    struct BannerOutput banout[1];
    const unsigned char *px;
    unsigned length;
    static const char *http_header =
            "HTTP/1.0 200 OK\r\n"
                    "Date: Tue, 03 Sep 2013 06:50:01 GMT\r\n"
                    "Connection: close\r\n"
                    "Via: HTTP/1.1 ir14.fp.bf1.yahoo.com (YahooTrafficServer/1.2.0.13 [c s f ])\r\n"
                    "Server: Apache/1.20.13\r\n"
                    "Cache-Control: no-store\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Language: en\r\n"
                    "Location: http://failsafe.fp.yahoo.com/404.html\r\n"
                    "Content-Length: 227\r\n"
                    "\r\n<title>hello</title>\n";

    banout_init(banout);
    px = (const unsigned char *)http_header;
    length = (unsigned)strlen(http_header);

    int new_state_id = service_detect_parse(stateTable, s, px, length, &banout, NULL);
    LOG(1, "new state id = %d\n", new_state_id);

    return 0;
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
    msg = "GET / HTTP/1.0\r\nUser-Agent: Patterns s0\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";
    s->id = 0;
    strcpy_s(s->msg, sizeof(s->msg), msg);
    // s->waiting = stateTable->recvingStateEntry[0]; // s.waiting = r0
    s->waiting_id = 0;
    stateTable->sendingStateEntry[0] = s;

    // s1
    s = (struct SendingState*)malloc(sizeof(*s));
    memset(s, 0, sizeof(*s));
    msg = "GET / HTTP/1.0\r\nUser-Agent: Patterns s1\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";
    s->id = 1;
    strcpy_s(s->msg, sizeof(s->msg), msg);
    // s->waiting = stateTable->recvingStateEntry[2];
    s->waiting_id = 2;
    stateTable->sendingStateEntry[1] = s;

    // s2
    s = (struct SendingState*)malloc(sizeof(*s));
    memset(s, 0, sizeof(*s));
    msg = "GET / HTTP/1.0\r\nUser-Agent: Patterns s2\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n";
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
    struct ServicePattern patterns0[] = {
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
    struct ServicePattern patterns1[] = {
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
    r->len_range.min = 200;
    r->len_range.max = INFINITY;
    r->goto_offset[0] = -4;
    stateTable->recvingStateEntry[2] = r;

    // r3
    r = (struct RecvingState *)malloc(sizeof(*r));
    r->id = 3;
    r->pattern_count = 2;
    struct ServicePattern patterns3[] = {
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
    r->goto_offset[0] = 1;// GOTO_FIN;
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