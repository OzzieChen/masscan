//
// Created by WeichenZhao on 2017/2/28.
//

#ifndef MASSCAN_SERVICE_STATE_H
#define MASSCAN_SERVICE_STATE_H

#include "smack.h"
#include "proto-banner1.h"

#include <string.h>

#define INFINITY ((unsigned short)~0)
#define MAX_SENDING_STATE_COUNT 10
#define MAX_RECVING_STATE_COUNT 10
#define MAX_PATTERN_COUNT 10
#define GOTO_FIN -1000
#define RANDOM_PORT 0

extern struct ProtocolParserStream banner_serviceDetect;

/**
 * Define the states of sending.
 * Embedded in TCP_Control_Block
 */
struct SendingState {
    unsigned short id;
    char msg[300];
    unsigned short waiting_id; // The recving state id that current sending state is waiting for
};

struct ServicePattern {
    const char *pattern;
    unsigned pattern_length;
    unsigned id;
};

struct RecvingState {
    unsigned short id;
    unsigned short is_banner:1;
    unsigned short pattern_count;
    struct ServicePattern patterns[MAX_PATTERN_COUNT];
    struct SMACK *automaton;

    /**
     * usage: {index, state_with_id}, {index, state_with_id}
     *
     * state_with_id:
     *  positive: sending state
     *  negative: receiving state
     * example:
     *  r1.goto_offset = {0, s1}, {1, r3}
     *  -> [1, -3]
     *  r1.goto_offset = FIN
     *  -> [GOTO_FIN]
     */
    short goto_offset[MAX_SENDING_STATE_COUNT + MAX_RECVING_STATE_COUNT];

    /**
     * [400, +) => min = 400, max = INFINITY => len >= 400
     * (300, 780] => min = 301, max = 780 => len >= 301 && len <= 780
     * [0, 200] => min = 0, max = 200 => len >=0, len <= 200
     * default => len >= 0
     // TODO: Check the input validation
     */
    struct length_range{
        unsigned short min;
        unsigned short max;
    } len_range;
};

struct ServiceStateTable {
    struct SendingState **sendingStateEntry;
    struct RecvingState **recvingStateEntry;
};

/**
 * Create a service state table, corresponding to each ThreadPair
 * and init its patterns.
 * @param entry_count
 * @return
 */
struct ServiceStateTable *create_service_state_table(size_t sending_state_count,
                                                     size_t recving_state_count,
                                                     char *filename);
void service_pattern_init(struct ServiceStateTable *stateTable, char *filename);
void service_pattern_set_parameter(struct ServiceStateTable *stateTable, char *name, char *value);

/**
 * Parse the service detection's response.
 * Process the recving patterns until meet any sending states.
 * @return new sending state or GOTO_FIN(aka. STATE_DONE)
 */
int service_detect_parse(const struct ServiceStateTable *stateTable,
                         const struct SendingState *s,
                         const unsigned char *px, size_t length,
                         struct BannerOutput *banout,
                         struct InteractiveData *more);

/**
 * Turn patterns to automaton
 * @param state inited receiving state
 */
void recving_state_pattern_init(struct RecvingState *state, char *smack_name);

int service_detect_selftest(void);
void selftest_fake_data(struct ServiceStateTable *stateTable);

/**
 * Utilities
 */
void trim(char *line, size_t sizeof_line);
int EQUALS(const char *lhs, const char *rhs);

#endif //MASSCAN_SERVICE_STATE_H
