#ifndef H_RAW_CHECK_PUSHPOP_H
    #define H_RAW_CHECK_PUSHPOP_H

    #include <inttypes.h>
    /* return value:
       1 ---- PUSH; (not including immediates' PUSH!)
       2 ---- POP;
       0 ---- none of the above 2.
     */
    int isPushPop(uint32_t inst_addr);

#endif
