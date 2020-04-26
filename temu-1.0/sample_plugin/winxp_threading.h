#ifndef H_WINXP_THREADING_H
    #define H_WINXP_THREADING_H

    #include "H_test_config.h"

    void list_total_threads_in_monitored_process( );

    int check_thread_context( );

    #ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
        extern h_monitored_thread_id;
    #endif

#endif
