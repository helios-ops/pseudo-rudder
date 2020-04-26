#ifndef H_THREAD_CONTEXT_H
    #define H_THREAD_CONTEXT_H

    #include <inttypes.h>
    #include "H_test_config.h"

    typedef struct h_thread_context
    {
	int tid;

	// HHui added at March 7th, 2012
	/* As there exist some EFLAGS saving errors when TEMU emulates an interrupt,
	   I temply mandatorily store and load all related thread-analysis-context !
	 */
	// concrete EFLAGS-states
	uint32_t con_eflags;

	// struct h_thread_context * next;
    }h_thread_context_t, *Ph_thread_context_t;

    typedef struct temu_thread_context_util
    {
	h_thread_context_t * (* h_add_thread_context_2_list)(int tid);
    }temu_thread_context_util_t, *Ptemu_thread_context_util_t;


    void init_thread_context_list( );

    void delete_thread_context_list( );

    h_thread_context_t * add_thread_context_2_list(int tid);

    h_thread_context_t * fetch_thread_context_by_tid(int tid);

#endif
