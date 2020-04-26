#ifndef H_WINXPSP2_ESP_RANGE_H
    #define H_WINXPSP2_ESP_RANGE_H

    #include <inttypes.h>
    #include "H_test_config.h"

    typedef struct threadstack_info
    {
	uint32_t stackbase;
	uint32_t stacklimit;

	struct threadstack_info * next;
    }threadstack_info_t, *Pthreadstack_info;

    typedef struct threadstack_info_list
    {
	struct threadstack_info * head;
	struct threadstack_info * end;

	int  count;
    }threadstack_info_list_t, *Pthreadstack_info_list;

    /* ------------------------------------------------------------------------------ */
    void init_threadstack_info_list( );

    void delete_threadstack_info_list( );

    void add_threadstack_info_to_list( uint32_t stackbase,
				       uint32_t stacklimit
				     );

    void fetch_threadstack_info_from_list( uint32_t * stackbases,
			  	           uint32_t * stacklimits
				         );
    /* ------------------------------------------------------------------------------ */


    void WINDOWS_obtain_esp_range( uint32_t    eprocess,
				   uint32_t ** low_esp,
			           uint32_t ** high_esp,
			           int *       count
			         );    

    void symaddr_obtain_stack_range_constraint( HVC     hvc,
					        HExpr   symaddr,
					        HExpr * out_of_range_constraint
					      );

    void symaddr_stack_eip_overwritten_constraint( HVC     hvc,
				       		   HExpr   symaddr,
					           HExpr * out_of_range_constraint
						 );

    #ifdef H_DEBUG_TEST
    int dbg_addr_is_in_stack_range( uint32_t   value,
			  	    uint32_t * start_addr,
				    uint32_t * end_addr
			          );
    #endif

#endif
