#include <stdlib.h>
#include <stdio.h>
#include <intttypes.h>
#include <malloc.h>

#include "H_test_config.h"
#include "../TEMU_main.h"

extern plugin_interface_t my_interface;

#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT

/* HHui TODO: a basis for multi-threading analysis */

h_thread_context_t * thread_context_list = NULL;
int thread_context_count = 0;
int thread_context_list_capacity_count = 0;

void init_thread_context_list( )
{
    thread_context_list  = (h_thread_context_t *)malloc(sizeof(h_thread_context_t) * 2);
    thread_context_count = 0;
    thread_context_list_capacity_count = 2;

    my_interface.thc_util = (temu_thread_context_util_t *)malloc(sizeof(temu_thread_context_util_t));
    (my_interface.thc_util)->h_add_thread_context_2_list = add_thread_context_2_list;

}// end of init_thread_context_list( )


void delete_thread_context_list( )
{
    free(thread_context_list);
    thread_context_count = 0;
    thread_context_list_capacity_count = 0;

    free(my_interface.thc_util);
}// end of delete_thread_context_list( )


h_thread_context_t * add_thread_context_2_list(int tid)
{
    if(thread_context_count == thread_context_list_capacity_count)
    {
	thread_context_list = (h_thread_context_t *)realloc( thread_context_list,
							     sizeof(h_thread_context_t) * 
							     (2 + thread_context_list_capacity_count)
							   );
	thread_context_list_capacity_count = thread_context_list_capacity_count + 2;
    }// end of if(thread_context_count)

    thread_context_list[thread_context_count].tid = tid;
    thread_context_count = thread_context_count + 1;

    return (thread_context_list + thread_context_count);
}// end of add_thread_context_2_list( )


h_thread_context_t * fetch_thread_context_by_tid(int tid)
{
    int i = 0;
    for(i = 0; i < thread_context_count; i = i + 1)
    {
	if(tid == thread_context_list[i].tid)
	{
	    return (thread_context_list + i);
	}// end of if(tid)
    }// end of for{i}

    return NULL;
}// end of fetch_thread_context_by_tid( )


#endif
