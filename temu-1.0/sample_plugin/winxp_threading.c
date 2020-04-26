#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "../TEMU_main.h"
#include "../shared/procmod.h"

#include "winxpsp2_defs.h"
// #include "winxp_threading.h"

#include "H_test_config.h"


extern plugin_interface_t my_interface;

void list_total_threads_in_monitored_process( )
{
    uint32_t eprocess  = my_interface.p_eprocess;
    uint32_t ethread   = 0;
    uint32_t teb       = 0;

    uint32_t cur_eproc = 0;
    uint64_t cur_tid   = 0;
    int      thread_count = 0;

    /*
    uint32_t current_tid = get_current_tid( );
    term_printf( "current tid = 0x%d\n",
		 current_tid
	       );
    */
    uint32_t threadlisthead = 0;
    TEMU_read_mem( (eprocess + THREAD_LIST_HEAD_IN_EPROCESS),
		   4,
		   &threadlisthead
    		 );

    uint32_t threadlist_entry = threadlisthead;

    

    // FLINK in the total thread-list !
    /*
    TEMU_read_mem( threadlisthead,
		   4, 
		   &threadlist_entry
		 );
    */


    // while(threadlist_entry != threadlisthead)
    do
    {		        
	// ETHREAD --- KTHREAD !
	ethread = threadlist_entry - THREAD_LIST_ENTRY_IN_ETHREAD;

	// checks for EPROCESS
	TEMU_read_mem( (ethread + EPROCESS_IN_ETHREAD),
		       4,
		       &cur_eproc
		     );
	if(cur_eproc != eprocess)
	{
	    goto NEXT_THREAD;
	}// end of if(cur_proc)

	// thread-ID
	TEMU_read_mem( (ethread + TID_IN_ETHREAD),
		       8,
		       &cur_tid
		     );
	/*
	// TEB
	TEMU_read_mem( (ethread + TEB_IN_KTHREAD),
		       4,
		       &teb
		     );		
	TEMU_read_mem( (teb + TID_IN_TEB),
		       8,
		       &cur_tid
		     );
	*/	
	term_printf( "thread: tid=0x%x\n",
		     cur_tid
		   );

	// if(cur_tid == )

	thread_count = thread_count + 1;

NEXT_THREAD:
        // FLINK in LIST_ENTRY !
        TEMU_read_mem( threadlist_entry,
		       4, 
		       &threadlist_entry
		     );	

    }while(threadlist_entry != threadlisthead); // end of while{threadlist_entry}    
}// end of list_total_threads_in_monitored_process( )



/* suppose cr3 was previously checked, here we only 
 */
int check_thread_context( )
{
    uint32_t eprocess  = my_interface.p_eprocess;
    uint32_t ethread   = 0;
    uint32_t teb       = 0;

    uint32_t cur_eproc = 0;
    uint64_t cur_tid   = 0;
    int      thread_count = 0;
    
    uint32_t current_tid = get_current_tid( );

    uint32_t threadlisthead = 0;
    TEMU_read_mem( (eprocess + THREAD_LIST_HEAD_IN_EPROCESS),
		   4,
		   &threadlisthead
    		 );

    uint32_t threadlist_entry = threadlisthead;

    do
    {		        
	// ETHREAD --- KTHREAD !
	ethread = threadlist_entry - THREAD_LIST_ENTRY_IN_ETHREAD;

	// checks for EPROCESS
	TEMU_read_mem( (ethread + EPROCESS_IN_ETHREAD),
		       4,
		       &cur_eproc
		     );
	if(cur_eproc != eprocess)
	{
	    goto NEXT_THREADING;
	}// end of if(cur_proc)

	// thread-ID
	TEMU_read_mem( (ethread + TID_IN_ETHREAD),
		       4,
		       &cur_tid
		     );

	/*
	term_printf( "thread: tid=0x%x\n",
		     cur_tid
		   );
	 */

	if(current_tid == cur_tid)
	{
	    term_printf("======================================================= great ======================================================= !\n");
	
	    return 1;
	}// end of if(current_tid)
	
	thread_count = thread_count + 1;

NEXT_THREADING:
        // FLINK in LIST_ENTRY !
        TEMU_read_mem( threadlist_entry,
		       4, 
		       &threadlist_entry
		     );	

    }while(threadlist_entry != threadlisthead); // end of while{threadlist_entry}    

    return 0;
}// end of check_thread_context( )






#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
    uint32_t h_monitored_thread_id = 0;
#endif


