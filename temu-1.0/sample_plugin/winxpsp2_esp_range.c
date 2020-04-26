#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "hc_interface.h"

#include "H_test_config.h"

#include "winxpsp2_defs.h"

#include "winxpsp2_esp_range.h"
#include "../TEMU_main.h"
#include "call_analysis.h"


extern plugin_interface_t my_interface;


static threadstack_info_list_t h_threadstack_info_list;

void init_threadstack_info_list( )
{
    h_threadstack_info_list.head = NULL;
    h_threadstack_info_list.end  = NULL;

    h_threadstack_info_list.count = 0;
}// end of init_threadstack_info_list( )

void delete_threadstack_info_list( )
{
    struct threadstack_info * entry     = h_threadstack_info_list.head;
    struct threadstack_info * pre_entry = NULL;

    while(entry != NULL)
    {
	pre_entry = entry;
	entry = entry->next;

	free(pre_entry);
    }// end of while{entry}

    h_threadstack_info_list.head  = NULL;
    h_threadstack_info_list.end   = NULL;
    h_threadstack_info_list.count = 0;
}// end of delete_threadstack_info_list( )


void fetch_threadstack_info_from_list( uint32_t * stackbases,
				       uint32_t * stacklimits
				     )
{
    struct threadstack_info * entry = h_threadstack_info_list.head;

    for(int i=0; i<h_threadstack_info_list.count; i=i+1)
    {
	stackbases[i]  = entry->stackbase;
	stacklimits[i] = entry->stacklimit;

	entry = entry->next;
    }// end of for{i}
}// end of add_threadstack_info_to_list( )



void add_threadstack_info_to_list( uint32_t stackbase,
				   uint32_t stacklimit
				 )
{
    struct threadstack_info * entry = (struct threadstack_info *)malloc(sizeof(struct threadstack_info));
    entry->next	      = NULL;
    entry->stackbase  = stackbase;
    entry->stacklimit = stacklimit;

    if( h_threadstack_info_list.head == NULL )
    {
	h_threadstack_info_list.head = entry;
	h_threadstack_info_list.end  = entry;
    }
    else
    {
	(h_threadstack_info_list.end)->next = entry;
	h_threadstack_info_list.end         = entry;
    }// end of if( )

    h_threadstack_info_list.count = h_threadstack_info_list.count + 1;
}// end of add_threadstack_info_to_list( )


void WINDOWS_obtain_esp_range( uint32_t    eprocess,
			       uint32_t ** low_esp,
			       uint32_t ** high_esp,
			       int *	   count
			     )
{
    uint32_t threadlisthead = 0;
    TEMU_read_mem( (eprocess + THREAD_LIST_HEAD_IN_EPROCESS),
		   4,
		   &threadlisthead
    		 );

    uint32_t threadlist_entry = threadlisthead;
    uint32_t ethread	= 0;
    uint32_t cur_eproc  = 0;
    uint32_t teb	= 0;
    uint32_t nt_tib	= 0;
    uint32_t stackbase  = 0;
    uint32_t stacklimit = 0;
    

    // FLINK in the total thread-list !
    /*
    TEMU_read_mem( threadlisthead,
		   4, 
		   &threadlist_entry
		 );
    */
    int thread_count = 0;

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

	/*
	term_printf( "ethread : 0x%x\n",
		     ethread
		   );
	*/

        // uint32_t stackbase_in_kthread = 0;
        // #define STACKBASE_IN_KTHREAD 	 0x168
	/*
	TEMU_read_mem( (kthread + STACKBASE_IN_KTHREAD),
		       4,
		       &stackbase_in_kthread
		     );
	term_printf( "stackbase_in_kthread : 0x%x\n",
		     stackbase_in_kthread
		   );
	*/

	// TEB
	TEMU_read_mem( (ethread + TEB_IN_KTHREAD),
		       4,
		       &teb
		     );
	/*
	term_printf( "TEB = NT_TIB = 0x%x\n",
		     teb
		   );
	*/
	// NT_TIB
	nt_tib = teb;

        // STACKBASE 
        TEMU_read_mem( (nt_tib + STACKBASE_IN_NT_TIB),
		       4,
		       &stackbase
		     );

	// STACKLIMIT 
	TEMU_read_mem( (nt_tib + STACKLIMIT_IN_NT_TIB),
		       4,
		       &stacklimit
		     );

	/*	
	term_printf( "stack ---- base = 0x%x --- limit = 0x%x\n",
		     stackbase,
		     stacklimit
		   );
	*/
	add_threadstack_info_to_list( stackbase,
				      stacklimit
				    );		

	thread_count = thread_count + 1;

NEXT_THREAD:
        // FLINK in LIST_ENTRY !
        TEMU_read_mem( threadlist_entry,
		       4, 
		       &threadlist_entry
		     );	

    }while(threadlist_entry != threadlisthead); // end of while{threadlist_entry}    


    *low_esp  = (uint32_t *)malloc(sizeof(uint32_t) * thread_count);
    *high_esp = (uint32_t *)malloc(sizeof(uint32_t) * thread_count);

/*
    for(int i=0; i<thread_count; i=i+1)
    {
	*( (uint32_t *)( (uint32_t)(*low_esp)  + i * sizeof(uint32_t) ) ) = stacklimit;
	*( (uint32_t *)( (uint32_t)(*high_esp) + i * sizeof(uint32_t) ) ) = stackbase;
    }// end of for{i}    
 */
    fetch_threadstack_info_from_list( *high_esp, // for stacklimits
				      *low_esp   // for stackbases
				    );

    // *count = thread_count - 1;
    *count = thread_count;

    // term_printf("finished thread ESP calculating \n");
}// end of WINDOWS_obtain_esp_range( )



void symaddr_obtain_stack_range_constraint( HVC     hvc,
					    HExpr   symaddr,
					    HExpr * out_of_range_constraint
					  )
{
    uint32_t eprocess    = my_interface.p_eprocess;

    uint32_t * low_esps  = NULL;    
    uint32_t * high_esps = NULL;
    int        count     = 0;


    init_threadstack_info_list( );

    WINDOWS_obtain_esp_range( eprocess,
			      &low_esps,
			      &high_esps,
			      &count
			    );

    HExpr temp_expr1 = NULL;
    HExpr temp_expr2 = NULL;
    HExpr temp_expr3 = NULL;
    HExpr low_bound_expr  = NULL;
    HExpr high_bound_expr = NULL;

    /*
    char * str_symaddr_expr = exprString(symaddr);
    term_printf( "symaddr is %s ------- totally %d separate ESP-ranges ---- low_esps = 0x%x, high_esps = 0x%x !\n",
		 str_symaddr_expr,
		 count,
		 low_esps,
		 high_esps
	       );
    free(str_symaddr_expr);
    */

    /* for each ESP-range, generate OUT-OF-RANGE constraint and summarize the total into one ! */
    for(int i=0; i<count; i=i+1)
    {
	
	term_printf( "low_esps[%d] = 0x%x, high_esps[%d] = 0x%x\n",
		     i,
		     low_esps[i],
		     i,
		     high_esps[i]
		   );
	

	temp_expr1 = vc_bvConstExprFromInt( hvc,
					    32,
					    low_esps[i]
					  );	
	// term_printf("vc_bvConstExprFromInt( ) ...\n");

	low_bound_expr = vc_bvLtExpr( hvc,
				      symaddr,
				      temp_expr1
			            );
/*
	low_bound_expr = vc_notExpr( hvc,
				     vc_bvBoolExtract( hvc,
						       low_bound_expr,
						       0
						     )
			           );
 */

	// vc_DeleteExpr(temp_expr1);
	// term_printf("vc_bvLtExpr( ) ...\n");
	

	temp_expr1 = vc_bvConstExprFromInt( hvc,
					    32,
					    high_esps[i]
					  );
	high_bound_expr = vc_bvGtExpr( hvc,
				       symaddr,
				       temp_expr1
				     );
/*
	high_bound_expr = vc_notExpr( hvc,
				      vc_bvBoolExtract( hvc,
							high_bound_expr,
							0
						      )
			            );

 */

	// term_printf("Now summarizing ...\n");

	temp_expr2 = vc_orExpr( hvc,
				low_bound_expr,
			 	high_bound_expr
			      );

	// term_printf("summarization finished ...\n");

	if(i == 0)
	{
	    *out_of_range_constraint = temp_expr2;
	}
	else
	{
	    *out_of_range_constraint = vc_andExpr( hvc,
						   *out_of_range_constraint,
						   temp_expr2
						 );
	}// end of if( )

    }// end of for{i}

    free(low_esps);
    free(high_esps);

    delete_threadstack_info_list( );

    // term_printf("symaddr_obtain_stack_range_constraint( )\n");
    
}// end of symaddr_obtain_stack_range_constraint( )


// checks for stack-eip overwritten
void symaddr_stack_eip_overwritten_constraint( HVC     hvc,
			       		       HExpr   symaddr,
					       HExpr * stack_eip_overwritten_written_constraint
					     )
{
    uint32_t * ebp_array = NULL;
    int	       i	 = 0;
    int	       count	 = 0;
    HExpr      tmp_expr1 = NULL;
    HExpr      tmp_expr2 = NULL;
    HExpr      tmp_expr3 = NULL;

    if( (count = Fetch_all_ebps_from_callstack(&ebp_array) ) == 0 )
    {
	*stack_eip_overwritten_written_constraint = NULL;
	return;
    }// end of if(Fetch_all_ebps_from_callstack)

    term_printf( "symaddr stack-eip count = %d\n",
		 count
	       );
    for(i = 0; i < count; i = i + 1)
    {
	tmp_expr1 = vc_bv32ConstExprFromInt( hvc,
					     ebp_array[i]
					   );
	tmp_expr2 = vc_eqExpr( hvc,
			       symaddr,
			       tmp_expr1
			     );
	if(i == 0)
	{
	    *stack_eip_overwritten_written_constraint = tmp_expr2;
	}
	else
	{
	    tmp_expr3 = *stack_eip_overwritten_written_constraint;
	    *stack_eip_overwritten_written_constraint = vc_orExpr( hvc,
								   tmp_expr3,
								   tmp_expr2
								 );
	    // vc_DeleteExpr(tmp_expr3);
	}// end of if(i)

	// vc_DeleteExpr(tmp_expr2);
	// vc_DeleteExpr(tmp_expr1);
    }// end of for{i}

    dump_callstack( );

    free(ebp_array);    
}// end of symaddr_stack_eip_overwritten_constraint( )



#ifdef H_DEBUG_TEST

void dbg_dump_stack_range( )
{
    int  i     = 0;
    int  count = 0;
    char buffer[50];

    uint32_t * low_esps    = NULL;
    uint32_t * high_esps   = NULL;
    int	       total_count = 0;

    int fd = -1;

    WINDOWS_obtain_esp_range( my_interface.p_eprocess,
			      &low_esps,
			      &high_esps,
			      &total_count
			    );
    umask(0);
    fd = open( "stack_log",
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );

    for(i = 0; i < total_count; i = i + 1)
    {
	count = sprintf( buffer,
			 "%x -- %x\n",
			 low_esps[i],
			 high_esps[i]
		       );
	buffer[count] = '\0';

	write( fd,
	       buffer,
	       count
	     );
    }// end of for{i}

    close(fd);
    free(low_esps);
    free(high_esps);
    delete_threadstack_info_list( );    
}// end of dbg_dump_stack_range( )


int dbg_addr_is_in_stack_range( uint32_t   value,
				uint32_t * start_addr,
				uint32_t * end_addr
			      )
{
    int i = 0;

    uint32_t * low_esps  = NULL;
    uint32_t * high_esps = NULL;
    int	       count	 = 0;

    WINDOWS_obtain_esp_range( my_interface.p_eprocess,
			      &low_esps,
			      &high_esps,
			      &count
			    );

    for(i = 0; i < count; i = i + 1)
    {
	if( ( value >= low_esps[i] ) &&
	    ( value <= high_esps[i] )
	  )
	{
	    *start_addr = low_esps[i];
	    *end_addr   = high_esps[i];

	    free(low_esps);
	    free(high_esps);
	    delete_threadstack_info_list( );

	    return 1;
	}// end of if(value)
    }// end of for{i}


    free(low_esps);
    free(high_esps);
    delete_threadstack_info_list( );

    return 0;
}// end of dbg_addr_is_in_stack_range( )
#endif




