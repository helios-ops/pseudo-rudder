/* Note: for function-summary symbolic-calculation, everytime we built-up a new pre-post condition pair,
	 we would reload all previously loaded snapshot with that new pre-post condition pair so as to 
	 force-up a new path.

	 We would make snapshot at the beginning of every interested function's hook point at its every
	 call-site first.
	 Then, when a new pre-post condition pair is generated, we would check every stored call-site, 
	 asking whether the sepcific call-site had previously met this pre-post condition. if not, we
	 should lift the snapshot into the TO-BE-LOADED queue so as to force another sym-exe path.
 */

#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include <xed-interface.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "func_summ_snapshot.h"
#include "expr_condition.h"
#include "function_summary.h"
#include "HVM_state.h"
#include "hc_interface.h"

#include "../TEMU_main.h"
#include "../TEMU_lib.h"

#include "H_test_config.h"

extern HVC HHui_VC;

// #ifdef HHUI_FUNC_SUMMARY_ENABLED

// records for total calling sequence !
/* ================================================================================================== */
#ifdef H_FUNC_CALLING_SEQUENCE_RECORD

static func_calling_list_t  H_func_calling_list;

void func_calling_list_init( )
{
    H_func_calling_list.head  = NULL;
    H_func_calling_list.end   = NULL;
    H_func_calling_list.count = 0;
}// end of func_calling_list_init( )


void func_calling_list_delete( )
{
    func_calling_entry_t * entry = H_func_calling_list.head;

    while(entry != NULL)
    {
	H_func_calling_list.head = entry->next;
	free(entry);
	entry = H_func_calling_list.head;
    }// end of while{entry}
}// end of func_calling_list_delete( )


void add_entry_2_func_calling_list_init(func_summ_snapshot_entry_t * fce_entry)
{
    func_calling_entry_t * entry = (func_calling_entry_t *)malloc(sizeof(func_calling_entry_t));
    entry->fce  = fce_entry;
    entry->next = NULL;

    if(H_func_calling_list.head == NULL)
    {
	H_func_calling_list.head = entry;
	H_func_calling_list.end  = entry;
    }
    else
    {
	(H_func_calling_list.end)->next = entry;	
	H_func_calling_list.end		= entry;
    }// end of if(H_func_calling_list)

    H_func_calling_list.count = H_func_calling_list.count + 1;
}// end of add_entry_2_func_calling_list_init( )

#endif
/* ================================================================================================== */




static void expr_cond_list_init(expr_cond_list_t * condlist)
{
    condlist->head  = NULL;
    condlist->end   = NULL;
    condlist->count = 0;
}// end of expr_cond_list_init( )


static void expr_cond_list_delete(expr_cond_list_t * condlist)
{
    expr_cond_entry_t * entry = condlist->head;

    while(entry != NULL)
    {
	condlist->head = (condlist->head)->next;

	free(entry);
	entry = condlist->head;
    }// end of while{entry}

    condlist->count = 0;
}// end of expr_cond_list_delete( )


// Note: we call this util when a new pre-post condition pair is applied to a specific callsite
static void add_entry_2_expr_cond_list( void 		 * condentry,
					expr_cond_list_t * condlist
				      )
{
    expr_cond_entry_t * entry = (expr_cond_entry_t *)malloc(sizeof(expr_cond_entry_t));
    entry->expr_cond = condentry;
    entry->next      = NULL;

    if(condlist->head == NULL)
    {
	condlist->head = entry;
	condlist->end  = entry;
    }
    else
    {
	(condlist->end)->next = entry;
	condlist->end	      = entry;
    }// end of if(condlist->head)
 
    condlist->count = condlist->count + 1;
}// end of add_entry_2_expr_cond_list( )


static int find_expr_cond_in_condlist( void	        * condentry,
				       expr_cond_list_t * condlist
				     )
{
    expr_cond_entry_t * entry = condlist->head;
    int   qresult  = 0;
    HExpr tmp_expr = NULL;

    while(entry != NULL)
    {
#ifndef H_COARSE_TESTING_CONDITION
    #define H_COARSE_TESTING_CONDITION
#endif

#ifdef H_COARSE_TESTING_CONDITION
	tmp_expr = vc_iffExpr( HHui_VC,
			       ( (h_condition_entry_t *)condentry )->pre_condition,
			       ( (h_condition_entry_t *)(entry->expr_cond) )->pre_condition
			     );
	vc_push(HHui_VC);
	qresult  = vc_query( HHui_VC,
		  	     tmp_expr
	 		   );
	vc_pop(HHui_VC);

	if(qresult == 1)
#else	
	if( ((uint32_t)condentry) == ((uint32_t)entry->expr_cond) )
#endif
	{
	    return 1;
	}// end of if(condentry)
	
	entry = entry->next;
    }// end of while{entry}

    return 0;
}// end of find_expr_cond_in_condlist( )


void func_summ_snapshot_list_init(func_summ_snapshot_list_t * fss_list)
{
    fss_list->head  = NULL;
    fss_list->end   = NULL;
    fss_list->count = 0;    
}// end of func_summ_snapshot_list_init( )


void func_summ_snapshot_list_delete(func_summ_snapshot_list_t * fss_list)
{
    func_summ_snapshot_entry_t * entry = fss_list->head;

    while(entry != NULL)
    {
	// free(entry->state_name);	
	fss_list->head = (fss_list->head)->next;
	free(entry);

	entry = fss_list->head;
    }// end of while{entry}
}// end of func_summ_snapshot_list_delete( )


// invoked when a pre-post condition pair is proved valid for the callsite of the funtion 'func_entry'
void add_condentry_2_func_summ_snapshot_entry( void     * func_entry,
					       uint32_t	  callsite_id,
					       void 	* cond_entry
					     )
{
    func_summ_snapshot_entry_t * entry = ( ( (function_summary_entry_t *)func_entry
					   )->fss_list
					 ).head;
    if(callsite_id == 2)
    {
	term_printf("callsite_id == 2\n");
    }// end of if(callsite_id)

    while(entry != NULL)
    {
	if(callsite_id == entry->callsite_id)
	{
	    add_entry_2_expr_cond_list( cond_entry,
					&(entry->H_expr_cond_list)
			      	      );
	    
	    #ifdef H_FUNC_SUMM_RESULT_DEBUG_DUMP
	    if( ( (callsite_id == 4) || (callsite_id == 5) 
		) ||
		(callsite_id == 8)
	      )
	    {
		term_printf("callsite_id = 4\n");
	    }// end of if(callsite_id)

	    func_summ_callsite_cond_append_2_file( ( (function_summary_entry_t *)func_entry )->vaddr,
						   (entry->H_expr_cond_list).count,
						   callsite_id,
						   ( (h_condition_entry_t *)cond_entry )->pre_condition
					         );
    	    #endif

	    return;
	}// end of if(callsite_id)

	entry = entry->next;
    }// end of while{entry}

    
}// end of add_condentry_2_func_summ_snapshot_entry( )



uint32_t find_specific_func_callsite( HExpr    		          path_expr,
				      uint32_t			  esp_addr,
				      func_summ_snapshot_list_t * fss_list				      
			            )
{
    func_summ_snapshot_entry_t * entry = fss_list->head;
    HExpr tmp_expr1 = NULL;
    int   qresult   = 0;

    // term_printf("\nNow verifying this calling instance for a previously visited callsite !\n");

    while(entry != NULL)
    {
	if(entry->esp_addr != esp_addr)
	{
	    entry = entry->next;
	    continue;
	}// end of if(entry)

	tmp_expr1 = vc_iffExpr( HHui_VC,
				path_expr,
				entry->cur_global_expr
			      );

	vc_push(HHui_VC);
	qresult   = vc_query( HHui_VC,
			      tmp_expr1
			    );
	vc_pop(HHui_VC);

	// checks for VALIDITY !
	if(qresult == 1)
	{
	    return entry->callsite_id;
	}// end of if(qresult)
	
	entry = entry->next;
    }// end of while{entry}

    // term_printf("No desired callsite found !\n");
    return 0;
}// end of find_specific_func_callsite( )



#ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
int find_entry_in_func_summ_snapshot_list( uint32_t		       func_addr,
					   uint32_t 		       caller_addr,
					   uint32_t 		       esp_addr,
					   func_summ_snapshot_list_t * fss_list
					 )
{
    func_summ_snapshot_entry_t * entry = fss_list->head;
    while(entry != NULL)
    {
	if( ( (entry->caller_addr == caller_addr) &&
	      (entry->func_addr == func_addr)
	    ) &&
	    (entry->esp_addr == esp_addr)
	  )
	{
	    return entry->callsite_id;
	}// end of if(entry)

	entry = entry->next;
    }// end of while{entry}
    
    return 0;
}// end of find_entry_in_func_summ_snapshot_list( )
#endif


/* invoked at general_function_summary_begin( ) when a new callsite of 
   a interested function 'func_addr' is introduced.
*/
void add_entry_2_func_summ_snapshot_list( // void *		      func_entry,
					  uint32_t 		      func_addr,
					  uint32_t		      esp_addr,

					  #ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
					  uint32_t 		      caller_addr,
					  #endif

					  uint32_t 		      callsite_id, 
					  HExpr			      cur_global_expr,
					  // allocated at general_function_summary_begin( )

					  func_summ_snapshot_list_t * fss_list
					)
{
    func_summ_snapshot_entry_t * entry = (func_summ_snapshot_entry_t *)malloc(sizeof(func_summ_snapshot_entry_t));
    // entry->func_entry	   = func_entry;
    entry->callsite_id     = callsite_id;
    entry->func_addr       = func_addr;
    entry->esp_addr	   = esp_addr;

#ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
    entry->caller_addr	   = caller_addr;
#endif

    entry->cur_global_expr = cur_global_expr;
    entry->next	           = NULL;

    // satisfied pre-post condition pair list
    expr_cond_list_init( &(entry->H_expr_cond_list) );

#ifdef H_FUNC_CALLING_SEQUENCE_RECORD
    // function calling sequece
    add_entry_2_func_calling_list_init(entry);
#endif

    if(fss_list->head == NULL)
    {
	fss_list->head = entry;
	fss_list->end  = entry;
    }
    else
    {
	(fss_list->end)->next = entry;
	fss_list->end	      = entry;
    }// end of if(fss_list.head)

    fss_list->count = fss_list->count + 1;    
}// end of add_entry_2_func_summ_snapshot_list( )


int func_summ_callsite_check_pre_post_condition( void			  * func_entry,
						 uint32_t		    callsite_id,
						 h_condition_entry_t 	  * cond_entry
					       )
{
    func_summ_snapshot_entry_t * entry = ( ((function_summary_entry_t *)func_entry)->fss_list ).head;

    while(entry != NULL)
    {
	if(callsite_id == entry->callsite_id)
	{
	    if( find_expr_cond_in_condlist( cond_entry,
				            &(entry->H_expr_cond_list)
				          ) == 1
	      )
	    {
		return 1;
	    }
	    else
	    {
		return 0;
	    }// end of if(find_expr_cond_in_condlist)
	}// end of if(callsite_id)

	entry = entry->next;
    }// end of while{entry}

    return 0;
}// end of func_summ_callsite_check_pre_post_condition( )



/* suppose for a snapshot, we've calculated a new pre-post function condition pair. 
   We have to lookup every currently existing callsite of this function trying to 
   apply this condition.

   invoked at general_function_summary_end( ) when a new pre-post condition pair 
   is calculated
*/
void func_summ_callsite_check_and_apply_pre_post_condition( void		* func_entry,
							    uint32_t		  immune_callsite_id,
							    h_condition_entry_t * cond_entry
							  )
{
    char name[256];
    int  count = 0;

    func_summ_snapshot_entry_t * entry = ( ((function_summary_entry_t *)func_entry)->fss_list ).head;

    while(entry != NULL)
    {
	if(immune_callsite_id != entry->callsite_id)
	{
	    if(entry->callsite_id == 2)
	    {
		term_printf("callsite_id == 2\n");
	    }// end of if(entry->callsite_id)

	    if( find_expr_cond_in_condlist( cond_entry,
				            &(entry->H_expr_cond_list)
				          ) == 1
	      )
	    {
		entry = entry->next;
		continue;
	    }
	    else
	    {
		/*
		if(entry->callsite_id == 4)
		{
		    term_printf("entry->callsite_id = 4\n");
		}// end of if(entry)
		*/

		count = sprintf( name,
		 	         "func_%x_snapshot_%x",
		    		 entry->func_addr,
		    		 entry->callsite_id
		   	       );
		name[count] = '\0';


		// HVM-state list management		
		/* ------------------------------------------------------------------------------------------- */
		/* Here, we try to remove out or truncate off those previously stored branches in this calling 
		   context if we are sure that they do satisfy this newly calculated pre-post condition.
		*/ 					
		tst_del_HVM_func_summ_snapshot_entry( entry->func_addr,
						      entry->callsite_id,
						      cond_entry
						    );

		/* we should now apply this newly calculated pre-post condition --- just push the general saved 
		   snapshot into the global queue for later scheduling !
		*/
		add_HVM_func_summ_snapshot_entry( func_entry,
						  entry->func_addr,
						  entry->callsite_id,
						  cond_entry,
						  name,
					    	  entry->cur_global_expr // constraint formula for this branch
				          	);

		// insert this 'cond_entry' into the cond_list of this call-site to denote satisfication !
		add_condentry_2_func_summ_snapshot_entry( func_entry,
					                  entry->callsite_id,
					                  cond_entry
					                );	    	        		
		/* ------------------------------------------------------------------------------------------- */
		// HVM-state list management

	    }// end of if(find_expr_cond_in_condlist)
	}
	else
	{
	    // insert this 'cond_entry' into the cond_list of this call-site to denote satisfication !
	    add_condentry_2_func_summ_snapshot_entry( func_entry,
					              entry->callsite_id,
					              cond_entry
					            );	    
	}// end of if(callsite_id)
	
	entry = entry->next;
    }// end of while{entry}

}// end of func_summ_callsite_apply_pre_post_condition( )



/* Encountering a new callsite with a path of a calculated condition, we would check for
   all previously calculated pre-post condition pairs' availability on this callsite so 
   as to force traversal over other concrete paths. We should also denote this condtion as
   calculated for this callsite. 

   invoked at general_function_summary_begin( ).
   
*/
void func_postpone_and_apply_calculated_conditions( void * 		  func_entry,
						    uint32_t 		  callsite_id,
						    h_condition_entry_t * condition // satisfied condition
					 	  )
{   
    func_summ_snapshot_entry_t * entry      = ( ((function_summary_entry_t *)func_entry)->fss_list ).head;
    h_condition_list_t         * cond_list  = &( ((function_summary_entry_t *)func_entry)->summary_conditions );
    h_condition_entry_t	       * cond_entry = cond_list->head; 

    HExpr tmp_expr = NULL;
    int	  qresult  = 0;
    char  snapshot_name[256];
    int   count    = 0;

    if(callsite_id == 2)
    {
	term_printf("callsite_id == 2\n");
    }// end of if(callsite_id)

    if(cond_entry == NULL)
    {
	return;
    }// end of if(cond_entry)

    count = sprintf( snapshot_name,
		     "func_%x_snapshot_%x",
		     ( (function_summary_entry_t *)func_entry )->vaddr,
		     callsite_id
		   );
    snapshot_name[count] = '\0';


    while(entry != NULL)
    {
	if(callsite_id == entry->callsite_id)
	{
	    cond_entry = cond_list->head; 	
	    while(cond_entry != NULL)
	    {

#ifndef H_COARSE_TESTING_CONDITION
    #define H_COARSE_TESTING_CONDITION
#endif


#ifdef H_COARSE_TESTING_CONDITION
		qresult  = 0;
		tmp_expr = vc_iffExpr( HHui_VC,
				       cond_entry->pre_condition,
				       condition->pre_condition
				     );
		vc_push(HHui_VC);
		qresult  = vc_query( HHui_VC,
				     tmp_expr
				   );
		vc_pop(HHui_VC);

		if( (qresult != 1) &&
#else
		if( (cond_entry != condition) &&
#endif
		    (cond_entry->calculated != 0)
		  )
		{
		    // make sure that this cond_entry hasn't been applied to this callsite !
		    if( find_expr_cond_in_condlist( cond_entry,
				       		    &(entry->H_expr_cond_list)
				     		  ) != 0 
		      )
		    {
			cond_entry = cond_entry->next;
			continue;
		    }// end of if()

		    // we should now build up an entry for future scheduling over this callsite !
		    add_HVM_func_summ_snapshot_entry( func_entry,
						      ( (function_summary_entry_t *)func_entry )->vaddr,
						      callsite_id,
						      cond_entry,
						      snapshot_name,
					    	      entry->cur_global_expr
				          	    );

		    // insert this 'cond_entry' into the cond_list of this call-site to denote satisfication !    
		    add_condentry_2_func_summ_snapshot_entry( func_entry,
							      callsite_id,
					   		      cond_entry
					  		    );

		}// end of if(cond_entry)

	        cond_entry = cond_entry->next;
	    }// end of while{cond_entry}
	}// end of if(callsite_id)

	entry = entry->next;
    }// end of while{entry}    

    // insert this 'cond_entry' into the cond_list of this call-site to denote satisfication !    
    add_condentry_2_func_summ_snapshot_entry( func_entry,
					      callsite_id,
					      condition
					    );
}// end of func_postpone_and_apply_calculated_conditions( )



void func_summ_pre_save( uint32_t func_addr,
			 uint32_t callsite_id
		       )
{
    char     name[256];
    int      count    = 0;
    uint32_t cur_eip  = 0;
    uint32_t next_eip = 0;

    count = sprintf( name,
		     "func_%x_snapshot_%x",
		     func_addr,
		     callsite_id
		   );
    name[count] = '\0';

    do_savevm(name);    
}// end of func_summ_pre_save( )


#ifdef H_FUNC_SUMM_RESULT_DEBUG_DUMP
void func_summ_callsite_cond_append_2_file( uint32_t func_addr,
					    uint32_t cur_id,
					    uint32_t callsite_id,
					    HExpr    pre_expr
					  )
{
    char   buffer[1024];
    int    count    = 0;
    int    fd       = 0;
    char * str_expr = NULL;
    int    length   = 0;

    umask(0);

    count = sprintf( buffer,
		     "./func_callsite/func_%x_callsite_%d",
		     func_addr,
		     callsite_id
		   );
    buffer[count] = '\0';

    if(cur_id == 1)
    {
        fd = open( buffer,
	           (O_CREAT | O_RDWR),
	           (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	         );
    }
    else
    {
        fd = open( buffer,
	           (O_RDWR | O_APPEND)
	         );
    }// end of if(cur_id)

    str_expr = exprString(pre_expr);
    count = sprintf( buffer,
		     "precondition_%d:\n",
		     cur_id
		   );
    buffer[count] = '\0';    
    write( fd,
	   buffer,
	   count
	 );

    length = strlen(str_expr);

    write( fd,
	   str_expr,
	   length
	 );

    write( fd,
	   "\n",
	   1
	 );

    free(str_expr);

    close(fd);
}// end of func_summ_callsite_cond_append_2_file( )



void func_summ_callsite_cond_dump(void * func_entry)
{
    func_summ_snapshot_entry_t * entry      = ( ((function_summary_entry_t *)func_entry)->fss_list ).head;
    expr_cond_entry_t	       * cond_entry = NULL;

    char   buffer[1024];
    int    count    = 0;
    int    fd       = 0;
    char * str_expr = NULL;
    int    i	    = 1;

    umask(0);

    while(entry != NULL)
    {
        count = sprintf( buffer,
			 "./func_callsite/dbg_func_%x_callsite_%d",
			 ( (function_summary_entry_t *)func_entry )->vaddr,
			 entry->callsite_id
		       );
	buffer[count] = '\0';

        fd = open( buffer,
	           (O_CREAT | O_RDWR),
	           (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	         );

	cond_entry = (entry->H_expr_cond_list).head;
	
	i = 1;
	while(cond_entry != NULL)
	{
	    str_expr = exprString( ( (h_condition_entry_t *)(cond_entry->expr_cond) )->pre_condition );
	    count = sprintf( buffer,
			     "precondition_%d:\n%s\n",
			     i,
			     str_expr
			   );
	    buffer[count] = '\0';

	    write( fd,
		   buffer,
		   count
		 );

	    free(str_expr);

	    i = i + 1;
	    cond_entry = cond_entry->next;
	}// end of while{cond_entry}

        close(fd);

	entry = entry->next;
    }// end of while{entry}    
}// end of func_summ_callsite_cond_dump( )

#endif

















