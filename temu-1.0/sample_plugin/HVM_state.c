#include <stdio.h>
#include <inttypes.h>
#include <malloc.h>
#include <string.h>


#include "../TEMU_lib.h"
#include "../TEMU_main.h"

#include "hc_interface.h"
#include "HVM_state.h"

#include "branch_update_VM.h"
#include "expr_condition.h"
#include "function_summary.h"
#include "taintcheck_hook.h"


#include "H_test_config.h"

#ifdef H_DEBUG_TEST
extern H_predicate_count;
#endif

extern HVC     HHui_VC;
extern HExpr   path_Expr;
extern HExpr * func_precondition_expr; 


extern PHVM_param_t  param;

extern uint32_t HHui_target_pid;

extern plugin_interface_t my_interface;


#ifdef H_FUNC_SUMM_RESULT_DEBUG_DUMP
int  loaded_snapshot_count = 0;
char curr_snapshot_name[100];
#endif


/*
#ifndef STR_VMENTRY
    #define STR_VMENTRY "VM_STATE_ENTRY_"
#endif
*/


// queue maintaining all the saved VM states
HVM_state_list_t  vm_list;
static uint32_t hvm_count = 1;

// functions
/* ------------------------------------------------------------------------------------------------------ */
void init_vm_state_list( )
{
    vm_list.head  = NULL;
    vm_list.end   = NULL;

    vm_list.count = 0; 


/*
    // total number of the snapshots our system maintained currently
    my_interface.snapshots_num   = 0;

    // id of the current snapshot being analyzed 
    my_interface.cur_snapshot_id = 0;
 */

}// end of init_vm_state_list( )


#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
/* Here, we try to remove out or truncate off those previously stored branching states in this 
   calling context if we are sure that they do satisfy this newly calculated pre-post condition.
*/
void tst_del_HVM_func_summ_snapshot_entry( uint32_t		 func_addr,
					   uint32_t		 callsite_id,
					   h_condition_entry_t * cond_entry  // a newly calculated pre-post condition !
					 )
{
    PHVM_state_entry_t entry  = vm_list.head;
    PHVM_state_entry_t entry1 = NULL;

    HExpr tmp_expr1 = NULL;
    HExpr tmp_expr2 = NULL;
    HExpr tmp_expr3 = NULL;
    HExpr tmp_expr4 = NULL;
    HExpr tmp_expr5 = NULL;

    int   qresult   = 0;

    int i     = 0;
    int j     = 0;
    int count = 0;

    HExpr * actual_param_exprs = NULL;
    HExpr * formal_param_exprs = NULL;

    int b_middle = 0;
/*
    uint8_t * content_buf = NULL;
    uint64_t  tcbmap      = 0;
    uint32_t  length      = 0;
    
    content_buf = func_load_stackparams( uint32_t   func_addr,
			    uint32_t   callsite_id,
			    uint8_t ** ret_buf,
			    uint32_t * length,
			    uint64_t * tcbmap
			  )
*/

    while(entry != NULL)
    {
	// the same calling-context !
	if( (func_addr == entry->func_addr) &&
	    (callsite_id == entry->callsite_id)
	  )
	{
	    // "pid_%d_HHui_snapshot_%d" vs "func_%x_snapshot_%x"
	    if( (entry->state_name)[0] == 'p')
	    {
		/* test if this snapshot's local predicate does satisfy the 'pre_condition' of 'cond_entry'.
		   if so, we would truncate it into the other sub-part which do no satisfy 'cond_entry' !
		*/
		vc_push(HHui_VC);
		tmp_expr1 = vc_impliesExpr( HHui_VC,
					    cond_entry->pre_condition,
				   	    (entry->cond_entry)->pre_condition					    
				          );
		// checks for VALIDITY !
		qresult   = 0;
		qresult   = vc_query( HHui_VC,
				      tmp_expr1
				    );
		vc_pop(HHui_VC);

		
		if(qresult == 1)
		{
		    /* Now we conclude that 'cond_entry' is a possibility for this branch, so we prohibited
		       it, driving it to the other path.

		       de-facto  ----  !(A and B) and A == A and !B
		    */
		    tmp_expr2 = vc_notExpr( HHui_VC,
					    cond_entry->pre_condition
					  );
		    tmp_expr3 = vc_andExpr( HHui_VC,
					    tmp_expr2,
					    (entry->cond_entry)->pre_condition
					  );
		    tmp_expr3 = vc_simplify( HHui_VC,
					     tmp_expr3
					   );

		    // checks for EXISTENCE !
		    tmp_expr4 = vc_notExpr( HHui_VC,
					    tmp_expr3
					  );

		    vc_push(HHui_VC);
		    qresult = 0;
		    qresult = vc_query( HHui_VC,
					tmp_expr4
				      );
		    vc_pop(HHui_VC);

		    if(qresult == 0)
		    {
			entry->local_path_expr = tmp_expr3;

			// update the snapshot's actual precondition so as to drive a new concrete execution !
		        /* ------------------------------------------------------------------------------------ */
// postpone variable substitution until HHui_vm_loadcb( ) !
/* 
			count = 0;
			for(i = 0; i < ( (function_summary_entry_t *)(entry->func_entry) )->argsize; i = i + 1)
			{
			    if( (entry->stack_param_tcbmap & (1 << i)) != 0 )
			    {
				count = count + 1;
			    }// end of if(entry->stack_param_tcbmap)
			}// end of for{i}

			actual_param_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
			formal_param_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
			
			for(i = 0, j = 0; i < ( (function_summary_entry_t *)(entry->func_entry) )->argsize; i = i + 1)
			{
			    if( (entry->stack_param_tcbmap & (1 << i)) != 0 )
			    {
				formal_param_exprs[j] = ( ( (function_summary_entry_t *)(entry->func_entry) 
							  )->stackarg_exprs
							)[i];

				actual_param_exprs[j] = ( ( (function_summary_entry_t *)(entry->func_entry) 
							  )->real_stackargs
							)[i].h_expr;

				j = j + 1;
			    }// end of if(entry->stack_param_tcbmap)
			}// end of for{i}

			tmp_expr5 = H_var_substitute_4expr( HHui_VC,
	 			   		 	    tmp_expr3,
						     	    formal_param_exprs,
						            actual_param_exprs,
						     	    count,
						            NULL // H_TEMU_printExpr
				      		          );

			// (entry->cond_entry)->pre_condition = tmp_expr5;
			// entry->local_path_expr = tmp_expr5;

			free(actual_param_exprs);
			free(formal_param_exprs);
*/
		        /* ------------------------------------------------------------------------------------ */
			// update the snapshot's actual precondition so as to drive a new concrete execution !
		    }
		    else
		    {
			// delete this snapshot from list
		        /* ------------------------------------------------------------------------------------ */
			b_middle = 0;

		        if(entry == vm_list.head)
		        {
			    vm_list.head         = entry->next;
			    (vm_list.head)->prev = NULL;
		        }
		        else if(entry == vm_list.end)
		        {
			    vm_list.end	         = entry->prev;
			    (vm_list.end)->next  = NULL;
		        }
		        else
		        {
			    entry1->next 	 = entry->next;
			    (entry->next)->prev  = entry1;			    
			    b_middle = 1;
		        }// end of if(entry)		
	
		        // do_delvm(entry->state_name);
			
		        free(entry->state_name);
		        free(entry);	

			vm_list.count = vm_list.count - 1;

			if(b_middle == 1)
			{
			    entry = entry1->next;
			    continue;
			}// end of if(b_middle)
		        /* ------------------------------------------------------------------------------------ */
		        // delete this snapshot from list

		    }// end of if(qresult == 0)		    		    
		}// end of if(qresult == 1)

	    }// end of if(entry)
	}// end of if(callsite_id)

	entry1 = entry;
	entry  = entry->next;
    }// end of while{entry}
    
}// end of tst_del_HVM_func_summ_snapshot_entry( )
#endif


#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK    
PHVM_state_entry_t add_HVM_func_summ_snapshot_entry( void		 * func_entry,
						     uint32_t		   func_addr,
						     uint32_t		   callsite_id,
						     h_condition_entry_t * cond_entry,
						     char 		 * snapshot_name,
						     HExpr       	   global_path_expr
				          	   )
{       
    int i     = 0;
    int j     = 0;
    int count = 0;
 
    HExpr * formal_param_exprs = NULL;
    HExpr * actual_param_exprs = NULL;

    PHVM_state_entry_t entry = (PHVM_state_entry_t)malloc(sizeof(HVM_state_entry_t)) ;
    if(entry == NULL)
    {
	term_printf("struct HVM_state_entry_t allocation fault !\n");
	return NULL;
    }// end of if( )

    entry->next = NULL;
    entry->prev = NULL;

    entry->global_path_expr = global_path_expr;
    entry->cond_entry	    = cond_entry;

    count = strlen(snapshot_name);
    entry->state_name = (char *)malloc( sizeof(char) * (count + 1));
    count = sprintf( entry->state_name,
		     "%s",
	    	     snapshot_name
	  	   );
    (entry->state_name)[count] = '\0';

    entry->is_pre_post_apply  = 1;
    entry->callsite_id        = callsite_id;
    entry->func_addr	      = func_addr;
    entry->func_entry	      = func_entry;
    entry->stack_param_tcbmap = (uint64_t)( ( (function_summary_entry_t *)func_entry
					    )->real_stackarg_tcbmap
					  );


    // build up 'local_path_expr' so as to constraint the concrete values !
    /* ------------------------------------------------------------------------------------ */
    entry->local_path_expr = cond_entry->pre_condition;
// postpone variable substitution until HHui_vm_loadcb( ) !
/*
    count = 0;
    for(i = 0; i < ( (function_summary_entry_t *)func_entry )->argsize; i = i + 1)
    {
	if( (entry->stack_param_tcbmap & (1 << i)) != 0 )
	{
	    count = count + 1;
	}// end of if(entry->stafck_param_tcbmap)
    }// end of for{i}
 
    actual_param_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
    formal_param_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
			
    for(i = 0, j = 0; i < ( (function_summary_entry_t *)func_entry )->argsize; i = i + 1)
    {
	if( (entry->stack_param_tcbmap & (1 << i)) != 0 )
	{
	    formal_param_exprs[j] = ( ( (function_summary_entry_t *)func_entry 
				      )->stackarg_exprs
				    )[i];

	    actual_param_exprs[j] = ( ( (function_summary_entry_t *)func_entry
				      )->real_stackargs
				    )[i].h_expr;

	    j = j + 1;
	}// end of if(entry->stack_param_tcbmap)
    }// end of for{i}

    entry->local_path_expr = H_var_substitute_4expr( HHui_VC,
   	 			   		     cond_entry->pre_condition,
						     formal_param_exprs,
						     actual_param_exprs,
						     count,
						     NULL // H_TEMU_printExpr
				      		   );


    free(actual_param_exprs);
    free(formal_param_exprs);
*/    
    /* ------------------------------------------------------------------------------------ */


    if(vm_list.head == NULL)
    {
	vm_list.head = entry;	
	vm_list.end  = entry;
    }
    else
    {
	vm_list.end->next = entry;
	entry->prev	  = vm_list.end;
	vm_list.end       = entry;

	
    }// end of if( )

    vm_list.count = vm_list.count + 1;

    return entry;

}// end of add_HVM_func_summ_snapshot_entry( )
#endif



PHVM_state_entry_t add_HVM_state_entry( HExpr                 local_path_expr,  // actual-param's local constraint formula
					h_condition_entry_t * cond_entry,
					HExpr		      global_path_expr, // constraint formula for this branch
					uint32_t	      branch_addr 	// first instruction's VA in this branch
				      )
/*
PHVM_state_entry_t add_HVM_state_entry( HExpr    path_expr,  // constraint formula for this branch
				        uint32_t branch_addr // first instruction's VA in this branch
				      )
*/
{    
    char     snapshot_name[1000];
    int	     snapshot_name_len;
    uint32_t org_eip;
    
    snapshot_name_len = sprintf( snapshot_name,
	     			 "pid_%d_HHui_snapshot_%d",
				 // vm_list.count
				 HHui_target_pid,
				 hvm_count 
	   		       );

    hvm_count = hvm_count + 1;

    snapshot_name[snapshot_name_len] = (char)0;


    PHVM_state_entry_t entry = ( PHVM_state_entry_t )malloc( sizeof( HVM_state_entry_t ) ) ;
    if(entry == NULL)
    {
	term_printf("struct HVM_state_entry_t allocation fault !\n");
	return NULL;
    }// end of if( )

    entry->prev	= NULL;
    entry->next = NULL;
    // entry->path_expr     = path_expr;

    entry->global_path_expr = global_path_expr;

    entry->local_path_expr  = local_path_expr;
    entry->cond_entry	    = cond_entry;

    entry->state_name    = (char *)malloc( sizeof(char) * (snapshot_name_len + 1));
    entry->monitored_eip = branch_addr;


#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK 
    entry->is_pre_post_apply = 0;

    entry->func_entry  = my_interface.cur_func_summ_entry;
    entry->func_addr   = 0;
    entry->esp_base    = 0;
    entry->callsite_id = 0;

    if(my_interface.cur_func_summ_entry != NULL)
    {
        entry->callsite_id = ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) )->curr_callsite_id;
	entry->func_addr   = ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) )->vaddr;
	entry->esp_base    = ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) )->stack_base;
    }// end of if(my_interface)
#endif

    if(entry->state_name == NULL)
    {
	term_printf("struct state_name for HVM_entry allocation fault !\n");
	return NULL;
    }// end of if( )


    strcpy( entry->state_name,
	    snapshot_name
	  );


    TEMU_read_register( eip_reg,
			&org_eip
		      );

    // HHui : update pc for the other path for future SYM-EXE's concrete environment's initialization !
    /* ----------------------------------------------------------------------------------------------------- */

    TEMU_write_register( eip_reg,
			 &branch_addr
		       ); 

    /* ----------------------------------------------------------------------------------------------------- */
   
    /*
    term_printf( "saved global expression : %s\n",
		 exprString(global_path_expr)
	       );
    */
    // *TEMU_cpu_eip = 

    // save the VM's states !
    do_savevm(entry->state_name);

    TEMU_write_register( eip_reg,
			 &org_eip
		       );


    if(vm_list.head == NULL)
    {
	vm_list.head = entry;	
	vm_list.end  = entry;
    }
    else
    {
	vm_list.end->next = entry;
	entry->prev 	  = vm_list.end;
	vm_list.end       = entry;
    }// end of if( )

    vm_list.count = vm_list.count + 1;

    return entry;
}// end of add_HVM_state_entry( )



void Delete_HVM_state_list( )
{
    if(vm_list.count == 0)
    {
	return;
    }// end of if( ) 
	
    PHVM_state_entry_t entry = (vm_list.head)->next;

    while(vm_list.head != NULL)
    {
	free(vm_list.head) ;
	vm_list.head = entry;
		
	if(entry == NULL)
	{
	    break;
	}// end of if( )

	entry = (vm_list.head)->next;
    }// end of while{ }
	
	//free(HHui_module_list);
	//HHui_module_list = NULL;

    vm_list.count = 0;	
    vm_list.head  = NULL;
    vm_list.end   = NULL;

}// end of Delete_HVM_state_list( )



/*
void BFS_restore_HVM_state_from_snapshot( HVC     hvc,
					  HExpr * path_expr // [ output ] : restoring the path-constraint for this branch
					)
 */
void BFS_restore_HVM_state_from_snapshot( )
{
    if(vm_list.count == 0)
    {
	// term_printf("branching snapshot list is now empty !\n");
	return;
    }// end of if( )

    PHVM_state_entry_t entry = vm_list.head;

    /*
    // free entry from list
    vm_list.head  = (vm_list.head)->next;
    vm_list.count = vm_list.count - 1;
    // entry->next = NULL;

    */
    
    term_printf( "loading vm --- name = %s\n",
		 entry->state_name
	       );

    // *path_expr = entry->path_expr;

    do_loadvm(entry->state_name);

    // term_printf("branch updated !\n");    

    // free(entry);

}// end of BFS_restore_HVM_state_from_snapshot( )



/* Now just remain for future extension
 */
void hvm_savecb( )
{
    
    
    
}// end of hvc_savecb( )



/* callback to be registered for snapshot restoration
   in fact, it would be called when do_loadvm( ) is called
 */
/*
int hvm_loadcb( QEMUFile * f,
		void     * opaque,
		int	   version_id
	      )
 */
void HHui_vm_loadcb( )
{
    int i     = 0;
    int j     = 0;
    int count = 0;
    HExpr * formal_param_exprs = NULL;
    HExpr * actual_param_exprs = NULL;

    char * tmp_str  = NULL;
    HExpr  tmp_expr = NULL;

    if(vm_list.count == 0)
    {
	term_printf("branching snapshot list is now empty !\n");
	return ; // 0;	
    }// end of if( )


    HVC hvc = *( (HVC *)( param->hvc
			) 
	       );
  
    PHVM_state_entry_t entry = vm_list.head;

    path_Expr = entry->global_path_expr;    
    

#ifdef H_FUNC_SUMM_RESULT_DEBUG_DUMP
    int tmp_count = 0;

    loaded_snapshot_count = loaded_snapshot_count + 1;
    tmp_count = sprintf( curr_snapshot_name,
			 "%s",
		         entry->state_name
		       );
    curr_snapshot_name[tmp_count] = '\0';    
#endif


    /*
    tmp_str = exprString(path_Expr);
    term_printf( "global expr is %s\n",
		 tmp_str
	       );
    free(tmp_str);
    */

#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK   
    if(entry->is_pre_post_apply != 0)
    {
	func_precondition_expr = &( (entry->cond_entry)->pre_condition
				  );

	( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) 
	)->curr_post_condition = entry->cond_entry;

	my_interface.pre_post_cond_snapshot = 1;

	if(entry->local_path_expr != NULL)
	{
            count = 0;
            for(i = 0; i < ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) )->argsize; i = i + 1)
            {
	        if( (entry->stack_param_tcbmap & (1 << i)) != 0 )
		{
	    	    count = count + 1;
		}// end of if(entry->stafck_param_tcbmap)
    	    }// end of for{i}
 
 	    actual_param_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
    	    formal_param_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
			
    	    for(i = 0, j = 0; i < ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) )->argsize; i = i + 1)
    	    {
		if( (entry->stack_param_tcbmap & (1 << i)) != 0 )
		{
	    	    formal_param_exprs[j] = ( ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry)
				              )->stackarg_exprs
				            )[i];

	   	    actual_param_exprs[j] = ( ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry)
				  	      )->real_stackargs
				    	    )[i].h_expr;
	    	    j = j + 1;
	        }// end of if(entry->stack_param_tcbmap)
    	    }// end of for{i}

	    entry->local_path_expr = H_var_substitute_4expr( HHui_VC,
   	 				   		     entry->local_path_expr,
							     formal_param_exprs,
							     actual_param_exprs,
							     count,
							     NULL // H_TEMU_printExpr
					      		   );
	    free(formal_param_exprs);
	    free(actual_param_exprs);

	}// end of if(entry->local_path_expr != NULL)

	goto HVM_UPDATE_TOTAL_VM_STATES;
    }// end of if(entry)
  
    my_interface.pre_post_cond_snapshot = 0;   
#endif


#ifdef HHUI_FUNC_SUMMARY_ENABLED
    /* ---------------------------------------------------------------------------------------------------------- */
    /* Here, we check if this snapshot's calling context would satisfy any precondition 
       calculated in some previously loaded snapshot's execution.

       if so, we switch to that precondition and use that summary; otherwise we should 
       continue with our own so as to create a new precondition.
    */
    if( ( entry->cond_entry != NULL ) && 
	( my_interface.cur_func_summ_entry != NULL )	
      )
    {	
	/* notice, if func_summ_test_precondition( ) returns 1, 'entry->curr_post_condition' would be set to  
	   the corresponding 'cond_entry' !
	*/
	
#ifndef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
	if( func_summ_test_precondition(my_interface.cur_func_summ_entry) == 1 )
	/*
	if( func_summ_test_symbolic_precondition( entry->cond_entry,
						  &( ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) 
						     )->
						)  
	  )
	*/
	{
	    delete_entry_from_h_condition_list( &( ( (function_summary_entry_t *) (my_interface.cur_func_summ_entry)
						   )->summary_conditions 
						 ), 
					        entry->cond_entry
				              );

	    // denoting that we would utilize that summary afterwards !	    
	    my_interface.func_postcondition_enable = 1;
	}
	else
	{
#endif
	    ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) 
	    )->curr_post_condition = entry->cond_entry;

#ifndef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
	}// end of if(func_summ_test_precondition)		
#endif	
	func_precondition_expr = &( ( ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) 
			 	      )->curr_post_condition
				    )->pre_condition 
				  );
    }// end of if(entry)
    /* ---------------------------------------------------------------------------------------------------------- */
#endif


HVM_UPDATE_TOTAL_VM_STATES:
#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(func_precondition_expr != NULL)
    {
	func_taint_memory_record_list_restore( &( ( ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) 
				 	            )->curr_post_condition
					          )->post_mem_cond
					 	)
					     );
    }// end of if(func_precondition_expr)


    my_interface.is_in_focused_module = 0;

    // if(entry->local_path_expr == NULL)
    if( (func_precondition_expr == NULL) || 
	(*func_precondition_expr == NULL)
      )
    {
	// term_printf("local expr is NULL\n");

        branch_update_VM_total_states( hvc,
			   	       path_Expr // entry->global_path_expr
				     );
    }
    else
    {
#else
	if(entry->local_path_expr != NULL)
	{
	    branch_update_VM_total_states( hvc,
			     	           vc_andExpr( HHui_VC,
						       path_Expr, 
						       entry->local_path_expr
						     )
				         );
	}
	else
	{
	    branch_update_VM_total_states( hvc,
			     	           path_Expr // tmp_expr
				         );
	}// end of if(entry->local_path_expr)
#endif

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    }// end of if(func_precondition_expr)       
#endif
    // Now free the entry from vm-list
    /* --------------------------------------------------------------------------------------- */
    vm_list.head  = (vm_list.head)->next;
    vm_list.count = vm_list.count - 1;
    entry->next   = NULL;

    free(entry->state_name);
    free(entry);
    /* --------------------------------------------------------------------------------------- */

                
    return ; // 0;
}// end of hvm_loadcb( )



int vm_state_list_is_empty( )
{    
    if(vm_list.count == 0)
    {
	return 1;
    }// end of if( )

    return 0;
}// end of if( )

/* ------------------------------------------------------------------------------------------------------ */
// functions






