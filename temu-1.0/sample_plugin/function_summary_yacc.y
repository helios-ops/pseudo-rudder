%{
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <malloc.h>
#include <string.h>
#include <inttypes.h>

#include "hc_interface.h"
#include "../shared/hookapi.h"
#include "H_taint_record.h"
#include "../taintcheck.h"
#include "H_hookdata.h"
#include "function_summary.h"
#include "h_atoi.h"
#include "module_notify.h"
#include "../TEMU_main.h"
#include "stp_variables.h"
#include "H_taint_record.h"

#include "../TEMU_lib.h"
#include "../TEMU_main.h"

#include "expr_condition.h"
#include "func_summ_hook.h"

#include "func_dump_stackparam.h"


// here are several global defination switches
#include "H_test_config.h"

#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
    #include "func_summ_snapshot.h"
#endif

#ifdef HH_INTERTESTED_FUNC_ANALYSIS
    #include "interested_func_analysis.h"
#endif

extern HVC	HHui_VC;
extern uint32_t HHui_target_cr3;

extern plugin_interface_t my_interface;
// is_in_focused_func



/* =================================================================================================================== */
/* NOTE: when function summary mechanism is adpted, 'path_Expr' would be suspended for calculating at the hook-point 
	 of the head a particular hooked function, during which 'func_precondition_expr' would be calculated for CJmps
	 instead. At the end of the hooked function, the literals of the calculated formula 'func_precondition_expr'
	 would be substituted by those corresponding actual parametric taints, with the derived new formula instance 
	 appended to the tail of 'path_Expr' representing the SYM-EXE result of this execution instance.
 */


// function's local path-constraint expressed through function's formal parametres
extern HExpr * func_precondition_expr; 

/* function's local path-constraint expressed through function's actual parametres.
   ( effective only when the function is calculated for a new pre-post condition-pair )
*/
extern HExpr   func_local_ending_expr;

// denoting current global path-constraint
extern HExpr   path_Expr;
/* =================================================================================================================== */




function_summary_entry_t * h_func_summary_entry;
struct module_entry *      h_module;

static uint32_t   module_offset = 0;

uint32_t HHui_tmp_vaddr   = 0;
char *   HHui_tmp_fname   = NULL;
int	 HHui_tmp_findex  = -1;
uint32_t HHui_tmp_argsize = 0;
/*
char h_reg_TEMU_index[8] = { R_EAX,
			     R_ECX,
			     R_EDX,
			     R_EBX,
			     R_ESP,
			     R_EBP,
			     R_ESI,
			     R_EDI
			   }; 
*/

static char * str_regname[ ] = { "eax",
				 "ecx",
				 "edx",
				 "ebx",
				 "esp",
				 "ebp",
				 "esi",
				 "edi",
				 NULL
			       };
static uint32_t TEMU_tcregidx[ ] = { R_EAX,
				     R_ECX,
				     R_EDX,
				     R_EBX,
				     R_ESP,
				     R_EBP,
				     R_ESI,
				     R_EDI
			  	   };

static char h_databuf[10];



extern PMODULE_INFO_LIST HHui_module_list;

/* ============================================================================================= */	
/* when function's local SYM-EXE encounters a CJmp, branch-save mechanism would be invoked. 
   All states of the current local analysis should be saved for future loading restoration.
   
   The current local analysis states include:
   1. all taint machine states (ensured by TEMU's taintcheck_load and taintcheck_save)
   2. the current global path constraint at the function's beginning and local path constraint 
   3. all actual parametres' taint states

   Here, we use snapshot-restoration technique to solve the above problems.
*/
void func_summ_taintcheck_save( QEMUFile * f,
				void     * opaque
			      )
{
    TEMU_CompressState_t state;
    // PMODULE_ENTRY	 m_entry = HHui_module_list.head;
    uint32_t separator = 0;

    function_summary_entry_t * func_entry = (function_summary_entry_t *)(my_interface.cur_func_summ_entry);

    if( TEMU_compress_open( &state, 
			    f
			  ) < 0
      )
    {
	return;
    }// end of if(TEMU_compress_open)


    TEMU_compress_buf( &state,
		       ( (uint8_t *)( &(my_interface.func_postcondition_enable) ) ),
		       4
		     );    

    // pointer to local path-constraint with regard to function's formal parametres
    TEMU_compress_buf( &state,
		       ( (uint8_t *)( &func_precondition_expr ) ),
		       4
		     );    
    if(func_precondition_expr == NULL)
    {
	return;
    }// end of if(func_precondition_expr)

    /*
    TEMU_compress_buf( &state,
	               ( (uint8_t *)(func_precondition_expr) ),
		       4
	   	     );    
    */

    // backtrace along the calling-sequences !
    while(func_entry != NULL)
    {
	// func_summary entry
        TEMU_compress_buf( &state,
		           ( (uint8_t *)&func_entry ),
		           4
		         );


// call-site ID
#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
        TEMU_compress_buf( &state,
		           (uint8_t *)( &(func_entry->curr_callsite_id) ),
		           4
		         );		
#endif

	// stack_base
        TEMU_compress_buf( &state,
		           (uint8_t *)( &(func_entry->stack_base) ),
		           4
		         );	

	// curr_post_condition	
	TEMU_compress_buf( &state,
		           (uint8_t *)( &(func_entry->curr_post_condition) ),
		           4
		         );	

	// last_func_postcondition_enable
	TEMU_compress_buf( &state,
		           (uint8_t *)( &(func_entry->last_func_postcondition_enable) ),
		           sizeof(int)
		         );	

	// actual stack parametres' taint states
	/* ------------------------------------------------------------------ */
        TEMU_compress_buf( &state,
		           (uint8_t *)( &(func_entry->argsize) ),
		           4
		         );	

	if(func_entry->argsize != 0)
	{
            TEMU_compress_buf( &state,
		               (uint8_t *)(&(func_entry->real_stackarg_tcbmap)),
		               8
		             );	
	    if(func_entry->real_stackarg_tcbmap != 0)
	    {
                TEMU_compress_buf( &state,
	  	                   (uint8_t *)(func_entry->real_stackargs),
		                   func_entry->argsize * sizeof(H_taint_record_t)
		                 );
	    }// end of if(func_entry->real_stackarg_tcbmap)
	}// end of if(func_entry->argsize)
	/* ------------------------------------------------------------------ */ // actual stack parametres


	// actual register parametres' taint states
	/* ------------------------------------------------------------------ */
        TEMU_compress_buf( &state,
		           (uint8_t *)(func_entry->real_regargs),
		           32 * sizeof(H_taint_record_t) 
		         );	

	TEMU_compress_buf( &state,
			   (uint8_t *)(&(func_entry->real_reg_tcbmap)),
			   4
			 );
	/* ------------------------------------------------------------------ */ // actual register parametres' taint states


/*
	// last func_summary entry
	TEMU_compress_buf( &state,
			   (uint8_t *)(&(func_entry->last_func)),
			   4
			 );	
*/
	func_entry = func_entry->last_func;
    }// end of while{m_entry}


    // signalling end
    TEMU_compress_buf( &state,
		       &separator,
		       4
		     );

    TEMU_compress_close(&state);

}// end of func_summ_taintcheck_save( )


int func_summ_taintcheck_load( QEMUFile * f,
			       void     * opaque,
  			       int	 version_id
			     )
{
    TEMU_CompressState_t state;
    uint32_t		 value;

    int i = 0;
   
    char * tmp_str = NULL;

    function_summary_entry_t * func_entry      = NULL;
    function_summary_entry_t * post_func_entry = NULL;

    if( TEMU_decompress_open( &state,
			      f
			    ) < 0
      )
    {
	return -EINVAL;
    }// end of if(TEMU_decompress_open)


/*
    // global path-constraint
    TEMU_decompress_buf( &state,
			 (uint8_t *)(&path_Expr),
			 4
		       );
*/

    TEMU_decompress_buf( &state,
		         ( (uint8_t *)( &(my_interface.func_postcondition_enable) ) ),
		         4
		       );    

    //  pointer to local path-constraint    
    TEMU_decompress_buf( &state,
	                 ( (uint8_t *)(&func_precondition_expr) ),
		         4
		       );

    if(func_precondition_expr == NULL) // ||
	// (*func_precondition_expr == NULL)
    {
	my_interface.cur_func_summ_entry       = NULL;
	my_interface.func_postcondition_enable = 0;

	goto FUNC_SUMM_TAINTCHECK_LOAD_ENDING;
    }// end of if(func_precondition_expr)

    /*
    TEMU_decompress_buf( &state,
	                 ( (uint8_t *)(func_precondition_expr) ),
		         4
		       ); 
    */

    /*
    // pointer to local path-constraint with regard to function's actual parametres
    TEMU_decompress_buf( &state,
	                 ( (uint8_t *)(&func_local_ending_expr) ),
		         4
	   	       );
    */

    /*    
    if(*func_precondition_expr != NULL)
    {
        tmp_str = exprString(*func_precondition_expr);
        term_printf( "func_summ_load: func_precondition_expr is %x, value is %x, restored expr is %s\n",
	  	     func_precondition_expr,
		     *func_precondition_expr,
		     tmp_str
	           );
	free(tmp_str);
    }// end of if(*func_precondition_expr)
    */


    func_entry = NULL;

// #ifdef H_WHILE
    while(1)
    {		
// 1. func_summ_entry
        TEMU_decompress_buf( &state,
			     (uint8_t *)(&value),
			     4
		           );

	if(func_entry == NULL)
	{
	    my_interface.cur_func_summ_entry = value;
	}// end of if(func_entry)

	func_entry = (function_summary_entry_t *)value;

	if(post_func_entry != NULL)
	{
	    post_func_entry->last_func = func_entry;
	}// end of if(post_func_entry)

	if(value == 0)
	{
	    break;
	}// end of if(value)


// call-site ID
#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
        TEMU_decompress_buf( &state,
		             (uint8_t *)( &(func_entry->curr_callsite_id) ),
		             4
		           );		
#endif

// stack_base
        TEMU_decompress_buf( &state,
		             (uint8_t *)( &(func_entry->stack_base) ),
		             4
		           );	


// 2. curr_post_condition		
	TEMU_decompress_buf( &state,
			     (uint8_t *)( &( func_entry->curr_post_condition ) ),
			     4
			   );

// 3. last_func_postcondition_enabled
	TEMU_decompress_buf( &state,
			     (uint8_t *)( &( func_entry->last_func_postcondition_enable ) ),
			     sizeof(int)
			   );	

// 4. actual stack parametres' taint states
	/* ------------------------------------------------------------------ */
        TEMU_decompress_buf( &state,
		             (uint8_t *)( &(func_entry->argsize) ),
		             4
		           );	

	if(func_entry->argsize != 0)
	{
// 5. real stackarg tcbmap
            TEMU_decompress_buf( &state,
		                 (uint8_t *)(&(func_entry->real_stackarg_tcbmap)),
		                 8
		               );

	    if(func_entry->real_stackarg_tcbmap != 0)
	    {
		
		if(func_entry->real_stackargs != NULL)
		{
		    free(func_entry->real_stackargs);		    
		}// end of if(func_entry->real_stackargs)
		func_entry->real_stackargs = (H_taint_record_t *)malloc(func_entry->argsize * sizeof(H_taint_record_t));
		
		/*
		term_printf( "func_entry: 0x%x ----- vaddr = 0x%x, stackarg_size = 0x%x, real_stackargs = 0x%x\n",
			     func_entry,
			     func_entry->vaddr,
			     func_entry->argsize,
			     func_entry->real_stackargs
			   );
		*/
// 6. real stack arguments
	        TEMU_decompress_buf( &state,
	  	                     (uint8_t *)(func_entry->real_stackargs),
		                     (func_entry->argsize) * sizeof(H_taint_record_t)
		                   );
	    }// end of if(func_entry)

	}// end of if(func_entry)	
	/* ------------------------------------------------------------------ */ // actual stack parametres' taint states



// 7. actual register parametres' taint records
	/* ------------------------------------------------------------------ */
        TEMU_decompress_buf( &state,
		             (uint8_t *)(func_entry->real_regargs),
		             32 * sizeof(H_taint_record_t)
		           );	

// 8. actual register parametres' taint bitmap
	TEMU_decompress_buf( &state,
			     (uint8_t *)(&(func_entry->real_reg_tcbmap)),
			     4
			   );
	/* ------------------------------------------------------------------ */ // actual register parametres' taint states


/*	
// 9. last func_summary entry
	TEMU_decompress_buf( &state,
			     (uint8_t *)(&(func_entry->last_func)),
			     4
			   );	
	value = func_entry->last_func;
*/
	post_func_entry = func_entry;
    }// end of while{1}

// #endif

FUNC_SUMM_TAINTCHECK_LOAD_ENDING:

   if(my_interface.hvm_load != NULL)
   {      
       my_interface.hvm_load( );
   }// end of if( )  


   // TEMU_decompress_close(&state);

   return 0;
}// end of func_summ_taintcheck_load( ) 


void func_summ_taintcheck_register( )
{
    register_savevm( "func_summ_taincheck",
		     0,
		     1,
		     func_summ_taintcheck_save,
		     func_summ_taintcheck_load,
		     NULL
		   );
}// end of func_summ_taintcheck_register( )


/* ============================================================================================= */	






// function summary makeup utils
/* ------------------------------------------------------------------------------ */

/* general_function_summary_end( ):
   1. record current path-expr as a new pre-condition for the current function
   2. record the combination of all symbolic-state modifications along the execution 
      as post-condition for the newly calculated pre-condition
 */
int general_function_summary_end(void * opaque)
{
    int tmp_postcondition_enable = my_interface.func_postcondition_enable;
    H_function_summary_data_t * hookdata = (H_function_summary_data_t *)opaque;
    
    if(my_interface.func_postcondition_enable != 0)
    {
	term_printf("Now applying a pre-calculated post-condition !\n");

	// Apply post-conditions !
	func_summ_postcondition_apply(hookdata->func_summary_entry);
    }
    else
    {
/* NOTE: before this time, the 'pre-post condition' is already stored in the global 
	 pre-post-condition-list of 'func_entry' ! 
*/
	// calculate a post-condition	
	postcondition_calculate(hookdata->func_summary_entry);

	// Apply post-conditions !
	func_summ_postcondition_apply(hookdata->func_summary_entry);

#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
	/* checks for all currently available callsites the newly calculated pre-post-condition pair,
	   while at the same time push the condition into the cond_list of this current callsite.
	*/
	func_summ_callsite_check_and_apply_pre_post_condition( 
				hookdata->func_summary_entry,
				( (function_summary_entry_t *)(hookdata->func_summary_entry) )->curr_callsite_id,
				( ( (function_summary_entry_t *)(hookdata->func_summary_entry) )->curr_post_condition )
							     );
#endif
    }// end of if(my_interface)    


    // context-restoration !
    /* ----------------------------------------------------------------------------------------------------------- */
    // restore to last-function's domain
    // my_interface.func_postcondition_enable = my_interface.last_func_postcondition_enable;
    my_interface.func_postcondition_enable = 
		( (function_summary_entry_t *)(hookdata->func_summary_entry) )->last_func_postcondition_enable;


    // record func-summary chaining sequence
    my_interface.cur_func_summ_entry = ( (function_summary_entry_t *)(hookdata->func_summary_entry) )->last_func;
    ( (function_summary_entry_t *)(hookdata->func_summary_entry) )->last_func = NULL;


    if(my_interface.cur_func_summ_entry != NULL)
    {
	func_precondition_expr = &( ( ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry) 
				      )->curr_post_condition 
				    )->pre_condition 
				  );
	
	func_taint_memory_record_list_restore( &( ( ( (function_summary_entry_t *)(my_interface.cur_func_summ_entry)
					            )->curr_post_condition
						  )->post_mem_cond
						)
					     );	
    }
    else
    {
	func_precondition_expr = NULL;
	func_local_ending_expr = NULL;

	func_taint_memory_record_list_restore(NULL);
    }// end of if(my_interface)
    /* ----------------------------------------------------------------------------------------------------------- */
    // context-restoration !    
    
    
/*
    if(tmp_postcondition_enable == 0)
    {
        // save the hook for future snapshot's usage
        add_entry_2_func_ret_hook_list( *TEMU_cpu_eip,
				        TEMU_cpu_regs[R_ESP] - 4,
				        general_function_summary_end,
				        hookdata->func_summary_entry,
				        sizeof(H_function_summary_data_t)
				      );
    }// end of if(my_interface.func_postcondition_enable)
*/

    del_tail_entry_from_func_ret_hook_list( *TEMU_cpu_eip,
					    (TEMU_cpu_regs[R_ESP] - 4),
					    general_function_summary_end
				          );

    hookapi_remove_hook(hookdata->handle);
    free(hookdata);

    return 0;
}// end of general_function_summary_end( )


/* general_function_summary_begin( ):   
   checks if input arguments satisfy any calculated pre-conditions. 
       if so, just ignore symbolic-execution
       else based on IDA analysis results, we would introduce stack-arguments and 
	    register-arguments as taints and carry-on symbolic execution in the 
	    function's domain 
	  
 */
int general_function_summary_begin(void * opaque)
{
    int   i = 0;
    int   j = 0;
    int   k = 0;

    uint32_t tmp_callsite_id = 0;

    char  var_name[256];
    int   count = 0;        
    HExpr tmp_expr = NULL;

    int   tmp_postcondition_enabled = 0;

    function_summary_entry_t * tmp_entry1 = my_interface.cur_func_summ_entry;
    function_summary_entry_t * tmp_entry2 = NULL;

    function_summary_entry_t * entry = (function_summary_entry_t *)opaque;
    H_taint_record_t record;

    uint64_t tcbmap = 0;

    uint32_t ret_eip;
    uint32_t esp_vaddr;    
    uint32_t cr3 = 0;
    H_function_summary_data_t * hookdata = NULL;

    int func_pred_satisfied = 0;

    char * tmp_str = NULL;
   
    uint8_t * content_buf = NULL;


    if(HHui_target_cr3 == 0)
    {
	return 0;
    }// end of if(HHui_target_cr3)

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(HHui_target_cr3 != cr3)
    {
	return 0;
    }// end of if(HHui_target_cr3)
        
/*
#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if( (my_interface.current_monitored_thread == 0) || 
      (my_interface.current_monitored_thread != get_current_tid( ))
    )
  {
      return 0;
  }// end of if(temu_plugin)
#endif
*/

    TEMU_read_register( esp_reg,
			&esp_vaddr
		      );

    TEMU_read_mem( esp_vaddr,
		   4,
		   &ret_eip
		 );
    entry->stack_base = esp_vaddr;


    tmp_callsite_id = find_specific_func_callsite( path_Expr,
						   esp_vaddr,
				      		   &(entry->fss_list)
			            		 );
    if(tmp_callsite_id != 0)
    {
	entry->curr_callsite_id = tmp_callsite_id;
	term_printf( "\nwe find a desired previously visited callsite %d!\n",
		     tmp_callsite_id
		   );
	if(tmp_callsite_id == 2)
	{
	    term_printf("callsite_id = 2 !\n");
	}// end of if(tmp_callsite_id)
    }
    else
    {
	entry->curr_callsite_id = 0;
	/*
	if(*TEMU_cpu_eip == 0x10001020)
	{
	    term_printf("\nWe encounter a new callsite !\n");
	
	    if(my_interface.func_postcondition_enable != 0)
	    {
	        term_printf("problematic !\n");
	    }// end of if( )
	}// end of if(*TEMU_cpu_eip)
	*/
    }// end of if(tmp_callsite_id)


    // my_interface.is_in_focused_func = 1;
    my_interface.focused_func_started = my_interface.focused_func_started + 1;

    if(my_interface.pre_post_cond_snapshot == 1)
    {
	/* here, we are in a state where the func-end was not hooked previously.
	   therefore, we should install the hook here so as to apply post-condition. 
	*/
	my_interface.pre_post_cond_snapshot = 0;
			
        hookdata = (H_function_summary_data_t *)malloc(sizeof(H_function_summary_data_t));
        hookdata->func_summary_entry = (void *)entry;
        hookdata->handle	     = hookapi_hook_return( ret_eip,
					        	    general_function_summary_end,
					    		    hookdata,
							    sizeof(H_function_summary_data_t)
					  	          );		
	return 0;
    }// end of if(my_interface.pre_post_cond_snapshot)

    entry->curr_post_condition = NULL;

    // stack-arguments introduced as taints
    /* -------------------------------------------------------- */

    // save function actual stack parametres' symbolic-states
    if(entry->argsize != 0)
    {
        entry->real_stackargs	    = (H_taint_record_t *)malloc(sizeof(H_taint_record_t) * entry->argsize);
        entry->real_stackarg_tcbmap = taintcheck_check_virtmem( (esp_vaddr + 4),
							        entry->argsize,
							        entry->real_stackargs
				     			      ); 
    }
    else
    {
	entry->real_stackargs	    = NULL;
	entry->real_stackarg_tcbmap = 0;
    }// end of if(entry->argsize)


    entry->real_reg_tcbmap = 0;

#ifndef H_FUNC_SUMM_STACKPARAM_ONLY
    // save function actual GP-register parametres' symbolic-states
    for(i = 0; i < 8; i = i + 1)
    {
        tcbmap = taintcheck_register_check( TEMU_tcregidx[i],
					    0,
					    4,
					    (uint8_t *)( ( ( (H_taint_record_t *)( entry->real_regargs )
							   ) + i * 4
							 )
						       )
					  );
	entry->real_reg_tcbmap = (entry->real_reg_tcbmap) | ( (tcbmap) << (i * 4) );
    }// end of for{i}
#endif

/*
    if( (func_pred_satisfied == 0) &&
	(
	  ( (entry->real_stackarg_tcbmap != 0) ||
	    (entry->real_reg_tcbmap != 0)
	  ) ||	  
	  ( (entry->argsize == 0) &&
	    (entry->regarg_mask == 0)
	  )	  
	)
      )
*/

    // check if we could apply function's calculated postconditions
    func_pred_satisfied = func_summ_test_precondition(entry);

    entry->last_func_postcondition_enable  = my_interface.func_postcondition_enable;
    my_interface.func_postcondition_enable = 0;


    if( (func_pred_satisfied == 0) && 
	( ( (entry->real_stackarg_tcbmap != 0) && (entry->argsize != 0) ) 
#ifndef H_FUNC_SUMM_STACKPARAM_ONLY
          ||
	  (entry->real_reg_tcbmap != 0)	  
#endif
	)
      )
//    if(func_pred_satisfied == 0)
    {
        // we only initialize new pre-condition and post-condition when some parametre is tainted !
        entry->curr_post_condition = add_entry_to_h_condition_list( &(entry->summary_conditions) );

	// current local path-condition expressed through function's formal parametres
        func_precondition_expr  = &( (entry->curr_post_condition)->pre_condition );

	// current local path-condition expressed through function's actual parametres
	entry->curr_local_expr  = NULL;
	// func_local_ending_expr  = &(entry->curr_local_expr);
    }
    else if(func_pred_satisfied != 0)
    {
	// func_local_ending_expr  = NULL;
	my_interface.func_postcondition_enable = 1;
        func_precondition_expr  = &( (entry->curr_post_condition)->pre_condition );
    }
    else
    {
	// func_local_ending_expr  = NULL;
	return 0;
    }// end of if(func_pred_satisfied)
    

    // record func-summary chaining sequence
    entry->last_func 		     = my_interface.cur_func_summ_entry;
    my_interface.cur_func_summ_entry = entry;


    if(func_pred_satisfied == 1)
    {
	goto FUNC_SUMM_HOOK_ENDING;
    }// end of if(func_pred_satisfied)

    
    // introduce formal parametres now !
    for(i = 0; i < entry->argsize; i = i + 1)
    {
// NOTE : we only introduce a formal stack parametre as taint when the specific location is tainted at the calling site !
	if((entry->real_stackarg_tcbmap & (1 << i)) != 0)
	{	
	    record.h_expr = (entry->stackarg_exprs)[i];	
	    record.origin = entry->vaddr;
	    record.type   = 4; // denoting func-summary usage !
	
	    add_stp_vlist_entry( (entry->stackarg_exprs)[i] );

	    taintcheck_taint_virtmem( esp_vaddr + 4 + i, // [esp] is ret-eip !
				      1,
				      1,
				      &record
				    );	
	}// end of if(entry)
    }// end of for{i}   
    /* -------------------------------------------------------- */
    // stack-arguments introduced as taints

    // introduce register-parametres now !
    // if(entry->regarg_mask != 0)
    // {
	k = 0;
	for(i = 0; i < 8; i = i + 1)
	{
// NOTE : we only introduce a formal register parametre as taint when the specific location is tainted at the calling site !
	    // if( ( entry->regarg_mask & (1 << i) ) != 0 )
	    if( entry->real_reg_tcbmap & ( 0xF << (i*4) ) != 0 )
	    {
		tmp_expr = (entry->regarg_exprs)[k];
		add_stp_vlist_entry( tmp_expr );

		for(j = 0; j < 4; j = j + 1)
		{
		    record.h_expr = vc_bvExtract( HHui_VC,
						  tmp_expr,
						  ( (j + 1) * 8 - 1 ),
						  ( j * 8 )
						);
		    record.type   = 4;
		    record.origin = entry->vaddr; // *TEMU_cpu_eip;

		    taintcheck_taint_register( TEMU_tcregidx[i],
					       j,
					       1,
					       1,
					       &record
					     );    
		}// end of for{j}	

		k = k + 1;	
	    }// end of if(entry)
	}// end of for{i}
    // }// end of if(entry)

FUNC_SUMM_HOOK_ENDING:

    // func_taint_memory_record_list_init( &(entry->tc_mem_rec_list) );

#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
    // entry->last_func_postcondition_enable  = my_interface.func_postcondition_enable;

    // store this callsite as snapshot into list
    /* ----------------------------------------------------------------------------------- */

#ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
    /* if there exists any such snapshot for this callsite of this function previously, 
       we should not make any snapshot any longer !
    */
    if( find_entry_in_func_summ_snapshot_list( *TEMU_cpu_eip,
					       TEMU_cpu_regs[R_ESP],
					       ret_eip,
					       (func_summ_snapshot_list_t * )( &(entry->fss_list) )
					     ) != 0 
      )
    {
	goto GENERAL_FUNCTION_SUMMARY_BEGIN_FINAL;
    }// end of if(find_entry_in_func_summ_snapshot_list)
#endif


    /* ----------------------------------------------------------------------------------- */

    tmp_postcondition_enabled = my_interface.func_postcondition_enable;    

#ifdef H_FUNC_SUMM_CHECK_CALLSITE
if(entry->curr_callsite_id == 0)
// {
    // insert this callsite into list for future branch-snapshot loading.
    /*
    add_entry_2_func_summ_snapshot_list( // entry,
					 *TEMU_cpu_eip,

					 #ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
					 ret_eip, // caller's pc, denoting his own ID
					 #endif

					 entry->accu_callsite_id,
					 path_Expr,	
					 (func_summ_snapshot_list_t * )( &(entry->fss_list) )
				       );
    */
// }
// else
{
#endif

    entry->accu_callsite_id = entry->accu_callsite_id + 1;

    // insert this callsite into list for future branch-snapshot loading.
    add_entry_2_func_summ_snapshot_list( // entry,
					 *TEMU_cpu_eip,
					 TEMU_cpu_regs[R_ESP],

					 #ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
					 ret_eip, // caller's pc, denoting his own ID
					 #endif

					 entry->accu_callsite_id,
					 path_Expr,	
					 (func_summ_snapshot_list_t * )( &(entry->fss_list) )
				       );
    entry->curr_callsite_id  = entry->accu_callsite_id;

    my_interface.func_postcondition_enable = 1;


    // tmp_entry2 			     = my_interface.cur_func_summ_entry;
    // my_interface.cur_func_summ_entry = tmp_entry1;

    /* Here, for the next snapshot, 'my_interface.cur_func_summ_entry' would point to this 
       function, but when loaded in HHui_vm_loadcb( ), as 'my_interface.pre_post_cond_snapshot'
       has been set to 1, re-entering general_function_summary_begin( ) would cause direct out.
    */
    func_summ_pre_save( *TEMU_cpu_eip,
			entry->curr_callsite_id
		      );

#ifdef H_FUNC_SUMM_CHECK_CALLSITE
}// end of if(entry->curr_callsite_id)
#endif

    my_interface.func_postcondition_enable = tmp_postcondition_enabled;    

    if(func_pred_satisfied == 1)
    {
        // if(entry->curr_callsite_id > 1)
        // {
	    // Here, we apply this callsite with every previously calculated but not applied pre-post
	    // condition pairs except the one currently satisfied  ----  just store them in list for 
	    // later scheduling.
	    func_postpone_and_apply_calculated_conditions( entry,
							   entry->curr_callsite_id,
							   entry->curr_post_condition // satisfied condition
							 );
	// }// end of if(entry)
    }// end of if(entry)

#endif    

GENERAL_FUNCTION_SUMMARY_BEGIN_FINAL:
    add_entry_2_func_ret_hook_list( ret_eip,
				    TEMU_cpu_regs[R_ESP],
				    general_function_summary_end,
				    entry,
				    sizeof(H_function_summary_data_t) 
				  );

    hookdata = (H_function_summary_data_t *)malloc(sizeof(H_function_summary_data_t));
    hookdata->func_summary_entry = (void *)entry;
    hookdata->handle		 = hookapi_hook_return( ret_eip,							
					    		general_function_summary_end,
					    		hookdata,
							sizeof(H_function_summary_data_t)
					  	      );

    return 0;
}// end of general_function_summary_begin( )
/* ------------------------------------------------------------------------------ */
// function summary makeup utils



void yyerror(const char * str)
{
/*
    fprintf( stderr,
	     "error: %s\n",
	     str
	   );
 */
    term_printf("fuck!\n");
}// end of yyerror( )


void function_summary_delete_for_module(void * module)
{
    function_summary_entry_t * entry = ( ((MODULE_ENTRY *)module)->func_list ).head;
    while(entry != NULL)
    {
	( ((MODULE_ENTRY *)module)->func_list ).head = entry->next;

	// TO DO: cleanup tasks for function_summary_entry_t
	/* ----------------------------------------------------------- */
	h_condition_list_delete( &(entry->summary_conditions) );
	free(entry);
	/* ----------------------------------------------------------- */

	entry = ( ((MODULE_ENTRY *)module)->func_list ).head;
    }// end of while{entry}

}// end of function_summary_delete_for_module( )


void post_func_summ_init(void * module)
{
    function_summary_entry_t * entry = NULL;

    int  i = 0;
    char var_name[256];
    int  count  = 0;
    int  count1 = 0;
    
    module_offset = 0;

    HType htype  = vc_bvType( HHui_VC,
			      8
			    );
    HExpr tmp_expr = vc_bv32ConstExprFromInt( HHui_VC,					      
					      32
					    );
    HType htype1 = vc_getType( HHui_VC,
			       tmp_expr
			    );
    // vc_DeleteExpr(tmp_expr);

    // char * tmp_str = NULL;

    // hook all the functions in this module to make function summary
    /* ----------------------------------------------------------------- */
    entry = (((MODULE_ENTRY *)module)->func_list).head;
    // term_printf("EEEEEEEEEEEEE --- %x", entry);

    (((MODULE_ENTRY *)module)->func_list).module = h_module;

    while(entry != NULL)
    {
	entry->last_func_postcondition_enable = 0;
	entry->last_func = NULL;

#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
        entry->accu_callsite_id = 0;
        entry->curr_callsite_id = 0;

	func_summ_snapshot_list_init( &(entry->fss_list) );
#endif

	entry->stackarg_exprs = (HExpr *)malloc( sizeof(HExpr) * (entry->argsize) );
	h_condition_list_init( &(entry->summary_conditions) );

	entry->real_stackargs 	    = NULL;
	entry->real_stackarg_tcbmap = 0;

	if(entry->stackarg_exprs == NULL)
	{
	    term_printf("Fuck : Now insufficient memory error happened !\n");
	    return;
	}// end of if(entry->stackarg_exprs)

	// stack-arguments' initialization	
	/* --------------------------------------------------- */
        for(i = 0; i < entry->argsize; i = i + 1)
        {
	    count = sprintf( var_name,
			     "func_%x_stack_%x",
			     entry->vaddr,
			     i
		           );
 	    var_name[count] = '\0';

	    /*
	    term_printf( "stack-argument introduced : %s\n",
			 var_name
		       );
	    */
	    (entry->stackarg_exprs)[i] = vc_varExpr( HHui_VC,
					  	     var_name,
					  	     htype
						   );	

	    
	    // add_stp_vlist_entry( (entry->stackarg_exprs)[i] );

        }// end of for{i}
	/* --------------------------------------------------- */
	// stack-arguments' initialization


	// register-arguments' initialization
	/* --------------------------------------------------- */
	// if(entry->regarg_mask != 0)
	// {	    
	// count = 0;
/*
	for(i = 0; i < 8; i = i + 1)
	{
	    if( (entry->regarg_mask & (1 << i)) != 0 )
	    {
		count = count + 1;
	    }// end of if(entry)		
	}// end of for{i}

*/
	entry->regarg_exprs = (HExpr *)malloc(sizeof(HExpr) * 8);
	for(i = 0; i < 8; i = i + 1)
	{
	    count1 = sprintf( var_name,
			      "func_%x_reg_%x",
			      entry->vaddr,
			      i
			    );
	    var_name[count1] = '\0';
	    (entry->regarg_exprs)[i] = vc_varExpr( HHui_VC,
						   var_name,
						   htype1
						 );
	}// end of for{i}	    	    
	// }// end of if(entry)
	/* --------------------------------------------------- */	
	// register-arguments' initialization


	// pre-conditions and post-conditions
	(entry->summary_conditions).head  = NULL;
	(entry->summary_conditions).end   = NULL;
	(entry->summary_conditions).count = 0;

	/*
	if(entry->vaddr == 0x10001020)
	{
	    term_printf("222222222\n");
	}// end of if(entry->vaddr)
	*/

	term_printf( "hook function at 0x%x, argsize = %d\n",
		     entry->vaddr,
		     entry->argsize
		   );
	hookapi_hook_function( 0,
			       entry->vaddr,
			       general_function_summary_begin,
			       entry,
			       sizeof(function_summary_entry_t)
			     );
	entry = entry->next;
    }// end of while{entry}
    /* ----------------------------------------------------------------- */
    // hook all the functions in this module to make function summary
    
}// end of post_func_summ_init( )


void function_summary_init(void * module)
{
    FILE * fp    = NULL;    
    char   buffer[1024];
    int    count = 0;

    count = sprintf( buffer,
		     "./IDA_analysis/%s_function_prototypes",
		     ( ( (struct module_entry *)module )->module_info).name
		   );
    buffer[count] = '\0';

    h_module = (struct module_entry *)module;
        
    fp = fopen( buffer,
		"r"
	      );
    if(fp == NULL)
    {
	return;
    }// end of if(fp)

    yyrestart(fp);
    yyparse( );    

    fclose(fp);

    post_func_summ_init(h_module);


    // term_printf("OK! parsing finished !\n");
}// end of function_summary_init( )
%}

%token FUNC_START TOKENIZER VADDR EQ SEMICOLON ARGSIZE NAME_STR NUMBER

%%
statements: 
	  |
	  statement statements;
statement:
	  // FUNC_START TOKENIZER VADDR EQ NUMBER SEMICOLON ARGSIZE EQ NUMBER SEMICOLON regarglist
	  FUNC_START TOKENIZER NAME_STR TOKENIZER VADDR EQ NUMBER SEMICOLON ARGSIZE EQ NUMBER SEMICOLON regarglist
	  {
	      HHui_tmp_vaddr   = h_atoint($7); // VADDR NUMBER
	      if(module_offset == 0)
	      {
	          module_offset = (h_module->module_info).base - ( (HHui_tmp_vaddr / 0x10000) * 0x10000 );
	      }// end of if(module_offset)
	      HHui_tmp_vaddr = HHui_tmp_vaddr + module_offset;

	      HHui_tmp_fname   = $3;
	      HHui_tmp_argsize = h_atoint($11);
	      

#ifdef HH_INTERTESTED_FUNC_ANALYSIS
	      HHui_tmp_findex = is_interested_func($3);
	      if(HHui_tmp_findex != -1)
	      {
		  hook_interested_func( HHui_tmp_findex,
					HHui_tmp_vaddr,
					HHui_tmp_argsize
				      );		  
		  free($3);
		  free($7);
		  free($11);
	      }// end of if( )
	      else
	      {
#endif
	      h_func_summary_entry = (function_summary_entry_t *)malloc(sizeof(function_summary_entry_t));
	      h_func_summary_entry->next = NULL;

	      h_func_summary_entry->regarg_mask = 0;

	      if( (h_module->func_list).head == NULL )
	      {
		  (h_module->func_list).head = h_func_summary_entry;
		  (h_module->func_list).end  = h_func_summary_entry;
	      }
	      else
	      {
		  ((h_module->func_list).end)->next = h_func_summary_entry; 
		  (h_module->func_list).end 	    = h_func_summary_entry; 
	      }// end of if(h_module)
		       
	      // vaddr
	      (h_module->func_list).count = (h_module->func_list).count + 1;
	      // h_func_summary_entry->vaddr = h_atoint($5); // VADDR NUMBER
	      h_func_summary_entry->vaddr = HHui_tmp_vaddr;	 	 

	      /*
	      term_printf( "function: vaddr = 0x%x --",
			   h_func_summary_entry->vaddr
			 );
	       */
	      // free($5);
	      free($7);
	      
	      // argsize
	      // h_func_summary_entry->argsize = h_atoint($9);
	      h_func_summary_entry->argsize = HHui_tmp_argsize;
	      /*
	      term_printf( "function: argsize = 0x%x \n",
			   h_func_summary_entry->argsize
			 );
	       */
	      // free($9);	   
	      free($11);

	      free($3);
#ifdef HH_INTERTESTED_FUNC_ANALYSIS
	      }// end of if(check_and_hook_interested_func)
#endif
	      // h_func_summary_entry-> = (void *)h_module;   
	  }
	  ;

regarglist:
	| 
	regarglist NAME_STR SEMICOLON
	{ 
	  for(int i = 0; i < 8; i = i + 1)
	  {
	      if(strcmp(str_regname[i], $2) == 0)
	      {
		  h_func_summary_entry->regarg_mask = h_func_summary_entry->regarg_mask | (1 << i);
		  break;
	      }// end of if(strcmp)
	  }// end of for{i}	
	  free($2);	 
	}
	;
%%



