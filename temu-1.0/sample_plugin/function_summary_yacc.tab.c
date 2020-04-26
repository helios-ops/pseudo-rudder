/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison implementation for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.5"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Copy the first part of user declarations.  */

/* Line 268 of yacc.c  */
#line 1 "function_summary_yacc.y"

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


/* Line 268 of yacc.c  */
#line 1321 "function_summary_yacc.tab.c"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     FUNC_START = 258,
     TOKENIZER = 259,
     VADDR = 260,
     EQ = 261,
     SEMICOLON = 262,
     ARGSIZE = 263,
     NAME_STR = 264,
     NUMBER = 265
   };
#endif



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef int YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */


/* Line 343 of yacc.c  */
#line 1373 "function_summary_yacc.tab.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  5
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   18

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  11
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  4
/* YYNRULES -- Number of rules.  */
#define YYNRULES  6
/* YYNRULES -- Number of states.  */
#define YYNSTATES  20

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   265

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
       0,     0,     3,     4,     7,    21,    22
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      12,     0,    -1,    -1,    13,    12,    -1,     3,     4,     9,
       4,     5,     6,    10,     7,     8,     6,    10,     7,    14,
      -1,    -1,    14,     9,     7,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,  1253,  1253,  1255,  1258,  1334,  1336
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "FUNC_START", "TOKENIZER", "VADDR", "EQ",
  "SEMICOLON", "ARGSIZE", "NAME_STR", "NUMBER", "$accept", "statements",
  "statement", "regarglist", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    11,    12,    12,    13,    14,    14
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,    13,     0,     3
};

/* YYDEFACT[STATE-NAME] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     0,     2,     0,     1,     3,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     5,     4,     0,     6
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     2,     3,    17
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -7
static const yytype_int8 yypact[] =
{
      -3,    -2,     1,    -3,    -6,    -7,    -7,     0,     2,    -1,
      -4,     3,     4,     5,     6,     7,    -7,     8,    11,    -7
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
      -7,    10,    -7,    -7
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
       1,     5,     4,     7,     8,    10,    11,     9,     0,     0,
      12,    14,    13,     6,    16,     0,    15,    18,    19
};

#define yypact_value_is_default(yystate) \
  ((yystate) == (-7))

#define yytable_value_is_error(yytable_value) \
  YYID (0)

static const yytype_int8 yycheck[] =
{
       3,     0,     4,     9,     4,     6,    10,     5,    -1,    -1,
       7,     6,     8,     3,     7,    -1,    10,     9,     7
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     3,    12,    13,     4,     0,    12,     9,     4,     5,
       6,    10,     7,     8,     6,    10,     7,    14,     9,     7
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* This macro is provided for backward compatibility. */

#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (0, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  YYSIZE_T yysize1;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = 0;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - Assume YYFAIL is not used.  It's too flawed to consider.  See
       <http://lists.gnu.org/archive/html/bison-patches/2009-12/msg00024.html>
       for details.  YYERROR is fine as it does not invoke this
       function.
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                yysize1 = yysize + yytnamerr (0, yytname[yyx]);
                if (! (yysize <= yysize1
                       && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                  return 2;
                yysize = yysize1;
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  yysize1 = yysize + yystrlen (yyformat);
  if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
    return 2;
  yysize = yysize1;

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */


/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks thru separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 4:

/* Line 1806 of yacc.c  */
#line 1259 "function_summary_yacc.y"
    {
	      HHui_tmp_vaddr   = h_atoint((yyvsp[(7) - (13)])); // VADDR NUMBER
	      if(module_offset == 0)
	      {
	          module_offset = (h_module->module_info).base - ( (HHui_tmp_vaddr / 0x10000) * 0x10000 );
	      }// end of if(module_offset)
	      HHui_tmp_vaddr = HHui_tmp_vaddr + module_offset;

	      HHui_tmp_fname   = (yyvsp[(3) - (13)]);
	      HHui_tmp_argsize = h_atoint((yyvsp[(11) - (13)]));
	      

#ifdef HH_INTERTESTED_FUNC_ANALYSIS
	      HHui_tmp_findex = is_interested_func((yyvsp[(3) - (13)]));
	      if(HHui_tmp_findex != -1)
	      {
		  hook_interested_func( HHui_tmp_findex,
					HHui_tmp_vaddr,
					HHui_tmp_argsize
				      );		  
		  free((yyvsp[(3) - (13)]));
		  free((yyvsp[(7) - (13)]));
		  free((yyvsp[(11) - (13)]));
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
	      free((yyvsp[(7) - (13)]));
	      
	      // argsize
	      // h_func_summary_entry->argsize = h_atoint($9);
	      h_func_summary_entry->argsize = HHui_tmp_argsize;
	      /*
	      term_printf( "function: argsize = 0x%x \n",
			   h_func_summary_entry->argsize
			 );
	       */
	      // free($9);	   
	      free((yyvsp[(11) - (13)]));

	      free((yyvsp[(3) - (13)]));
#ifdef HH_INTERTESTED_FUNC_ANALYSIS
	      }// end of if(check_and_hook_interested_func)
#endif
	      // h_func_summary_entry-> = (void *)h_module;   
	  }
    break;

  case 6:

/* Line 1806 of yacc.c  */
#line 1337 "function_summary_yacc.y"
    { 
	  for(int i = 0; i < 8; i = i + 1)
	  {
	      if(strcmp(str_regname[i], (yyvsp[(2) - (3)])) == 0)
	      {
		  h_func_summary_entry->regarg_mask = h_func_summary_entry->regarg_mask | (1 << i);
		  break;
	      }// end of if(strcmp)
	  }// end of for{i}	
	  free((yyvsp[(2) - (3)]));	 
	}
    break;



/* Line 1806 of yacc.c  */
#line 2688 "function_summary_yacc.tab.c"
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



/* Line 2067 of yacc.c  */
#line 1349 "function_summary_yacc.y"





