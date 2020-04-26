#ifndef H_FUNCTION_SUMMARY_H
    #define H_FUNCTION_SUMMARY_H

    #include <inttypes.h>
    #include "hc_interface.h"
    // #include "module_notify.h"
 
    #include "expr_condition.h"
    #include "H_taint_record.h"

    #include "../TEMU_lib.h"
    #include "H_test_config.h"

    #include "taintcheck_hook.h"

// feedback pre-post conditions to snapshots of a function
#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
    #include "func_summ_snapshot.h"			
#endif

    typedef struct function_summary_entry
    {
	uint32_t vaddr;

	// stack-arguments
	int	 argsize;

	h_func_taint_mem_record_list_t tc_mem_rec_list;

/* NOTE: when A( ) calls B(b1, b2), parametre expressions outside B( )'s domain would be stored in 'real_stackargs', 
	 while in B( ) only 'stackarg_exprs' would be symbolically-executed as formal-paramtres.
*/
	uint32_t	    stack_base;
	HExpr *  	    stackarg_exprs;

	H_taint_record_t *  real_stackargs;
	uint64_t 	    real_stackarg_tcbmap;

	// 1 bit per general-purpose register candidate. low->high: eax, ebx, ecx, edx, esi, edi, esp, ebp	
	uint8_t  	    regarg_mask;      // register-parametre usage
	
	// register-arguments expressions
	HExpr *  	    regarg_exprs;     // formal-parametres --- byte-wise
	H_taint_record_t    real_regargs[32]; // actual-parametres --- byte-wise
	uint32_t	    real_reg_tcbmap;  // byte-wise bitmap	

/* --------------------------------------------------------------------------------------------------------------- */
/* note, here EFLAGS would not be considered, just clean all of them. We only consider a PARTIAL-EVALUATION here ! */
/* --------------------------------------------------------------------------------------------------------------- */

	// summarizing total pre-conditions and post-conditions of the current function
	h_condition_list_t  summary_conditions;

	// current local epxr in func's body after variable substitution
	HExpr  		   curr_local_expr;

	h_condition_entry_t * curr_post_condition;

	// denoting previous-function's calculation decision
        int last_func_postcondition_enable;	

// feedback pre-post conditions to snapshots of a function
#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
	uint32_t		  accu_callsite_id;
	uint32_t		  curr_callsite_id;
	func_summ_snapshot_list_t fss_list;		
#endif

	// record the chaining sequence of nested function calls
	struct function_summary_entry * last_func;

	struct function_summary_entry * next;

    }function_summary_entry_t, *Pfunction_summary_entry_t;
    

    typedef struct function_summary_list_entry
    {
	function_summary_entry_t * head;
	function_summary_entry_t * end;
	int count;

	void * module;
	// struct mdl_function_summary_entry * next;
    }function_summary_list_entry_t, *Pfunction_summary_list_entry_t;


/*    
    typedef struct struct mdl_function_summary_list_entry
    {	
	mdl_function_summary_entry_t * head;
	mdl_function_summary_entry_t * end;
	int count;
    }mdl_function_summary_list_entry_t, *Pmdl_function_summary_list_entry_t;

 */
    void function_summary_init(void * module_entry);
    void post_func_summ_init(void * module);

    void function_summary_delete_for_module(void * module);
   
    int general_function_summary_begin(void * opaque);
    int general_function_summary_end(void * opaque);
 

    void func_summ_taintcheck_register( );
/*
    void func_summ_taintcheck_save( QEMUFile * f,
				    void     * opaque
			          );
    
    int func_summ_taintcheck_load( QEMUFile * f,
			           void     * opaque,
  			           int	      version_id
			         );
*/
#endif
