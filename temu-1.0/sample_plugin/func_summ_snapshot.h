#ifndef H_FUNC_SUMM_SNAPSHOT_H
    #define H_FUNC_SUMM_SNAPSHOT_H

    #include <inttypes.h>
    #include "hc_interface.h"

    #include "expr_condition.h"
    #include "H_test_config.h"

    /* ------------------------------------------------------------------------------ */
    typedef struct expr_cond_entry
    {
	void * 			 expr_cond;
	struct expr_cond_entry * next;
    }expr_cond_entry_t, *Pexpr_cond_entry_t;


    typedef struct expr_cond_list
    {
	expr_cond_entry_t * head;
	expr_cond_entry_t * end;
	int		    count;
    }expr_cond_list_t, *Pexpr_cond_list_t;
    /* ------------------------------------------------------------------------------ */



    // we would make snapshot at every call-site's entry-point of the interested function
    typedef struct func_summ_snapshot_entry
    {
	/* ----------------------------------------------------------------------- */
	/* records up calling context to uniquely identify-out the call-site.
	   Note, this ID is allocated everytime at 'general_function_summary_begin'.

	   However, 'callsite_id' in itself isn't enough for identify-out a callsite.
	   We should combine with 'cur_global_expr' together to obtain up meaningful 
	   identification.

	   When encountering a specific calling instance, we should check the formula
	   'A iff B', in which A is 'cur_global_expr' held by 'func_summ_snapshot_entry_t'
	   while B is the current path_Expr, so as to force the above checking policy.
	*/
	uint32_t callsite_id;
	HExpr	 cur_global_expr;
	/* ----------------------------------------------------------------------- */


#ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
  	uint32_t caller_addr;
#endif
	// we use this to obtain the orginal function's snapshot name ---- ["func_%x_snapshot_%x", func_addr, callsite_id]
	uint32_t func_addr;

	uint32_t esp_addr;

	/* ----------------------------------------------------------------------- */
	// the general information shared by all callsites of this function
	// void *   func_entry;
	/* ----------------------------------------------------------------------- */
	
	// previously checked pre-post condition pairs (stored in 'function_summary_entry_t')
	expr_cond_list_t  H_expr_cond_list;

	struct func_summ_snapshot_entry * next;
    }func_summ_snapshot_entry_t, *Pfunc_summ_snapshot_entry_t;


    typedef struct func_summ_snapshot_list
    {
	func_summ_snapshot_entry_t * head;
	func_summ_snapshot_entry_t * end;
	
	int  count;
    }func_summ_snapshot_list_t, *Pfunc_summ_snapshot_list_t;


    typedef struct func_calling_entry
    {
	func_summ_snapshot_entry_t * fce;
	struct func_calling_entry  * next;
    }func_calling_entry_t, *Pfunc_calling_entry_t;

    typedef struct func_calling_list
    {
	func_calling_entry_t * head;
	func_calling_entry_t * end;
	int count;
    }func_calling_list_t, *Pfunc_calling_list_t;



    /* ===================================================================================================== */
    void func_summ_snapshot_list_init(func_summ_snapshot_list_t * fss_list);
    void func_summ_snapshot_list_delete(func_summ_snapshot_list_t * fss_list);


    uint32_t find_specific_func_callsite( HExpr    		      path_expr,
					  uint32_t		      esp_addr,
				 	  func_summ_snapshot_list_t * fss_list
			                );


    #ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
    int find_entry_in_func_summ_snapshot_list( uint32_t		           func_addr,
					       uint32_t			   esp_addr,
					       uint32_t 	           call_addr,
					       func_summ_snapshot_list_t * fss_list
					     );
    #endif

    void add_entry_2_func_summ_snapshot_list( // void *			  func_entry,
					      uint32_t 		          func_addr,
					      uint32_t			  esp_addr,

					      #ifdef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
					      uint32_t 			  caller_id,
					      #endif

					      uint32_t 		          callsite_id, 
					      HExpr		          cur_global_expr,
					      func_summ_snapshot_list_t * fss_list
					    );

    void add_condentry_2_func_summ_snapshot_entry( void	    * func_entry,
					           uint32_t   callsite_id,
					           void     * cond_entry
					         );


    int func_summ_callsite_check_pre_post_condition( void		 * func_entry,
						     uint32_t		   callsite_id,
						     h_condition_entry_t * cond_entry
					           );

    void func_postpone_and_apply_calculated_conditions( void * 		      func_entry,
						        uint32_t 	      callsite_id,
						        h_condition_entry_t * condition // satisfied condition
					 	      );


    void func_summ_pre_save( uint32_t func_addr,
			     uint32_t callsite_id
		           );

    #ifdef H_FUNC_SUMM_RESULT_DEBUG_DUMP
    void func_summ_callsite_cond_append_2_file( uint32_t func_addr,
					        uint32_t cur_id,
					        uint32_t callsite_id,
					        HExpr    pre_expr
					      );

    void func_summ_callsite_cond_dump(void * func_entry);
    #endif


    #ifdef H_FUNC_CALLING_SEQUENCE_RECORD
    // total calling sequence list utils
    void func_calling_list_init( );
    #endif
    /* ===================================================================================================== */

#endif
