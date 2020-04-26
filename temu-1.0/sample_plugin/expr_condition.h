#ifndef H_EXPR_CONDITION_H
    #define H_EXPR_CONDITION_H

    #include "hc_interface.h"
    #include "taintcheck_hook.h"

    typedef struct h_condition_entry
    {
	// used under state reloading context
	uint8_t   calculated;

	/* constraint that should be obeyed by the functions' actual parametres,
	   also representing the local execution effects that would be joined 
	   into 'path_Expr'.
	*/
	HExpr     pre_condition;
	
	// HExpr 	  asserted_condition;

	// post-conditions	
	/* ----------------------------------------------- */        
	h_func_taint_mem_record_list_t post_mem_cond;
	HExpr   * reg_exprs;
	uint8_t * reg_ids;
 	int	  reg_count;
	/* ----------------------------------------------- */ // post-conditions	

	struct h_condition_entry * prev;
	struct h_condition_entry * next;
    }h_condition_entry_t, *Ph_condition_entry_t;


    typedef struct h_condition_list
    {
	h_condition_entry_t * head;
	h_condition_entry_t * end;
	int count;
    }h_condition_list_t, *Ph_condition_list_t;


    int H_build_formal_actual_expr_correspondence( void 		    * func_m_entry,
					           HExpr		   ** formal_exprs,
					           HExpr 		   ** actual_exprs			 
					         );


    HExpr H_build_general_postcondition_predicate( // h_func_taint_mem_record_list_t * mem_list,
					           void * func_m_entry
					         );


    // checks whether any precondition is satisfied so as to apply function's calculated postconditions    
    int func_summ_test_precondition(void *entry);

    void func_summ_postcondition_apply(void * func_m_entry);
    void postcondition_calculate(void * func_m_entry);


    void h_condition_list_init(h_condition_list_t * cond_list);

    h_condition_entry_t * add_entry_to_h_condition_list(h_condition_list_t * cond_list);

    void delete_entry_from_h_condition_list( h_condition_list_t  * cond_list, 
					     h_condition_entry_t * entry
				           );

    void h_condition_list_delete(h_condition_list_t * cond_list);

    h_condition_entry_t * expr_cond_branch_save(void * func_entry);

    void func_dump_total_precondition(void * func_entry);
#endif
