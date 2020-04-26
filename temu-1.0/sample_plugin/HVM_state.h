#ifndef HVM_STATE_H
    #define HVM_STATE_H

    #include <inttypes.h>
    #include "hc_interface.h"

    #include "../TEMU_lib.h"

    #include "expr_condition.h"
    #include "H_test_config.h"

    /* when a tainted branching point is encountered, current SYM-VM's state would be 
       saved along with the updated path-expr for the unsearched branch-case
     */

    typedef struct HVM_param
    {
	int      * cur_proc_terminated;
	HVC      * hvc;
	HExpr    * path_expr;

	uint32_t * pid;
	uint32_t * HHui_current_monitored_eip;  
    }HVM_param_t, *PHVM_param_t;



    typedef struct HVM_state_entry
    {
	/* if HHUI_FUNC_SUMMARY_ENABLED is not defined, or 'local_func_expr_position' is NULL,
	      'path_expr' means global path-expr for this branch;
	   otherwise the global path-expr at the beginning of the target function.
 	*/
	HExpr    global_path_expr;     
	HExpr    local_path_expr;    // local function path constraint expressed through its actual parametres 
	// HExpr    local_formal_expr;  // local function path constraint expressed through its formal parametres 

	h_condition_entry_t * cond_entry;


#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK 
	void *   func_entry;
	uint32_t func_addr;
	uint32_t esp_base;

	uint64_t stack_param_tcbmap;
	uint32_t callsite_id;

	int 	 is_pre_post_apply;
#endif

	char *   state_name;    // relevant snapshot's name
	uint32_t monitored_eip;


#ifdef HHUI_FUNC_SUMMARY_ENABLED
 	HExpr  * local_func_expr_position;
	HExpr  * local_func_expr;
#endif

	struct HVM_state_entry * prev;
	struct HVM_state_entry * next;
    }HVM_state_entry_t, *PHVM_state_entry_t;


    typedef struct HVM_state_list
    {
	struct HVM_state_entry * head;	
	struct HVM_state_entry * end;	

	int  count;
    }HVM_state_list_t, *PHVM_state_list_t;



    // my snapshot list !
    // extern HVM_state_list_t vm_state_list;
    extern HVM_state_list_t vm_list;


    // functions    
    /* -------------------------------------------------------------------------- */
    void init_vm_state_list( );

    PHVM_state_entry_t add_HVM_state_entry( HExpr   		  local_path_expr, // function's local domain by actual para
					    h_condition_entry_t * cond_entry,
					    HExpr       	  global_path_expr,// constraint formula for this branch
					    uint32_t 		  branch_addr      // first instruction's VA in this branch
				          );

#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK    
    PHVM_state_entry_t add_HVM_func_summ_snapshot_entry( void *		       func_entry,
							 uint32_t	       func_addr,
						         uint32_t	       callsite_id,
							 h_condition_entry_t * cond_entry,
							 char * 	       snapshot_name,
					    		 HExpr       	       global_path_expr
							 // constraint formula for this branch
				          	       );

    void tst_del_HVM_func_summ_snapshot_entry( uint32_t		     func_addr,
					       uint32_t		     callsite_id,
					       h_condition_entry_t * cond_entry
					     );
#endif


    void Delete_HVM_state_list( );

    /*
    void BFS_restore_HVM_state_from_snapshot( HVC     hvc,
					      HExpr * path_expr // [ output ] : restoring the path-constraint for this branch
					    );	
    */
    void BFS_restore_HVM_state_from_snapshot( );

    int vm_state_list_is_empty( );


    void hvm_savecb( );



    /* callback to be registered for snapshot restoration
       in fact, it would be called when do_loadvm( ) is called
     */
    void HHui_vm_loadcb( );

/*
    int hvm_loadcb( QEMUFile * f,
		    void     * opaque,
		    int	       version_id
	          );
 */
    /* -------------------------------------------------------------------------- */
    // functions

#endif
