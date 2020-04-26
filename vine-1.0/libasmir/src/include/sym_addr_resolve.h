#ifndef H_SYM_ADDR_RESOLVE_H

    #define H_SYM_ADDR_RESOLVE_H

    #include <inttypes.h>   

    // #include "hc_interface.h"
    #include "H_STP_stub.h"


    /* -------------------------------------------------------------------------------------- */
    typedef struct value_entry
    {
	uint32_t 	     value;
	struct value_entry * next;
    }value_entry_t, *Pvalue_entry_t;


    typedef struct value_entry_set
    {
	struct value_entry * head;
	struct value_entry * tail;

	int count;
    }value_entry_set_t, *Pvalue_entry_set;

    void init_value_entry_set( );
    void free_value_entry_set( );
    void add_value_entry_to_set(uint32_t value);
    void fetch_all_values_from_set(uint32_t * arr);
    /* -------------------------------------------------------------------------------------- */


    int hvc_symaddr_solve( HVC         hvc,
		           HExpr *     path_expr,
		           HExpr       symaddr_expr,
		           int         access_mode,      	 /* 1 -- read; 2 -- write; 4 -- execute */
		           HExpr *     invalid_constraint_exprs, // 2 elements' array holding ERRORs' constraints !
		           uint32_t ** correct_concrete_addrs_values,
			   HExpr **    symaddr_correct_concrete_addrs_constraints,
		           int	*      correct_concrete_addrs_count
		         );


    int symaddr_concrete_solve( HVC         hvc,
			       	HExpr *     path_expr,
		      	        HExpr       symaddr_expr,
			        uint32_t ** correct_concrete_addrs_values, // caller should be responsible for free( ) it !
				HExpr **    symaddr_correct_concrete_addrs_constraints
			      );

    /* For SYM-Addressing memory READing ! */
    HExpr symaddr_reading_expr_formulate( HVC        hvc,
				          uint32_t * symaddr_corect_concrete_addrs_values, 
				          HExpr *    symaddr_correct_concrete_addrs_constraints, 					          int        correct_concrete_addrs_count,
				          int        data_length,
				          char *     records
				        );    

#endif
