#ifndef H_FORMULA_SOLVE_H

    #define H_FORMULA_SOLVE_H

    #include <inttypes.h>
    #include "hc_interface.h"



    /* ---------------------------------------------------------------------------------------------------------- */
    int predicate_form_build( HVC	 hvc,
			      HExpr      branch_expr,
			      HExpr    * x_exprs,    // [input]: total unit-var-exprs

			      int	 x_count,
			      HExpr *    pred_expr   // [output]
			 )


    uint32_t stp_formula_solve( HVC   hvc,
				HExpr formula_expr,
				HType formula_type,
				HExpr pred_expr			    
			      );


    uint32_t pred_stp_formula_solve( HVC   hvc,				
			    	     HExpr formula_expr,
				     HExpr pred_expr
			           );

    // caller should manually free( ) the above obtained 'pred_expr'
    // void predicate_form_remove( );
    /* ---------------------------------------------------------------------------------------------------------- */


#endif
