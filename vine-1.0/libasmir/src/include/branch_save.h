#ifndef H_BRANCH_SAVE_H
    #define H_BRANCH_SAVE_H

    typedef int (*BRANCH_SAVE)( HVC      HHui_VC,
				HExpr *  path_Expr,       // IN-OUT
				HExpr    predicate_expr,
				int      H_predicate,

				uint32_t tbranch,
				uint32_t fbranch,	   

				uint32_t ir_true_real_fbranch_addr,  // calculated IR true branch !		 
			        uint32_t ir_false_real_tbranch_addr  // calculated IR false branch !		 
			      );

/*
    int branch_save( HVC      HHui_VC,
		     HExpr *  path_Expr,       // IN-OUT
		     HExpr    predicate_expr,
		     int      H_predicate,

		     uint32_t tbranch,
		     uint32_t fbranch,	   
		     uint32_t branch_addr 	   // calculated IR false branch !		 
	           );
 */

#endif
