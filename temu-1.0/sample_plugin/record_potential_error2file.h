#ifndef H_RECORD_POTENTIAL_ERROR2FILE_H
    #define H_RECORD_POTENTIAL_ERROR2FILE_H

    #include "hc_interface.h"

    // record errors found during API hooking.
    // void APIHooking_record_ERROR_2file(char * str_info);
    void APIHooking_record_ERROR_2file( HExpr err_expr,
				        int   category_id
				      );

    // testcase generation for errors found during API-Hooking.
    void H_APIHooking_error_testcase_generate_4_expr( HExpr    path_expr,
				    	              uint32_t category_id, 
				      		      int      local_id
			       	     	            );

    void H_TEMU_printExpr(void * expr);

    typedef void(*H_ERROR_TESTCASE_GENERATION_4_EXPR)( HExpr    path_expr,
						       uint32_t category_id,
						       int	local_id
				       	             );

    // testcase generation for errors found during IR-SYMEXE.
    // the corresponding expr-record function resides in the 'IR_SymEXE.so' module.
    void H_IRSYMEXE_error_testcase_generate_4_expr( HExpr    path_expr,
				    	            uint32_t category_id,
				      		    int	     local_id
			       	     	          );

#endif
