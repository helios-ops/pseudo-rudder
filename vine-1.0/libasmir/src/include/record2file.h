#ifndef H_RECORD2FILE_H
    #define H_RECORD2FILE_H

    #include "H_STP_stub.h"
    /* err_id: 0 --- sym-addr write out-of-range 
	       1 --- sym-addr write invalid access
	       2 --- sym-addr write stack-eip overwritten

	       3 --- sym-addr read out-of-range
	       4 --- sym-addr read invalid access	       
	       5 --- divide by 0
     */    

    /*
    void record_ERROR_2file( char * str_info,
			     int    err_id
			   );
     */
    void record_ERROR_2file( HExpr err_expr,
			     int   err_id
			   );

    /*
    void H_record_error_testcase_4_expr( HExpr    path_expr,
				     	 uint32_t category_id
			       	       );
     */
#endif
