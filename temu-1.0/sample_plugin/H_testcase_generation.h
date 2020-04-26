#include <inttypes.h>

#include "hc_interface.h"
#include "H_test_config.h"


#ifdef H_DEBUG_TEST
void dbg_testcase_generate_4_expr( char * filename,
				   HExpr  path_expr
			         );
#endif

#ifdef H_PATH_EXPR_TESTCASE_GENERATION 
    void H_testcase_generate_4_expr( uint32_t HHui_path_id,
				     HExpr    path_Expr
				   );
#endif
