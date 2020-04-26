#ifndef H_DBG_UTIL_H
    #define H_DBG_UTIL_H

    #include <inttypes.h>
    #include "hc_interface.h"
    #include "H_test_config.h"

    #ifdef H_DEBUG_TEST

	typedef struct h_dbg_util
	{
	    void (*h_dbg_register_sym_change)(int regidx);
	    void (*h_dbg_memory_sym_change)( uint32_t vaddr, 
			    		     int      size 
					   );

	    // HHui added at April 7th, 2012
	    #ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
	    void (*h_dbg_taint_byte_refered)(int idx);
	    #endif

	}h_dbg_util_t, *Ph_dbg_util_t;


	void dbg_taintcheck_register_check(int reg);

	void dbg_taintcheck_memory_check(uint32_t vaddr);

	void dbg_taintcheck_EFLAGS_check(int bit_idx);

	void dbg_dump_path_expr( );

	void dbg_dump_expr( HExpr  expr,
			    char * filename,
			    char * tc_filename,
			    int	   category    // 0 --- not-generate testcase; 1 --- otherwise;
			  );

	#ifdef H_DBG_CHECK_MONITORED_MACHINE_STATE
	void dbg_set_dbgutil_4_temu( );

	void dbg_delete_dbgutil_4_temu( );

	void dbg_taint_byte_refered(int idx);

	// utils for GDB
	/* ---------------------------------------------------------------- */
	void dbg_set_monitored_sym_memory( uint32_t vaddr,
					   int	    size
					 );
	
	void dbg_set_monitored_sym_register(int regidx);

	void dbg_set_monitored_taint_byte_idx(int idx);
	/* ---------------------------------------------------------------- */
	#endif
    #endif
#endif
