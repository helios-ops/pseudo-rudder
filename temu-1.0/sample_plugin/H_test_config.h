#include "../config-host.h"

#ifndef H_TEST_CONFIG_H
    #define H_TEST_CONFIG_H
    
/* Here are some global switch-macroes */


    // should we mask the original 'optimize_FLAGS( )' in 'translate.c' ??
    #ifndef H_MASK_OPTIMIZE_INSN_EFLAGS_CALC
	#define H_MASK_OPTIMIZE_INSN_EFLAGS_CALC
    #endif


// HHui added at March 12th, 2012
/* ======================================================================================== */
    // should we use protocol analysis results ?? --------- TO ANALYSE FIXED-LENTH INPUT ??
    #ifndef H_USE_PROTOCOL_ANALYSIS
	#define H_USE_PROTOCOL_ANALYSIS
    #endif
/* ======================================================================================== */


    // should we make hardcodingly patch in order to save-load correct thread-context ??
    #ifndef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
	#define H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
    #endif


    #ifndef HH_TRACE_MONITOR
	#define HH_TRACE_MONITOR

        
	// should we record the concrete-instructions along the path ?
	#ifndef HH_TRACE_MONITOR_NOT_TAINTED_INSN
	    #define HH_TRACE_MONITOR_NOT_TAINTED_INSN
	#endif
	

	// should we monitor symaddr-access along the path ?
	#ifndef H_TRACE_MONITOR_SYMADDR_ACCESS
	    #define H_TRACE_MONITOR_SYMADDR_ACCESS
	#endif
    #endif

/*
    // should we ignore sym-state change by some concrete executions in unfocused modules ??
    #ifndef H_IGNORE_SYM_STATE_CHANGE_IN_UNFOCUSED_MODULE
	#define H_IGNORE_SYM_STATE_CHANGE_IN_UNFOCUSED_MODULE
    #endif
*/

    // for compositional symbolic-execution
    /* -------------------------------------------------------------- */
    #ifndef INTERESTED_MODULE_MONITOR 
        #define INTERESTED_MODULE_MONITOR 
    #endif


// should we rawly checks a instrution whether it's PUSH/POP or not ?
    #ifndef H_RAW_CHECK_PUSHPOP
	#define H_RAW_CHECK_PUSHPOP
    #endif


// ------------------------ enabling function-summary analysis ?? ------------------------ */
    #ifdef HHUI_FUNC_SUMMARY_ENABLED
	// #define HHUI_FUNC_SUMMARY_ENABLED

	// should we hook-specially some interested functions ?
	#ifndef HH_INTERTESTED_FUNC_ANALYSIS
	    #define HH_INTERTESTED_FUNC_ANALYSIS
	#endif

	// feedback pre-post conditions to snapshots of a function
	#ifndef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
	    #define HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
	#endif

	/*	
        #ifndef H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
	    #define H_CALL_INSTANCE_SHARE_CALLSITE_SNAPSHOT
	#endif	
	*/

        // only introduce stack-argument as formal argument ??
        #ifndef H_FUNC_SUMM_STACKPARAM_ONLY
	    #define H_FUNC_SUMM_STACKPARAM_ONLY
        #endif

	#ifndef H_FUNC_SUMM_CHECK_CALLSITE
	    #define H_FUNC_SUMM_CHECK_CALLSITE
	#endif
    #endif
// ------------------------ enabling function-summary analysis ?? ------------------------ */


    // we display those results when debugging
    #ifndef H_FUNC_SUMM_RESULT_DEBUG_DUMP
	#define H_FUNC_SUMM_RESULT_DEBUG_DUMP
    #endif


    #ifndef H_PATH_EXPR_TESTCASE_GENERATION
	#define H_PATH_EXPR_TESTCASE_GENERATION
    #endif

    /*
    #ifndef H_MANUALLY_SEARCHING_FOR_BRANCHES
	#define H_MANUALLY_SEARCHING_FOR_BRANCHES
    #endif
    */

    /*
    #ifndef _H_DEBUG_TEST
	#define _H_DEBUG_TEST
    #endif
    */
    #ifndef H_DEBUG_TEST
	#define H_DEBUG_TEST

	// should we check for taint-changes of those focused registers or memory locations ??
	#ifndef H_DBG_CHECK_MONITORED_MACHINE_STATE
	    #define H_DBG_CHECK_MONITORED_MACHINE_STATE
	#endif

	// should we check when some interested taint-byte is referenced ??
	#ifndef H_DBG_CHECK_TAINT_BYTE_REFERENCED
	    #define H_DBG_CHECK_TAINT_BYTE_REFERENCED
	#endif

    #endif

    /*
    #ifndef H_FUNC_CALLING_SEQUENCE_RECORD
	#define H_FUNC_CALLING_SEQUENCE_RECORD
    #endif
    */

/*
    // just for test !
    #ifdef H_FUNC_SUMM_VC_PREASSERT
	#undef H_FUNC_SUMM_VC_PREASSERT
    #endif
*/
    /* -------------------------------------------------------------- */
    // for compositional symbolic-execution


    #ifndef HHUI_MONITOR_ONLY_USERSPACE
	#define HHUI_MONITOR_ONLY_USERSPACE
    #endif

/*-------- HHui temply removed at Dec 1st, 2011 for small experimental purpose --------*/
// #ifdef HHUI_FUNC_SUMMARY_ENABLED    
    /*
    #ifndef HHUI_IDA_INTEREdSTED_FUNC_IGNORE
	#define HHUI_IDA_INTEREdSTED_FUNC_IGNORE
    #endif
    */
// #endif


    // mask symbolic-execution when encountering some special hooks
    #ifndef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK
	#define HHUI_INTERESTED_FUNCTION_SYMEXE_MASK
    #endif


    /* purely an experimental purpose, just only SYM-EXE the instructions belong to the thread introducing taints.
       NOTE: here, I would only monitor just 1 target thread !
     */
    #ifndef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
	#define HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
    #endif


// there exists problem in vine's print-IR util
/*
    #ifndef H_PRINT_IR
	#define H_PRINT_IR
    #endif
*/
    
    // should we make parametre check at API-callage, malloc( ) etc.
    #ifndef HHUI_API_CALL_CHECK_TAINT_PARAMETRE
	#define HHUI_API_CALL_CHECK_TAINT_PARAMETRE
    #endif



    // for callstack analysis, should we consider only those APP-level callstacks ?
    #ifndef HHUI_CALLSTACK_MONITOR_ONLY_APPLEVEL
	#define HHUI_CALLSTACK_MONITOR_ONLY_APPLEVEL
    #endif

    
    // TODO: several scanning rules could be defined here.
    /* ============================================================================================================= */
    /*  when we encounter a path with a special SYM-ERROR condition, should we 
	continue searching the path with other valid conditions ? 
	Defining 'H_VULSCAN_ONCE_ENOUGH' would say 'no' to IR-SYMEXE, which would
	in turn switch-off the SYM-EXE for the following part in the path.
	otherwise, IR-SYMEXE should make a complete search which is not perfectly
	implemented in the current version.
     */
    #ifndef H_VULSCAN_ONCE_ENOUGH
        #define H_VULSCAN_ONCE_ENOUGH
    #endif
    /* ============================================================================================================= */
    

    // should we not care the target's execution until some taints were introduced.
    #ifndef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
	#define HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
    #endif


    // should we care only those interested exploitable taint sources
    #ifndef HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
        #define HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
    #endif

    /* here are several state-monitoring utils which we could change by calling the corresponding 
       modifying functions during the debugging session. 
       Notify: when we build the final version, these should be disabled !
     */
    #ifndef HHUI_DEBUG_MODIFY_STATE
	#define HHUI_DEBUG_MODIFY_STATE
    #endif


    
    #ifndef IR_SYMBOLIC_EXECUTION
        #define  IR_SYMBOLIC_EXECUTION
    #endif

    /*
    #ifndef H_SYMEXE_REP_OPTIMIZE
	#define H_SYMEXE_REP_OPTIMIZE
    #endif
    */
#endif
