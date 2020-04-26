/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

/********************************************************************
 * @file sample_plugin.c
 * @author: Heng Yin <hyin@cs.berkeley.edu>
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "config.h"

#include "../taintcheck.h"
#include "../shared/procmod.h"
#include "../shared/hooks/function_map.h"
#include "../slirp/slirp.h"
#include "../TEMU_lib.h"
#include "../shared/hookapi.h"
#include "../shared/read_linux.h"
#include "../shared/reduce_taint.h"
#include <xed-interface.h>

// #include "network.h"

#include "H_test_config.h"

#include "H_taint_record.h"


#include "eflag_tc_monitor.h"

// #include "insn_taint_state.h"


#include <dlfcn.h>


#include "H_cpu.h"

// #include "IR_operation.h"
#include "module_notify.h"


#include "main.h"
#include "proc_notify.h"


#include "Reg_convert.h"
#include "insn_effect_restore.h"


#include "H_STP_stub.h"

#include "stp_variables.h"
#include "HVM_state.h"


#include "jcc_pred_branch.h"
#include "branch_save.h"

#include "winxpsp2_vad.h"

#include "FileHandle.h"
#include "H_malloc_data.h"

#include "call_analysis.h"

#include "taintcheck_hook.h"

#include "HH_encap_taintcheck.h"

#include "winxp_threading.h"
#include "record_potential_error2file.h"

#include "thread_context.h"

#include "dbg_util.h"

#ifdef H_DEBUG_TEST
extern uint32_t dbg_interested_eip;
#endif

// insn-dst-operand-list -------- defined in "insn_effect_restore.c"
extern Insn_dst_list h_insn_dst_list;


// switches for several vulnerability scanning policies.
/* ======================================================================= */
int H_vulscan_once_enough_err_found = 0;
/* ======================================================================= */


HVC   HHui_VC;

/* ---------------------------------------------------------------------------------------------- */
// record the constraint-expression summarized along a particular execution path !
HExpr path_Expr;

// function's current local-pre-condition expressed through local function's formal parametres
HExpr * func_precondition_expr = NULL;

// function's current local-pre-condition expressed through local function's actual parametres
HExpr   func_local_ending_expr = NULL;
/* ---------------------------------------------------------------------------------------------- */


// nonsense !
HExpr hhui_expr;

// seq_num of file records ERROR path-expression
static int error_fd_seq_num = 0;
static int temp_fd_seq_num  = 0;


extern int cur_monitored_proc_fd ;


// IR Symbolic Execution Engine ! 
// prototype in IR_SYMEXE.so's symbol table : _Z21symexe_asm_vine_blockPv
// symexe_asm_vine_block
SYMEXE_ASM_VINE_BLOCK  symexe_asm_vine_block;

static int block_should_monitor = 0;

// IR lifting related functions
/* ==================================================================================================== */
static GETCONCRETEMEMDATA	  HH_GetConcreteMemData;


/*
static ASM_TO_VINE_IR 	    	  HH_translate_ASM_to_VineIR;
static PRINT_CURRENT_VINE_IR	  HH_print_cur_vine_ir;
static INIT_TRANSLATION	    	  HH_Init_Translation;
static CLEANUP_TRANSLATION   	  HH_Cleanup_Translation;
 */

ASM_TO_VINE_IR 	    	  HH_translate_ASM_to_VineIR;
PRINT_CURRENT_VINE_IR	  HH_print_cur_vine_ir;
INIT_TRANSLATION	  HH_Init_Translation;
CLEANUP_TRANSLATION   	  HH_Cleanup_Translation;

GET_HH_TEMU_INFO	      	  Get_HH_Temu_Info;
SET_HH_TEMU_CONCRETE_READ  	  Set_HH_Temu_Concrete_Read;


// let SYM-EXE obtain STP utils
OBTAIN_STP_UTILS_FROM_PLUGIN	  Obtain_stp_utils_From_plugin;

#ifdef H_DEBUG_TEST
GET_TEMU_DBGUTIL Get_temu_dbgutil;
#endif

void * parser_so_handle ;
/* ==================================================================================================== */
// IR lifting related functions




// #include "key_taint_source_list.h"
/* ---------------------------------------------------------------------- */
tpage_entry_t ** tpage_table; //!<memory page table

uint64_t * HH_regs_bitmap    = 0; //!<bitmap for registers
uint8_t  * HH_regs_records   = NULL; //!<taint records for registers

uint32_t * HH_eflags_bitmap  = 0; //!<bitmap for eflags
uint8_t  * HH_eflags_records = NULL; //!<taint records for eflags
/* ---------------------------------------------------------------------- */


plugin_interface_t my_interface;

char current_mod[128] = "";

char current_proc[128] = "";
int  current_proc_set  = 0 ; 

PMODULE_ENTRY cur_module = NULL;


/* flag indicating whether or not the monitored process has been terminated. 
   0 ------- monitored but not terminated
   1 ------- terminated 
  -1 ------- proc not begin yet
 */
int  cur_proc_terminated = -1; 



char monitored_proc[128] = "";
char image_path[128]     = "";

// int should_monitor = 0;

static int taint_sendkey_id = 0;
static int table_lookup_enabled = 1;

FILE * my_log = NULL;

xed_state_t xedState;


uint32_t modified_EFLAGS;



// HHui Data Structure
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
uint32_t HHui_target_cr3 = 0 ; // CR3 to uniquely identify out the target process
uint32_t HHui_target_pid = 0 ;


uint32_t HHui_current_monitored_eip = 0 ;

/*
#ifdef H_RAW_CHECK_PUSHPOP
uint32_t current_inst_is_PUSHPOP = 0;
uint32_t current_inst_org_esp	 = 0;
uint32_t org_inst_executed_esp   = 0;
#endif
*/

// extern PMODULE_INFO_LIST HHui_module_list;

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */ // HHui Data Structure



// utils used to make sure the concrete instruction is taint-propagation-related or not
/* --------------------------------------------------------------------------------------------------------------- */
static int HH_taint_instruction  = 0;  // flag indicating whether the concrete instruction is taint or not
static int HH_tainted_addressing = 0;

static int LastisREP = 0;
int isREP = 0;

void reg_write_callback( uint32_t regidx, 
			 int	 size
		       )
{
    return ;
}// end of reg_write_callback( )

void reg_read_callback( uint32_t regidx, 
			int	 size
		      )
{
    int i = 0;

#ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
    // temply only caring for 32-bit archs
    H_taint_record_t records[4];
#endif

    uint32_t current_CR3 = 0 ;  

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000)
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif

    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
#endif

    TEMU_read_register( cr3_reg, 
			&current_CR3
		      );

    uint64_t tc_bmap = 0;
    

    if( (HHui_target_cr3 == current_CR3) &&
	(HHui_current_monitored_eip != 0) &&
        (*TEMU_cpu_eip == HHui_current_monitored_eip)
      )
    {
	if(cur_module != NULL)
	{
	    #ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
	    tc_bmap = taintcheck_register_check( (regidx / 4),
					         (regidx % 4),
					 	 size,
					 	 records
				       	       );
	    #else
	    tc_bmap = taintcheck_register_check( (regidx / 4),
					         (regidx % 4),
					 	 size,
					 	 NULL
				       	       );
	    #endif
	    if(tc_bmap != 0)
	    {
		HH_taint_instruction = 1;

		#ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
		for(i = 0; i < size; i = i + 1)
		{
		    if( tc_bmap & (1 << i) )
		    {
			dbg_taint_byte_refered( records[i].offset );
		    }// end of if(tc_bmap)
		}// end of for{i}
		#endif
	    }// end of if( )	    

	}// end of if( )

    }// end of if( )

}// end of reg_read_callback( )


void mem_write_callback( uint32_t vaddr, // mem virtual addr !
	       		 uint32_t paddr,
	       		 int	 size
	     	       ) 
{
    // PMODULE_ENTRY cur_module;

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif

/*
    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)
 */

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
#endif

    uint32_t current_CR3 = 0 ;  

    TEMU_read_register( cr3_reg, 
			&current_CR3
		      );

    uint64_t tc_bmap = 0;

    if( (HHui_target_cr3 != 0) &&
	(HHui_target_cr3 == current_CR3) &&
	(HHui_current_monitored_eip != 0) // &&
        // (*TEMU_cpu_eip == HHui_current_monitored_eip)
      )
    {
	if(cur_module != NULL)
	{	    	   
	    // checking if corresponding accessing address is tainted
	    /* ------------------------------------------------------------- */
	     
	    tc_bmap = taintcheck_register_check( R_A0,
		  			         0,
					         4,
				    		 NULL
				    	       );
	    if(tc_bmap != 0)
	    {		
		HH_taint_instruction = 1;
	    }
	    else
	    {
	        tc_bmap = taintcheck_register_check( R_T0,
		  			             0,
					             4,
				    		     NULL
				    	           );
		if(tc_bmap != 0)
	 	{
		     HH_taint_instruction = 1;
		}
		else
		{
		    tc_bmap = taintcheck_register_check( R_T1,
		 	 			         0,
					             	 4,
				    		     	 NULL
				    	               );
		    if(tc_bmap != 0)
		    {
		        HH_taint_instruction = 1;
		    }// end of if( )

		}// end of if( )
	    }// end of if( )
	    /* ------------------------------------------------------------- */	    
	}// end of if( )
    }// end of if( )
}// end of mem_write_callback( )


void mem_read_callback( uint32_t vaddr, // mem virtual addr !
	       		uint32_t paddr,
	       		int	 size
	     	      ) 
{
    int i = 0;

#ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
    H_taint_record_t records[4];
#endif

    // PMODULE_ENTRY cur_module;
    uint32_t current_CR3 = 0 ;  

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif

    
    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)
    
#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
#endif

    TEMU_read_register( cr3_reg, 
			&current_CR3
		      );

    uint64_t tc_bmap = 0;

    if( (HHui_target_cr3 != 0) &&
	(HHui_target_cr3 == current_CR3) &&
	(HHui_current_monitored_eip != 0) &&
        (*TEMU_cpu_eip == HHui_current_monitored_eip)
      )
    {
	if( cur_module != NULL )
	{
	    #ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
	    tc_bmap = taintcheck_check_virtmem( vaddr,
					        size,
				    		records
				    	      );
	    #else
	    tc_bmap = taintcheck_check_virtmem( vaddr,
					        size,
				    		NULL
				    	      );
	    #endif

	    if(tc_bmap != 0)
	    {
		HH_taint_instruction = 1;

		#ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
		for(i = 0; i < size; i = i + 1)
		{
		    if( tc_bmap & (1 << i) )
		    {
			dbg_taint_byte_refered( records[i].offset );
		    }// end of if(tc_bmap)
		}// end of for{i}
		#endif
	    }
	    else
	    {
		// checking if corresponding accessing address is tainted
		/* ------------------------------------------------------------- */
		tc_bmap = taintcheck_register_check( R_A0,
						     0,
					             4,
				    		     NULL
				    	           );
		if(tc_bmap != 0)
	        {
		    HH_taint_instruction = 1;
	        }// end of if( )
		/* ------------------------------------------------------------- */
	    }// end of if( )	    

	}// end of if( )

    }// end of if( )

}// end of mem_read_callback( )
/* --------------------------------------------------------------------------------------------------------------- */

uint32_t jcc_encountered = 0 ;

// void my_conjmp(uint32_t opdata)
int my_cjmp(uint32_t t0)
{

    uint32_t current_CR3 = 0 ;

    xed_decoded_inst_t xedd;  
    xed_error_enum_t   xed_error;

    char  buf[15];
    char  str[100];
    int   stmt_size;

    char insn_bytes[3] ;

#ifdef HH_TRACE_MONITOR	
    char str_tracefile_output[300];
    int  i_tracefile_output_num;
#endif

    HExpr predicate_expr;

    HExpr    branch_expr;
    uint32_t branch_addr;

    // if SATisfiable ?
    int   is_SAT;

    int	     H_predicate  = 0;
    uint32_t fbranch	  = 0;
    uint32_t tbranch	  = 0;
    // HWholeCounterExample wce;

    uint16_t pred_bits    = 0; 

    // PMODULE_ENTRY cur_module = NULL;

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	// free_insn_dst_list( );
	return 0;
    }// end of if(*TEMU_cpu_eip)
#endif


#ifdef H_VULSCAN_ONCE_ENOUGH
    // we've already found an error in this path, so ignore the following SYM-EXE in the path.
    if(H_vulscan_once_enough_err_found != 0)
    {
	// free_insn_dst_list( );
	return 0;
    }// end of if(H_vulscan_once_enough_err_found)
#endif

// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	// free_insn_dst_list( );
	return 0;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      // return;
      // HHui patched at March 21st, 2012      
      return 0;
  }
  else if(my_interface.current_monitored_thread != get_current_tid( ))
  {
      // free_insn_dst_list( );
      // return;
      // HHui patched at March 21st, 2012
      return 0;
  }// end of if(my_interface)
#endif

    if(block_should_monitor == 0)
    {
	// return;
        // HHui patched at March 21st, 2012
        return 0;
    }// end of if(block_should_monitor)    


#ifdef HHUI_FUNC_SUMMARY_ENABLED
    // walk through all instructions until function's end, just to apply those post-conditions
    if(my_interface.func_postcondition_enable != 0)
    {
	// return;
        // HHui patched at March 21st, 2012
        return 0;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	// return;
        // HHui patched at March 21st, 2012
        return 0;
    }// end of if(my_interface)
#endif 

    TEMU_read_register(cr3_reg, &current_CR3);
  
    
/* flag indicating whether or not the monitored process has been terminated. 
   0 ------- monitored but not terminated
   1 ------- terminated 
  -1 ------- proc not begin yet
 */
    // int  cur_proc_terminated = -1; 

    
    if(cur_proc_terminated != 0)
    {
	// return t0;
        // HHui patched at March 21st, 2012
        return 0;
    }// end of if( )
    

    if(cur_proc_terminated == 1)
    {
	// return 1;
        // HHui patched at March 21st, 2012
        return 0;
    }// end of if( )


/*
    // checks if any bit in EFLAG is tainted with SYM-EXPR
    if( !symcheck_EFLAG( ) )
    {
	return 1;
    }// end of if( )
 */


    // Now just only focus on the target monitored process !
    
    if( ( HHui_target_cr3 != 0 ) &&
	( HHui_target_cr3 == current_CR3 ) && // &&	
	( HHui_current_monitored_eip != 0) // &&
	// ( HHui_current_monitored_eip == *TEMU_cpu_eip )
	
	
      )
    {
/*
	if( (cur_module = Find_Module_for_VA( HHui_current_monitored_eip )) == NULL )
	{
	    return 1;	
	}// end of if( )
 */
	if(cur_module == NULL)
	{
	    // return 1;
            // HHui patched at March 21st, 2012
            return 0;
	}// end of if(cur_module)

	TEMU_read_mem( HHui_current_monitored_eip,
		       3,
		       insn_bytes
		     );
	

    #ifdef H_DEBUG_TEST
    if( (dbg_interested_eip != 0) && 
	(dbg_interested_eip == HHui_current_monitored_eip)
      )
    {
	term_printf( " dbg : my_cjmp( ) ---- HHui_current_monitored_eip: %x\n",
		     HHui_current_monitored_eip
		   );
    }// end of if( )
    #endif

	if( !( ( (uint32_t)( insn_bytes[0] ) >= 0x70 ) &&
	       ( (uint32_t)( insn_bytes[0] ) <= 0x7F )
	     ) 	       
	  )
	{
	    if( !( ( (uint32_t)( insn_bytes[0] ) == (uint32_t)0x0F )  &&
		   ( ( (uint32_t)( (uint8_t)( insn_bytes[1] ) ) >= (uint32_t)0x80 ) &&
		     ( (uint32_t)( (uint8_t)( insn_bytes[1] ) ) <= (uint32_t)0x8F )
		   )
		 )
	      )
	    {
		// return 1;
		// HHui patched at March 21st, 2012
	        return 0;
	    }// end of if( )

	}// end of if( )
	
 	    jcc_encountered = 1;

	    xed_decoded_inst_set_mode( &xedd, 
				       XED_MACHINE_MODE_LEGACY_32, 
				       XED_ADDRESS_WIDTH_32b
				     );
    	
            // TEMU_read_mem(*TEMU_cpu_eip, 15, buf);
   	    // HHui_current_monitored_eip = *TEMU_cpu_eip;
	    TEMU_read_mem( HHui_current_monitored_eip, 
			   15, 
			   buf
			 );

    	    xed_error = xed_decode( &xedd, 
    	     	                    STATIC_CAST(const xed_uint8_t*,buf),
                                    15
				  );


	    if(xed_error == XED_ERROR_NONE) 
            {
                xed_decoded_inst_dump_intel_format(&xedd, str, sizeof(str), 0);		
		
	    // HHui added at April 8th for debugging purpose
	    /* ----------------------------------------------------------------------- */
	    #ifdef H_DEBUG_TEST
		if(str[0] != 'j')
		{
		    term_printf( "fucking my_cjmp( ) ! ---- insn[%x] is %s\n",
				 HHui_current_monitored_eip,
				 str
			       );
		}// end of if(str[0])

		/*
		if(modified_EFLAGS != 0)
		{
		    term_printf( "fucking my_cjmp( ) ! ---- modified_EFLAGS = %x\n",
				 modified_EFLAGS
			       );
		}// end of if(modified_EFLAGS)
		*/
	    #endif
	    /* ----------------------------------------------------------------------- */

		// checks if any bit in EFLAG is tainted with SYM-EXPR
		/*
	        if( !symcheck_EFLAG( ) )
	        {
		    return 1;
	        }// end of if( )
 		*/

		concrete_jcc_branch_analyze( buf,
					     HHui_current_monitored_eip, //*TEMU_cpu_eip,
					     xedd._decoded_length,
					     &H_predicate,
					     &tbranch,
					     &pred_bits // predicates' indices
		  	        	   );


		if(symcheck_EFLAG(pred_bits) == 0)
		{		    

/* ---------------------------------------------------------------------------------------------- */
#ifdef HH_TRACE_MONITOR
    #ifdef HH_TRACE_MONITOR_NOT_TAINTED_INSN
		    if(cur_monitored_proc_fd != -1)
		    {
		        i_tracefile_output_num = sprintf( str_tracefile_output, 
							  "[tid:%x]--%s:0x%x --- %s --- %s\n",
							  my_interface.current_monitored_thread, // tid
							  (cur_module->module_info).name,        // module-name
						          HHui_current_monitored_eip,
						          str,
						          "clear"
						        );

    		        write( cur_monitored_proc_fd,
			       str_tracefile_output, 
			       i_tracefile_output_num
			     );			   
		    }// end of if( )
    #endif
#endif
/* ---------------------------------------------------------------------------------------------- */

		    // return 1;
		    /* ================================================== */
		    /*
		    // HHui patched at March 21st, 2012		    
		    if(H_predicate == 0)
		    {
	                return 2;
		    }
		    else
		    {
			return 1;
		    }// end of if(H_predicate)
		    */
		    /* ================================================== */
		    return 0;
		}// end of if( )
		

		// lift the asm instruction into vine IR	
		/* ---------------------------------------------------------------------------------------------- */	          	     	
	      	stmt_size = HH_translate_ASM_to_VineIR( buf,
				  	    	        HHui_current_monitored_eip,  // virtual address for the istruction
						      	xedd._decoded_length
			    	       		      );

	        

		if(stmt_size != 0)
	     	{		
		    term_printf( "%s!: eip=%08x %s, thread=0x%x \n", 
		                 // monitored_proc, 
			         (cur_module->module_info).name,
			         HHui_current_monitored_eip,
		                 str,
			         get_current_tid( )
			         // xedd._decoded_length
 		               );


                /* ----------------------------------------------------------------------------------------- */
	        #ifdef HH_TRACE_MONITOR
		    if(cur_monitored_proc_fd != -1)
		    {
		        i_tracefile_output_num = sprintf( str_tracefile_output, 
						          "[tid:%x]--%s:0x%x --- %s --- %s\n",
							  my_interface.current_monitored_thread, // tid
							  (cur_module->module_info).name,        // module-name
						          HHui_current_monitored_eip,
						          str,
						          "tainted"
						        );
			str_tracefile_output[i_tracefile_output_num] = '\0';

    		        write( cur_monitored_proc_fd,
			       str_tracefile_output, 
			       i_tracefile_output_num
			     );			   
		    }// end of if( )
	        #endif
                /* ----------------------------------------------------------------------------------------- */



		    term_printf( "Address %d ---------- Stmts num = %d\n", 
			         HHui_current_monitored_eip, //*TEMU_cpu_eip,
		     	         stmt_size      
		   	       );

		    term_printf("\n----------------------------- Vine IR lifting -----------------------------\n");

		#ifdef H_PRINT_IR	    
    	      	    HH_print_cur_vine_ir(term_printf);
		#endif		    

		    term_printf( "IR Block found for address %d\n", 
				 *TEMU_cpu_eip
			       );	

  		    term_printf("\n---------------------------------------------------------------------------\n");
		}// end of if(stmt_size)   

		/* ---------------------------------------------------------------------------------------------- */
	    	// lift the asm instruction into vine IR
		    		    
		if(stmt_size != 0) 
	  	{
		    // special SYM-EXE for branching stmt !
		    fbranch = 0 ;

		    // update current predicate-VC !
	   	    fbranch = xedd._decoded_length + *TEMU_cpu_eip;	


		    symexe_asm_vine_block( HHui_VC,
					   // &predicate_expr,
					   &path_Expr,
					   &predicate_expr, //&branch_addr,

					   H_predicate,
					   tbranch,
					   fbranch,
					   branch_save,

					   0 // isREP
					 );		    
		}
		#ifdef H_DEBUG_TEST
		else
		{
		    term_printf( "invalid-translation for %x ------ stmt-size = 0\n",
				 HHui_current_monitored_eip
			       );
		}
		#endif
		// end of if(stmt_size)
		    		

	
	    }// end of if(xed_error)	    

    }// end of if( )


 
    // return 1;
    /* ================================================== */
    /*
    // HHui patched at March 21st, 2012
    if(H_predicate == 0)
    {
	return 2;
    }
    else
    {
	return 1;
    }// end of if(H_predicate)
    */
    return 0;
    /* ================================================== */
}// end of my_cjmp(uint32_t t0)



void stp_error_handler(const char * err_msg)
{
    term_printf( "STP error : %s\n", 
		 err_msg
	       );
}// end of stp_error_handler( ) 


static void do_monitor_proc(char *proc)
{
  // term_printf("sizeof(H_taint_record_t) is %d\n", sizeof(H_taint_record_t));

  char * image_ptr = (char *)(image_path + 2);
  // record the specific process's CR3 value for further identifying it out 

  // HHui_target_pid = find_pid_by_name(proc);
  // HHui_target_cr3 = find_cr3(HHui_target_pid);  

  term_printf("HHui new process : %s\n", proc);

  strncpy(monitored_proc, proc, 128);  
  
  // Ensure the image file copy to be IR-lifted would be in the current directory
  image_path[0]	= '.';
  image_path[1] = '/';

  strcpy(image_ptr, monitored_proc);
  printf("Process image path = %s\n", image_path);

/*  
  HH_Init_Translation(image_path);
 */ 

  current_proc_set = 1 ;

}// end of do_monitor_proc(char *proc)




//Send a tainted keystroke with a specified origin.
/* --------------------------------------------------------------------------------------------------- */
void do_taint_sendkey(const char *string, int id)
{
  // static int key_source_id = 0 ;
  
  // key_source_id = key_source_id + 1;
  

  uint32_t current_CR3;
  char     current_proc_name[128];
  uint32_t current_proc_id = 0 ;

  if(HHui_target_pid == 0)
  {
      return ;
  }// end of if( )


  taint_sendkey_id = id;
  printf("do_taint_sendkey( ) ------------ HHui_keystroke_taint_id = %d\n", taint_sendkey_id) ;
  

  do_send_key(string);

}// end of do_taint_sendkey(const char *string, int id)
/* --------------------------------------------------------------------------------------------------- */



void display_current_modules( )
{
    Display_current_modules_in_list( ) ;
}// end of display_current_modules( )



static term_cmd_t my_term_cmds[] = 
{
  { "taint_sendkey", "si", (void (*)())do_taint_sendkey,
    "key id", "send a tainted key to the guest system"},
/*
  {"taint_nic", "i", (void (*)())do_taint_nic,
   "state", "set the network input to be tainted or not"},

*/
  { "linux_ps", "", (void (*)())do_linux_ps,
    "", "list the processes on linux guest system"
  },
  { "guest_ps", "", (void (*)())list_procs,
    "", "list the processes on guest system"
  },
  { "monitor_proc", "s", (void (*)())do_monitor_proc,
    "proc_name", "monitor a process"
  },

/* ------------------------------------ HHui added commands ! ------------------------------------  */
  { "display_current_modules", "", (void (*)())display_current_modules,
    "", "display the desired modules currently loaded in the monitored process"
  },

  /* =============================================================================================================== */
  { "focus_module", "s", (void (*)())get_focused_modules,
    "modules-list", "spcify the focused modules to symbolic-execute on(the modules' names should be separated by '-')"
  },

  { "focuse_module_from_file", "", (void (*)())get_focused_modules_from_file,
    "focuse_module_from_file", "specify total focused modules by designating the file-list containing the names"
  },  
  /* =============================================================================================================== */


  /* =============================================================================================================== */
  { "total_interested_modules", "s", (void (*)())get_total_modules,
    "total_list", "specify total interested modules to symbolic-execute on(the modules' names should be separated by '-')"
  },

  { "total_interested_modules_from_file", "", (void (*)())get_total_modules_from_file,
    "total_module_list_from_file", "specify total interested modules by designating the file-list containing the names"
  },
  /* =============================================================================================================== */

  { "dbg_display_total_interested_modules", "", (void(*)())dbg_display_total_interested_modules,
    "display_total_interested_modules", "dbg-util: display_total_interested_modules"
  },

  { "callstack_dump", "", (void (*)())dump_callstack,
    "callstack", "dump the backtrace contents in the callstack"
  },

  { "list_monitored_threads", "", (void (*)())list_total_threads_in_monitored_process,
    "threads", "list all the threads in the monitored process"
  },

#ifdef H_MANUALLY_SEARCHING_FOR_BRANCHES
  { "search_new_path", "", (void (*)())H_search_new_path,
    "new_path", "Sym-Exe new path"
  },
#endif
/*
#ifdef HHui_FUNC_SUMMARY_SNAPSHOT_FEEDBACK
  { "func_callsite_stats", "i", (void (*)())func_summ_callsite_cond_dump,
    "func_callsite_statistics", "list all statistics about the specific function's callsite"
  }, 
#endif
*/
/* ------------------------------------------------------------------------------------------------ */

  {NULL, NULL, (void (*)( ))NULL, NULL}
};



static term_cmd_t my_info_cmds[] = 
{
  {NULL, NULL},
};




// record up all concrete values of the dest operands originally taint-free now tainted by the ASM instruction
static void 
my_taint_propagate( int		      nr_src,
		    taint_operand_t * src_oprnds,
		    taint_operand_t * dst_oprnd,
		    int mode
		  )
{
    /*
    xed_decoded_inst_t xedd;
    uint8_t buf[15];
    char    str[128];

    int      stmt_size       = 0;
    uint32_t current_CR3     = 0 ;

    PMODULE_ENTRY cur_module = NULL;

        

    TEMU_read_register(cr3_reg, &current_CR3);
  
    // Now just only focus on the target monitored process !
    if(HHui_target_cr3 == current_CR3)  
    {    

	if(dst_oprnd->taint == 0)
	{
	}

	add_insn_dst_opnd( uint32_t     con_value,
				opnd_type_t  type,
				int	     byte_num
		      	      );    

    }// end of if( )

    */

}// end of my_taint_propagate(int nr_src, taint_operand_t * src_oprnds, taint_operand_t * dst_oprnd, int mode)




//parse the message from guest system to extract OS-level semantics
static void my_guest_message(char *message)
{
    switch (message[0]) 
    {
        case 'P':
	    parse_process(message);
	    break;
        case 'M':
   	    parse_module(message);
	    break;
    }// end of switch{ }

}// end of my_guest_message(char *message)




//This callback is invoked at the beginning of each basic block
static int my_block_begin( )
{
    uint32_t    current_CR3;
  
#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return 0;
    }// end of if(*TEMU_cpu_eip)
#endif

    TEMU_read_register(cr3_reg, &current_CR3);

    block_should_monitor = 0;
  
    if( current_proc_set != 1 )
    {
  	return 0;
    }// end of if( )


    if(HHui_target_cr3 == 0)
    {
	return 0;
    }// end of if(HHui_target_cr3)

    should_monitor = (HHui_target_cr3 == current_CR3) ? 1 : 0 ;
  
  
    if (!should_monitor)
    {	
	return 0;
	//goto finished;	
    }// end of if( )
  
/*
#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      goto finished;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      goto finished;
  }// end of if(my_interface)
#endif
*/

    // decides if we should monitor the following instructions in this block
    cur_module = Find_Module_for_VA(*TEMU_cpu_eip);

    if(cur_module != NULL)
    {
        block_should_monitor = my_interface.is_in_focused_module ;
    }// end of if(cur_module)
    
finished:

    //we should always check if there is a hook at this point, 
    //no matter we are in the monitored context or not, because 
    //some hooks are global.
    hookapi_check_call(should_monitor);
    return 0;
}// end of my_block_begin()




//This callback is invoked for every instruction
static void my_insn_begin( )
{
    xed_decoded_inst_t xedd;

    uint32_t current_CR3;

    char     buf[20];
    char     str[128];
    
    uint32_t org_esi = 0;
    uint32_t org_edi = 0;

#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
    h_thread_context_t * cur_thread_context = NULL;
#endif

    // HHui patched at April 8th, 2012
    modified_EFLAGS = 0;


    // PMODULE_ENTRY cur_module = NULL;
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
    if(my_interface.symexe_enabled_for_taint == 0)
    {
	return;
    }// end of if(my_interface.symexe_enabled_for_taint)
#endif

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( *TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif
 
#ifdef H_VULSCAN_ONCE_ENOUGH
    // we've already found an error in this path, so ignore the following SYM-EXE in the path.
    if(H_vulscan_once_enough_err_found != 0)
    {
	return;
    }// end of if(H_vulscan_once_enough_err_found)
#endif

#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(my_interface.current_monitored_thread != get_current_tid( ))
  {
      return;
  }
#endif

// HHui added at March 7th, 2012
#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
  else
  {
      cur_thread_context = fetch_thread_context_by_tid(my_interface.current_monitored_thread);
      *TEMU_cpu_eflags   = cur_thread_context->con_eflags;
  }// end of if(my_interface)
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif

    /*
    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)    
     */

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
 
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)
#endif

    if(cur_proc_terminated == 2)
    {
	cur_proc_terminated = 0;
	// BFS_restore_HVM_state_from_snapshot( );	
	return ;
    }// end of if( )


    if(cur_proc_terminated == 1)
    {
	return;
    }// end of if( )


    /* flag indicating whether or not the monitored process has been terminated. 
       0 ------- monitored but not terminated
       1 ------- terminated 
      -1 ------- proc not begin yet
     */
    // int  cur_proc_terminated = -1; 
    /*

    
    if(cur_proc_terminated != 0)
    {
	return;
    }// end of if( )
    */


    if(HHui_target_cr3 == 0)
    {
	HHui_current_monitored_eip = 0;
        return;
    }// end of if( )


    //if this is not the process we want to monitor, return immediately
    TEMU_read_register(cr3_reg, &current_CR3);
    // should_monitor = (HHui_target_cr3 == current_CR3) ? 1 : 0 ;
    
    
    if(HHui_target_cr3 != current_CR3)
    {
	HHui_current_monitored_eip = 0;
	return;
    }// end of if( )

/*
    // if( (cur_module = Find_Module_for_VA(*TEMU_cpu_eip)) == NULL )
    if( (cur_module = Find_Module_for_VA(*TEMU_cpu_eip)
        ) == NULL 
      )
    {
	HHui_current_monitored_eip = 0;
	return;	
    }// end of if( )
 */
    if(cur_module == NULL)
    {
	HHui_current_monitored_eip = 0;
	return;	
    }// end of if(cur_module)

    init_tc_symaddr_mem_restore_list( );

    // initialize the container for dst-con-values    
    init_insn_dst_list( );

    HHui_current_monitored_eip = *TEMU_cpu_eip;

#ifdef H_DEBUG_TEST
    if( (dbg_interested_eip != 0) && 
	(HHui_current_monitored_eip == dbg_interested_eip)
      )
    {
	term_printf( "dbg: my_insn_begin( ) ---- eip = 0x%x\n",
		     HHui_current_monitored_eip
		   );
    }// end of if(HHui_current_monitored_eip)
#endif

/*
#ifdef H_RAW_CHECK_PUSHPOP
    current_inst_is_PUSHPOP = isPushPop(*TEMU_cpu_eip);
    current_inst_org_esp    = TEMU_cpu_regs[R_ESP];

    if(*TEMU_cpu_eip == 0x401010)
    {
	term_printf( "0x401010 --- esp = %x\n",
		     current_inst_org_esp
		   );
    }// end of if(*TEMU_cpu_eip)
#endif
*/

    /*
    PMODULE_ENTRY cur_module = NULL;
    // uint32_t	  current_CR3;
        


    // Now just only focus on the target monitored process !


    
    if( (cur_module = Find_Module_for_VA( HHui_current_monitored_eip )) == NULL )
    {
	return;    
    }// end of if( )
    */


    /*
    xed_decoded_inst_set_mode( &xedd, 
			       XED_MACHINE_MODE_LEGACY_32, 
			       XED_ADDRESS_WIDTH_32b
			     );

    xed_error_enum_t xed_error = xed_decode( &xedd, 
    	     	                             STATIC_CAST(const xed_uint8_t*,buf),
                                             15
				           );



    if(xed_error == XED_ERROR_NONE) 
    {
        xed_decoded_inst_dump_intel_format(&xedd, str, sizeof(str), 0);

	// term_printf("HHui @!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		
        term_printf( "%s!: eip=%08x %s \n", 
	             //monitored_proc, 
		     (cur_module->module_info).name,
		     HHui_current_monitored_eip,
	             str// ,
		     // xedd._decoded_length
 	           );

	// prefetch the desired concrete values
	// HHui_get_xed_dst_operand(&xedd);

    }// emd of if( )
    */
    
    TEMU_read_register( esi_reg,
			&org_esi
		      );
    add_insn_dst_opnd( org_esi,
		       (R_ESI * 4),
		       OPND_REG_VALUE,
		       4
		     );

    TEMU_read_register( edi_reg,
		    	&org_edi
		      );
    add_insn_dst_opnd( org_edi,
		       (R_EDI * 4),
		       OPND_REG_VALUE,
		       4
		     );

}// end of my_insn_begin( )




//This callback is invoked for every keystroke
static void my_send_keystroke(int reg)
{
  if(HHui_target_pid == 0)
  {
     return ;
  }// end of if( )

  printf("\n HHui : keystroke accepted ---- dst reg : %d \n", reg);

  // taint_record_t record;
  H_taint_record_t record;
  
    
  if (taint_sendkey_id) 
  {
    //if this keystroke is supposed to be tainted, 
    //we will taint the destination register
    bzero(&record, sizeof(record));
    record.origin = taint_sendkey_id;
    record.offset = 0;
    
    // taint the dst reg : introduce up the taint source
    taintcheck_taint_register(reg, 0, 1, 1, (uint8_t *) &record);

    term_printf("Finished taint reg !\n");
    taint_sendkey_id = 0;
  }// end of if( )

}// end of my_send_keystroke(int reg)



static void my_cleanup( )
{
    procmod_cleanup( );

    hookapi_cleanup( );

    function_map_cleanup( );
    
    Delete_module_list( );

    // HHui added for LEN-analysis at August 15th, 2011
    H_taint_origin_list_delete( );

    // HHui added for call-analysis at August 16th, 2011
    H_callstack_list_delete( );

    // Remove maintained File-related API-hooking infomation !
    delete_filehandle_entry_list( );

    // Remove out those interested modules
    remove_interested_module_list( );

    // HH_Cleanup_Translation( );


    if(parser_so_handle != NULL)
    {
        // cleanup for the IR-lifting mechanism
        // HHui_Cleanup_Translation( );
        HH_Cleanup_Translation( );
        dlclose(parser_so_handle);
    }// end of if( )


    fclose(my_log);
    my_log = NULL;

    // HH_Cleanup_Translation( );

#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
    delete_thread_context_list( );
#endif

#ifdef H_USE_PROTOCOL_ANALYSIS
  file_proto_list_delete( );
#endif

#ifdef H_DBG_CHECK_MONITORED_MACHINE_STATE
  dbg_delete_dbgutil_4_temu( );
#endif
}// end of my_cleanup( )



int my_before_taint_propagate( )
{

    // PMODULE_ENTRY cur_module  = NULL;
    uint32_t 	  current_CR3 = 0;

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif

    TEMU_read_register(cr3_reg, &current_CR3);
  
    // Now just only focus on the target monitored process !
    if(HHui_target_cr3 == current_CR3)  
    { 

#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif

   
        // return 1 : screen out the taint propagation of TEMU
	/*
        if( (cur_module = Find_Module_for_VA(*TEMU_cpu_eip)) == NULL )
	{
	    return 0;
	}// end of if( )
	*/
	
	if(cur_module == NULL)
	{
	    return 0;
	}// end of if(cur_module)

	if(HHui_current_monitored_eip == *TEMU_cpu_eip)
	{	    
  	    term_printf( "my_before_taint_propagate( ) --- eip = 0x%x ---- ECX taint-bitmap = %d\n",
			 *TEMU_cpu_eip,
		         taintcheck_register_check( 1,
						    0,
						    4,
						    NULL
					          )
		       );	    

	}// end of if( )
		   

	return 1;
	// return 0;

    }// end of if( )    
 
    return 0;
}// end of my_before_taint_propagate( )


void my_insn_end( )
{
    uint32_t cur_esi = 0;
    uint32_t cur_edi = 0;

    xed_decoded_inst_t xedd;
    uint8_t buf[30];
    char    str[128];

    int      stmt_size   = 0;
    uint32_t current_CR3 = 0 ;

    int      H_predicate = 0;

    uint32_t branch_addr;
    uint32_t tbranch;
    uint32_t fbranch;
    uint16_t pred_bits;
    HExpr    predicate_expr = NULL;    

#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
    h_thread_context_t * cur_thread_context = NULL;
#endif

#ifdef HH_TRACE_MONITOR	
    char str_tracefile_output[300];
    int  i_tracefile_output_num;
#endif

// As no taints have being introduced, we should not take any interest for the current target's execution.
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
    if(my_interface.symexe_enabled_for_taint == 0)
    {
	// free_insn_dst_list( );
	return;
    }// end of if(my_interface.symexe_enabled_for_taint)
#endif

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    // HHui modified at March 8th, 2012
    // if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    if( (uint32_t)HHui_current_monitored_eip >= (uint32_t)0x80000000 )
    {
	// free_insn_dst_list( );
	return;
    }// end of if(*TEMU_cpu_eip)
#endif

#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
    if(my_interface.current_monitored_thread == 0)
    {
	// free_insn_dst_list( );
        return;
    }
    else if(my_interface.current_monitored_thread != get_current_tid( ))
    {
	// free_insn_dst_list( );
        return;
    }
    // HHui added at March 7th, 2012
    #ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
    else
    {
	if(HHui_current_monitored_eip != 0)
	{
            cur_thread_context = fetch_thread_context_by_tid(my_interface.current_monitored_thread);
            cur_thread_context->con_eflags = *TEMU_cpu_eflags;
	}// end of if(HHui_current_monitored_eip)

    }// end of if(my_interface)
    #endif
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	// free_insn_dst_list( );
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	goto MY_INSN_END_FINAL;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	// free_insn_dst_list( );
	return;
    }// end of if(my_interface)
#endif

    // monitored process, monitored thread, not monitored block
    if(block_should_monitor == 0)
    {
	goto MY_INSN_END_FINAL;
    }// end of if(block_should_monitor)    


    if(jcc_encountered == 1)
    {
	goto MY_INSN_END_FINAL;
    }// end of if( )	


        
    /* flag indicating whether or not the monitored process has been terminated. 
       0 ------- monitored but not terminated
       1 ------- terminated 
      -1 ------- proc not begin yet
     */
    // int  cur_proc_terminated = -1; 
    
    /* ============================================================================================== */
    /*
    int	     i = 0;
    uint64_t m_tcbitmap = 0;
    HExpr    tmp_expr   = NULL;
    uint32_t tmp_value  = 0;
    H_taint_record_t * records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t) * 4 );
    

    // A must !
    HH_taint_instruction = 0;


    free(records);
    */
    /* ============================================================================================== */
    #ifdef H_DEBUG_TEST
    if( (dbg_interested_eip != 0) && 
	(dbg_interested_eip == HHui_current_monitored_eip)
      )
    {
	term_printf( " dbg : my_insn_end( ) ---- HHui_current_monitored_eip: %x\n",
		     HHui_current_monitored_eip
		   );
    }// end of if( )
    #endif


    if(cur_proc_terminated == 1)
    {
	// term_printf("ending !\n");
	concrete_insn_clear_eflags( );
	
	iterate_and_taint_clear_list( );

	// free_insn_dst_list( );
	return;
    }// end of if( )
      
    TEMU_read_register(cr3_reg, &current_CR3);


    // HHui added at March 6th, 2012 
    /* special treat for jcc ------ some jcc may not invoke my_cjmp,
       so I patched here !
     */
    /* -------------------------------------------------------------------------- */
    // Now just only focus on the target monitored process !
    if( (HHui_target_cr3 != 0) &&
	(HHui_target_cr3 == current_CR3) &&
	(HHui_current_monitored_eip != 0)
      )
    {
	if(jcc_encountered == 0)
	{
	    TEMU_read_mem( HHui_current_monitored_eip, 
			   2, 
			   buf
			 );
	    if( ( ( (uint32_t)( buf[0] ) >= 0x70 ) &&
	          ( (uint32_t)( buf[0] ) <= 0x7F )
	        ) ||	      
	        ( ( (uint32_t)( buf[0] ) == (uint32_t)0x0F )  &&
		  ( ( (uint32_t)( (uint8_t)( buf[1] ) ) >= (uint32_t)0x80 ) &&
		    ( (uint32_t)( (uint8_t)( buf[1] ) ) <= (uint32_t)0x8F )
		  )
		)
	    )
	    {
		my_cjmp(1);

		// HHui patched at March 25th, 2012
		/* ================================================== */
		if(jcc_encountered != 0)
		{
		/* ================================================== */

		    goto GENERAL_INSN_END_FINAL;

		// HHui patched at March 25th, 2012
		/* ================================================== */
		}
		/* ================================================== */
	    }// end of if( )	   
	}// end of if(jcc_encountered)
    }// end of if(HHui_target_cr3)
    /* -------------------------------------------------------------------------- */  


    // if( Is_Insn_tainted( ) != 0 )
    if(HH_taint_instruction != 0)
    {	  
/*
#ifdef H_RAW_CHECK_PUSHPOP
    // if it's a symbolic PUSH/POP, I should restore the ESP to its orignal value before execution.
    if(current_inst_is_PUSHPOP != 0)
    {
	org_inst_executed_esp = TEMU_cpu_regs[R_ESP];
	TEMU_cpu_regs[R_ESP]  = current_inst_org_esp;
    }// end of switch{current_inst_is_PUSHPOP}
#endif
*/
	if(HH_tainted_addressing == 1)
	{

	    delete_restore_tc_symaddr_mem_list( );
	}// end of if( )

	// Now just only focus on the target monitored process !
	if( (HHui_target_cr3 != 0) &&
	    (HHui_target_cr3 == current_CR3)  
	  )
	{  
	    /*
	    if( (cur_module = Find_Module_for_VA( HHui_current_monitored_eip )) == NULL )
	    // if( cur_module == NULL )
	    {
		// iterate_and_taint_clear_list( );
		goto GENERAL_INSN_END_FINAL;
		// free_insn_dst_list( );		
		// return;	
	    }// end of if( )
	     */
	    if(cur_module == NULL)
	    {
	        goto GENERAL_INSN_END_FINAL;
	    }// end of if(cur_module)

	    xed_decoded_inst_set_mode( &xedd, 
				       XED_MACHINE_MODE_LEGACY_32, 
				       XED_ADDRESS_WIDTH_32b
				     );
	    	
	    TEMU_read_mem( HHui_current_monitored_eip, 
			   30, 
			   buf
			 );

	    xed_error_enum_t xed_error = xed_decode( &xedd, 
	    	     	                             STATIC_CAST(const xed_uint8_t*,buf),
		                                     30
						   );

	    if(xed_error == XED_ERROR_NONE) 
            {
                xed_decoded_inst_dump_intel_format(&xedd, str, sizeof(str), 0);		
		
                term_printf( "%s!: eip=%08x %s, thread=0x%x \n", 
		             // monitored_proc, 
			     (cur_module->module_info).name,
			     HHui_current_monitored_eip,
		             str,
			     get_current_tid( )
			     // xedd._decoded_length
 		           );
     		

/* ---------------------------------------------------------------------------------------------- */
#ifdef HH_TRACE_MONITOR
		if(cur_monitored_proc_fd != -1)
		{
		    i_tracefile_output_num = sprintf( str_tracefile_output, 
						      "[tid:%x]--%s:0x%x --- %s --- %s\n",
						      my_interface.current_monitored_thread, // tid
						      (cur_module->module_info).name, 	     // module-name
						      HHui_current_monitored_eip,
						      str,
						  // should we monitor symaddr-access along the path ?
						  #ifdef H_TRACE_MONITOR_SYMADDR_ACCESS
						      ( (HH_tainted_addressing == 1) ? "tainted-addr" :
						  #endif
						      "tainted"
						  // should we monitor symaddr-access along the path ?
						  #ifdef H_TRACE_MONITOR_SYMADDR_ACCESS
						      )
						  #endif						
						    );
		    str_tracefile_output[i_tracefile_output_num] = '\0';

    		    write( cur_monitored_proc_fd,
			   str_tracefile_output, 
			   i_tracefile_output_num
		         );			   
		}// end of if( )
#endif
/* ---------------------------------------------------------------------------------------------- */



	     	// lift the asm instruction into vine IR	
      	    	/* -------------------------------------------------------------------------------- */

   	    	term_printf("\n----------------------------- Vine IR lifting -----------------------------\n");            
  	    	stmt_size = HH_translate_ASM_to_VineIR( buf,
			  	    	                HHui_current_monitored_eip,//*TEMU_cpu_eip,  // virtual address for the istruction
					      		xedd._decoded_length
		    	       		    	      );
  		term_printf( "Address 0x%8x ---------- Stmts num = %d\n", 
	      		     //*TEMU_cpu_eip,
			     HHui_current_monitored_eip,
	     	  	     stmt_size      
	   	 	   );

	  	if(stmt_size != 0) 
  	        {    
    		#ifdef H_PRINT_IR
		    HH_print_cur_vine_ir( term_printf );
		#endif
	  	    term_printf( "IR Block found for address %d\n", 
		    		 //*TEMU_cpu_eip
				 HHui_current_monitored_eip
		     	       );	  	    
	      	}
	    #ifdef H_DEBUG_TEST
		else
		{
		    term_printf( "invalid-translation for %x ------ stmt-size = 0\n",
				 HHui_current_monitored_eip
			       );
		}
	    #endif
		// end of if(stmt_size)      
  	        term_printf("\n---------------------------------------------------------------------------\n");      
		
		
  	        /* -------------------------------------------------------------------------------- */
  	        // lift the asm instruction into vine IR

   	        
		// display_insn_total_dst_opnds( );
	        iterate_display_insn_total_dst_opnds( );


// IR Symbolic Execution for the current tainted instruction !
/* ===================================================================================================================================== */
#ifdef IR_SYMBOLIC_EXECUTION
		// symexe_asm_vine_block( HHui_VC ) ;

		/* special treat for instructions like REP, REPNZ */
		if( ( buf[0] == 0xF3 ) ||
		    ( buf[0] == 0xF2 )
		  )
		{
		    // previous instruction is REP, so we would not handle the current instruction's SYM-EXE.
		    /*
		    if(LastisREP)
		    {
			goto MY_INSN_END_FINAL;
		    }// end of if(LastisREP)

		    LastisREP = 1;
		    */

		    isREP = 1;
		    concrete_jcc_branch_analyze( buf,
					         HHui_current_monitored_eip,
					         xedd._decoded_length,
					         &H_predicate,
						 &tbranch,
						 &pred_bits 
		  	        	       );

		    fbranch = HHui_current_monitored_eip + xedd._decoded_length;
				    
		    // HHui added at 3-pm, March 6th, 2012
		    /* As many pairs of <insn_begin, insn_end> would be invoked during the emulation of 
		       REP-like instructions, we should flap 'H_predicate' so as to notify IRSymEXE just
		       make 1-pass sym-exe, rather than sym-exeing the whole loop.
		     */
		     /*		     
		     if(H_predicate == 0)
		     {
			TEMU_read_register( esi_reg,
					    &cur_esi
					  );
			TEMU_read_register( edi_reg,
					    &cur_edi
					  );

			// possibly not-complete ! TODO: DF-calculation !
			// checks if the current insn_end( ) corresponds to the last round emulation of REP
			if( !( ( ( cur_edi == ((h_insn_dst_list.head)->next)->con_value - 1 ) && 
				 ( (*TEMU_cpu_eflags & (1 << 10)) != 0 ) // DF == 1
			       ) || 
			       ( ( cur_edi == ((h_insn_dst_list.head)->next)->con_value + 1 ) &&    
				 ( (*TEMU_cpu_eflags & (1 << 10)) == 0 ) // DF == 0
			       )
			     )
			  )
			{
			    H_predicate = 1;
			}// end of if(cur_edi)
		     }// end of if(H_predicate)
		     */
		}// end of if( )


		if(stmt_size != 0) 
  	        {

	            symexe_asm_vine_block( HHui_VC,
				           &path_Expr,
				           &predicate_expr,
				           // &branch_addr,

				           H_predicate,
				           tbranch,
				           fbranch,
				           branch_save,

					   isREP
				         );


		}// end of if( )

		// just for debugging !
		/* --------------------------------------------------------------------------------- */
		/* --------------------------------------------------------------------------------- */ // just for debugging !


		if(stmt_size != 0) 
  	        {

		// just for debugging !
		/* --------------------------------------------------------------------------------- */
		
		H_taint_record_t temp_record[4] ;
		uint32_t	 tbmap;
/*
		if( (uint32_t)HHui_current_monitored_eip == 0x4010d6 )
		{
		    tbmap = taintcheck_check_virtmem( 0x12fb56,
			 		              1,
						      temp_record
					 	    );

		    if(tbmap != 0)
		    {
		        term_printf( "special 0x4010d6 --- virtmem[0x12fb56] is symbolic as %s\n", 
				     exprString(temp_record[0].h_expr)
			           );
		    }// end of if( )
		    
		}// end of if( )		
*/
		/* --------------------------------------------------------------------------------- */ // just for debugging !

/*
		    symexe_asm_vine_block( HHui_VC,  
				           // &path_Expr
					   NULL,
					   NULL
				         ) ;
 */

		// just for debugging !
		/* --------------------------------------------------------------------------------- */
		/*
		H_taint_record_t temp_record ;
		uint32_t	 tbmap;

		if( (uint32_t)HHui_current_monitored_eip == 0x004010a0 )
		{
		    tbmap = taintcheck_register_check( R_ECX,
			 		               0,
					   	       1,
						       &temp_record
					 	     );
		    if(tbmap != 0)
		    {
		        term_printf( "IR_SE finish : CL --- index is %d ----- taintbitmap is 0x%x, record-expression is %s\n", 
			  	     R_ECX,
			     	     tbmap,
				     exprString(temp_record.h_expr)
			           );
		    }// end of if( )

		}// end of if( )
		*/
		/* --------------------------------------------------------------------------------- */ // just for debugging !

		    // sym_monitor_EFLAGS( );
		}// end of if( )



		
#endif
/* ===================================================================================================================================== */


	    }// end of if(xed_error == XED_ERROR_NONE) 



	}// end of (HHui_target_cr3 == current_CR3)  


/*
#ifdef H_RAW_CHECK_PUSHPOP
    // if it's a symbolic PUSH/POP, I should restore the ESP to its orignal value before execution.
    if(current_inst_is_PUSHPOP != 0)
    {
	TEMU_cpu_regs[R_ESP] = org_inst_executed_esp;
    }// end of switch{current_inst_is_PUSHPOP}
#endif
*/
    }// 
    else
    {
	;
        /* in fact, if the instruction is not a tainted-instruction, we should clear-up the corresponding modified EFLAGS' symbolic records ! */	
    }// end of if( Is_Insn_tainted( ) != 0 )



    // clear-up those concrete value list
MY_INSN_END_FINAL:

    if(HH_taint_instruction == 0)
    {
	if(cur_proc_terminated == 0)
	{
	    TEMU_read_register(cr3_reg, &current_CR3);
  
	    // Now just only focus on the target monitored process !
	    if( (HHui_target_cr3 != 0) &&
	        (HHui_target_cr3 == current_CR3) 
		// && (HHui_current_monitored_eip != 0) // HHui added at March 6th, 2012 
							/* ==> HHui deleted at March 7th, 2012
							   TOBE CONSIDERED: why (critical for expl.mid) ?
							 */
	      )
	    {        

/* ---------------------------------------------------------------------------------------------- */
#ifdef HH_TRACE_MONITOR
    #ifdef HH_TRACE_MONITOR_NOT_TAINTED_INSN
		if(cur_monitored_proc_fd != -1)
		{
		    // jcc-insn would all be recorded at my_cjmp( ), so here ignore them.
		    if( (jcc_encountered == 0) && 
			(HHui_current_monitored_eip != 0) // &&
			// HHui patched at March 24th, 2012
			// (my_interface.current_monitored_thread != )
		      )
		    {
	    		xed_decoded_inst_set_mode( &xedd, 
						   XED_MACHINE_MODE_LEGACY_32, 
				       		   XED_ADDRESS_WIDTH_32b
				     		 );	    	
	 		TEMU_read_mem( HHui_current_monitored_eip, 
				       30, 
			   	       buf
			 	     );
			xed_error_enum_t xed_error = xed_decode( &xedd, 
	    	     	  		                         STATIC_CAST(const xed_uint8_t*,buf),
		                                     		 30
						   	       );
			if(xed_error == XED_ERROR_NONE) 
            		{
		            xed_decoded_inst_dump_intel_format(&xedd, str, sizeof(str), 0);

		            i_tracefile_output_num = sprintf( str_tracefile_output, 
							      "[tid:%x]--%s:0x%x --- %s --- %s\n",
							      my_interface.current_monitored_thread, // tid
							      (cur_module->module_info).name,        // module-name
						              HHui_current_monitored_eip,
						              str,
						              "clear"
						            );
	    		    write( cur_monitored_proc_fd,
			    	   str_tracefile_output, 
			    	   i_tracefile_output_num
		                 );
			}// end of if(xed_error)
		    }// end of if(jcc_encountered)
		}// end of if(cur_monitored_proc_fd)
    #endif
#endif
/* ---------------------------------------------------------------------------------------------- */

		//if(jcc_encountered == 0)
		//{
		    // term_printf("000000000");
	            // concrete_insn_clear_eflags( );
	    /*
	    #ifdef H_IGNORE_SYM_STATE_CHANGE_IN_UNFOCUSED_MODULE
		if(cur_module != NULL)
		{
	    #endif
	    */
		    // HHui patched at March 24th, 2012
		    /* ====================================================================== */
		    if( (my_interface.current_monitored_thread != 0) &&
		        (my_interface.current_monitored_thread == get_current_tid( ))
		      )
		    {
		    /* ====================================================================== */

	                iterate_and_taint_clear_list( );		    
	                *HH_eflags_bitmap = *HH_eflags_bitmap & (~modified_EFLAGS);

		    // HHui patched at March 24th, 2012
		    /* ====================================================================== */
		    }// end of if(my_interface.current_monitored_thread)
		    /* ====================================================================== */

	    /*
	    #ifdef H_IGNORE_SYM_STATE_CHANGE_IN_UNFOCUSED_MODULE
		}// end of if(cur_module)
	    #endif
	    */
		// }// end of if( )

	    }// end of if(HHui_target_cr3)
 	}// end of if(cur_proc_terminated)
    }// end of if( )

GENERAL_INSN_END_FINAL:

    /*
    if(HH_taint_instruction != 0)
    {
	if( ( (HHui_target_cr3 != 0) &&
	      (HHui_target_cr3 == current_CR3)  
	    )
	  )
	{
	    term_printf( "taintcheck_check_virtmem( ) is at address 0x%x --- ",
			 (uint32_t)taintcheck_check_virtmem
		       );
	    uint64_t mem_status = taintcheck_check_virtmem( 0x12FAF4,
							    1,
							    NULL
							  );
	    term_printf( "memstatus = 0x%x\n",
			 (( mem_status != 0 ) ?  1 : 0)
		       );
	}// end of if( )
    }// end of if( )
    */

/*
#ifdef H_RAW_CHECK_PUSHPOP
    current_inst_is_PUSHPOP    = 0;
#endif
*/
    // clean-up the instruction's taint-effect of EFLAGS 
    modified_EFLAGS    	       = 0;

    HH_tainted_addressing      = 0;
    HH_taint_instruction       = 0;
    HHui_current_monitored_eip = 0;
    free_insn_dst_list( );    
	
    jcc_encountered = 0;

    // term_printf("insn_end!\n");
}// end of my_insn_end( )




void  H_get_insn_dst_concrete_value( taint_operand_t *dst_oprnd )
{
/*
    uint32_t	 current_CR3;

    opnd_type_t  dst_type;
    uint32_t	 dst_value;
    int		 dst_byte_num;	    

    int		 index;
    int		 offset;

    int 	 width = dst_oprnd->size;

    uint32_t	 TEMU_reg_index;

    TEMU_read_register(cr3_reg, &current_CR3);
  

    // term_printf("Now getting the concrete summary !\n");

    // Now just only focus on the target monitored process !    
    
    if(HHui_target_cr3 == current_CR3)  
    {   



	switch(dst_oprnd->type)
	{
	    case 0:
	    {
		// concrete value of register

		// dst_type       = OPND_REG_VALUE;	
		term_printf( "H_get_insn_dst_concrete_value( ) : regidx = %d, regoffset = %d, regsize = %d, taint-bitmap = %x\n",
			     (dst_oprnd->addr / 4),
			     (dst_oprnd->addr % 4),
			     (dst_oprnd->size),
	
			     taintcheck_register_check( (dst_oprnd->addr / 4),
							(dst_oprnd->addr % 4),
							(dst_oprnd->size),
							NULL
						      )
			   );

		
		TEMU_reg_index = Convert_taint_reg_to_TEMU_reg( dst_oprnd->addr,
								width
							      );

		if( TEMU_reg_index == ( (1<<32) - 1 ) )		
		{
		    return ;
		}// end of if( )

		TEMU_read_register( TEMU_reg_index,
				    &dst_value
				  );
		
		break;
	    }
	    
	    case 1:
	    {
		// concrete value of memory

		dst_type     = OPND_MEM_VALUE;

		TEMU_read_mem( dst_oprnd->addr,
			       width,
			       &dst_value
			     );

		break;
	    }
	    
	}// end of switch{ }



	
	add_insn_dst_opnd( dst_value,
			   dst_oprnd->addr,
			   dst_type,
			   width
		         );
	
	
	
    }// end of if( )
    */
    
}// end of H_get_insn_dst_concrete_value( )



void HHui_memory_write_access( uint32_t addr,
			       int      size //,
			       // int      access_mode // 0 -- read ; 1 -- write
		             )
{
    uint32_t current_CR3;
    uint32_t con_value;

    // PMODULE_ENTRY cur_module = NULL;

    uint64_t           tc_bmap = 0;
    H_taint_record_t * records = NULL;

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif


/*
    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)
 */

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
#endif

    TEMU_read_register(cr3_reg, &current_CR3);
  
    // Now just only focus on the target monitored process !
    if(HHui_target_cr3 != current_CR3)
    {
	return;
    }// end of if( )



// temply delete by HHui at August 25th, 2011
/*
    if( (*TEMU_cpu_eip != HHui_current_monitored_eip ) &&
	(*TEMU_cpu_eip - HHui_current_monitored_eip > 10)
      )
    {
	return;	
    }// end of if( )
 */

    // term_printf("m\n");

    // Now just only focus on the target monitored process !
    TEMU_read_mem( addr,
	           size,
		   &con_value
		 );


    add_insn_dst_opnd( con_value,
	  	       addr,
		       OPND_MEM_VALUE,
		       size
		     );

    if(HH_tainted_addressing == 1)
    {	
	records = (H_taint_record_t *)malloc(sizeof(H_taint_record_t) * size);
	tc_bmap = taintcheck_check_virtmem( addr,
					    size,
					    records
					  );
	
	add_tc_symaddr_mem_addr_entry_to_list( addr,
					       size,
					       tc_bmap,
					       records
					     );
	free(records);
    }// end of if( )

/*
    if( HHui_current_monitored_eip == 0x40b89a)
    {
	uint64_t mem_status = taintcheck_check_virtmem(0x12)
    }// end of if( )
 */
    /*
    if( (cur_module = Find_Module_for_VA( HHui_current_monitored_eip )) != NULL )
    {
	// checking if corresponding accessing address is tainted
	tc_bmap = taintcheck_register_check( R_A0,
		  			     0,
					     4,
				    	     NULL
				    	   );
	if(HHui_current_monitored_eip == 0x4010AA)
	{
	    term_printf( "0x4010AA ------ memory-write -------- address-tcbmap = 0x%x\n",
			 tc_bmap
		       );	   
	}// end of if(HHui_current_monitored_eip)
	
        if(tc_bmap != 0)
	{		
	    HH_taint_instruction = 1;
	}// end of if(tc_bmap)
    }// end of if(cur_module)
    */
}// end of HHui_memory_access( )



void HHui_write_register_access( uint32_t regidx,
				 int      offset,
			      	 int      size
			       )
{
    // 8 general registers' concrete value obtainment
    uint32_t current_CR3;
    uint32_t con_value;

    int      tc_regidx; 
    uint32_t temu_regidx;

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif


/*
    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)
 */

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
#endif

    TEMU_read_register(cr3_reg, &current_CR3);
  

    // Now just only focus on the target monitored process !
    if(HHui_target_cr3 != current_CR3)
    {
	return;
    }// end of if( )


// temply delete by HHui at August 25th, 2011
    // if( (cur_module = Find_Module_for_VA(*TEMU_cpu_eip)) == NULL )
    /*
    if( (*TEMU_cpu_eip != HHui_current_monitored_eip ) &&
	(*TEMU_cpu_eip - HHui_current_monitored_eip > 10)
      )
    {
	return;	
    }// end of if( )
    */

    tc_regidx = regidx * 4 + offset;
    temu_regidx = Convert_taint_reg_to_TEMU_reg( tc_regidx,
					         size
				      	       );

    if( ((1 << 32) - 1) == temu_regidx )
    {
	// term_printf("fuck!");

	return;
    }// end of if( )

    
    /*   
    term_printf( "eip = 0x%8x, tc_regidx = %d, temu_regidx = %d\n",
		 *TEMU_cpu_eip,
	         tc_regidx,
		 temu_regidx
	       );
    */

    TEMU_read_register( temu_regidx,
		 	&con_value		
		      );
    
    add_insn_dst_opnd( con_value,
	  	       tc_regidx,
		       OPND_REG_VALUE,
		       size
		     );
  

}// end of HHui_write_register_access( )


/* --------------------------------------------------------------------------------------------- */


void HHui_modify_EFLAGS_access(uint32_t mask)
{
    uint32_t current_CR3;    

    int      tc_regidx; 
    uint32_t temu_regidx;

    // modified_EFLAGS = 0 ;

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)HHui_current_monitored_eip >= (uint32_t)(0x80000000) )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif


#ifdef H_DEBUG_TEST
    if(HHui_current_monitored_eip == 0x7d062b15)
    {
	term_printf("insn: 0x7d062b15\n");
    }// end of if(*TEMU_cpu_eip)
#endif

// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(my_interface.current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif


/*
    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)
 */

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
#endif

    // if( (cur_module = Find_Module_for_VA(*TEMU_cpu_eip)) == NULL )
/*
    if( (*TEMU_cpu_eip != HHui_current_monitored_eip ) ||
	(HHui_current_monitored_eip == 0)
      )
    {
	return;	
    }// end of if( )
 */
    TEMU_read_register(cr3_reg, &current_CR3);  
    // Now just only focus on the target monitored process !
    if(HHui_target_cr3 != current_CR3)
    {
	return;
    }// end of if( )

    modified_EFLAGS = mask;


    /* in fact, if the instruction is not a tainted-instruction, we should clear-up the corresponding modified EFLAGS' symbolic records ! */
/*
    if(HH_taint_instruction == 0)
    {
	*HH_eflags_bitmap = *HH_eflags_bitmap & (~mask);
    }// end of if( )
 */

}// end of HHui_modify_EFLAGS_access( )
/* --------------------------------------------------------------------------------------------- */


void mysymbolic_addressing_check(uint32_t reg_idx)
{
    uint64_t tc_bitmap   = 0;
    uint32_t current_CR3 = 0;
    TEMU_read_register(cr3_reg, &current_CR3);  

#ifdef HHUI_MONITOR_ONLY_USERSPACE
    if( (uint32_t)*TEMU_cpu_eip >= (uint32_t)0x80000000 )
    {
	return;
    }// end of if(*TEMU_cpu_eip)
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    if(my_interface.is_in_cur_interested_func != 0)
    {
	return;
    }// end of if(my_interface.is_in_cur_interested_func)
#endif


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(my_interface.current_monitored_thread == 0)
  {
      return;
  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return;
  }// end of if(my_interface)
#endif


    if(block_should_monitor == 0)
    {
	return;
    }// end of if(block_should_monitor)

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    if(my_interface.func_postcondition_enable != 0)
    {
	return;
    }// end of if(my_interface)

    if(my_interface.focused_func_started == 0)
    {
	return;
    }// end of if(my_interface)
#endif

    // Now just only focus on the target monitored process !
    if(HHui_target_cr3 != current_CR3)
    {
	return;
    }// end of if( )

    tc_bitmap = taintcheck_register_check( reg_idx,
					   0,
					   4,
					   NULL
					 );
    if(tc_bitmap != 0)
    {
	HH_tainted_addressing = 1;
	HH_taint_instruction  = 1;
    }// end of if( )

}// end of mysymbolic_addressing_check( )


PHVM_param_t  param;

void H_update_after_loadvm(const char * param)
{
    
}// end of H_update_after_loadvm( )


plugin_interface_t * init_plugin( )
{

  if (!(my_log = fopen("plugin.log", "w"))) 
  {
    fprintf(stderr, "cannot create plugin.log\n");
    return NULL;
  }// end of if( )  

 

  // loading the Vine-IR Lifting and SymExecuting dll
  /*
  parser_so_handle = dlopen( "IR_op.so",
		       	     0
		     	   );
  */
  // IR_SymEXE.so
  parser_so_handle = dlopen( "IR_SymEXE.so",
		       	     0
		     	   );

  if(parser_so_handle == NULL)
  {
    term_printf("Module IR_SymEXE.so loading failure !\n");
    return NULL;
  }// end of if( )


  // IR Lifting utils
  /* ---------------------------------------------------------------------------------------------------- */

//_Z26HH_translate_ASM_to_VineIRPhj

  // HH_translate_ASM_to_VineIR = (ASM_TO_VINE_IR)dlsym(parser_so_handle, "_Z26HH_translate_ASM_to_VineIRPhj");
  // _Z26HH_translate_ASM_to_VineIRPhyj
  HH_translate_ASM_to_VineIR = (ASM_TO_VINE_IR)dlsym(parser_so_handle, "_Z26HH_translate_ASM_to_VineIRPhjj");
								      //_Z26HH_translate_ASM_to_VineIRPhjj
									
  // HH_translate_ASM_to_VineIR = (ASM_TO_VINE_IR)dlsym(parser_so_handle, "HH_translate_ASM_to_VineIR");

  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "HH_translate_ASM_to_VineIR");
    return NULL;
  }// end of if( )


// _Z20HH_print_cur_vine_irPFvPKczE
  HH_print_cur_vine_ir	  = (PRINT_CURRENT_VINE_IR)dlsym(parser_so_handle, "_Z20HH_print_cur_vine_irPFvPKczE");
  // HH_print_cur_vine_ir	  = (PRINT_CURRENT_VINE_IR)dlsym(parser_so_handle, "HH_print_cur_vine_ir");
  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "HH_print_cur_vine_ir");
    return NULL;
  }// end of if( )

  
  // HH_Init_Translation	  = (INIT_TRANSLATION)dlsym(parser_so_handle, "_Z19HH_Init_TranslationPc");
  HH_Init_Translation	  = (INIT_TRANSLATION)dlsym(parser_so_handle, "_Z19HH_Init_TranslationPcjjPFvPKczE");
								     //_Z19HH_Init_TranslationPcjj
								     //_Z19HH_Init_TranslationPcjj

  // HH_Init_Translation	  = (INIT_TRANSLATION)dlsym(parser_so_handle, "HH_Init_Translation");
  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure ! --- Init_trnaslate = 0x%x\n", "HH_Init_Translation", HH_Init_Translation);
    return NULL;
  }// end of if( )


  HH_Cleanup_Translation  = (CLEANUP_TRANSLATION)dlsym(parser_so_handle, "_Z22HH_Cleanup_Translationv");
  // HH_Cleanup_Translation  = (CLEANUP_TRANSLATION)dlsym(parser_so_handle, "HH_Cleanup_Translation");
  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "HH_Cleanup_Translation");
    return NULL;
  }// end of if( )  
  /* ---------------------------------------------------------------------------------------------------- */
  // IR Lifting utils




  //_Z25Set_HH_TEMU_concrete_readPFijiPvEPFviS_EPFyjiPhEPFyiiiS4_EPFyjiyS4_EPFyiiiyS4_E



  // These functions let IR_SymExe.so know how to interact with TEMU's abstract machine states !
  /* ---------------------------------------------------------------------------------------------------- */
  // _Z25Set_HH_TEMU_concrete_readPFijiPvEPFviS_EPFyjiPhEPFyiiiS4_E
  // _Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_E
  Set_HH_Temu_Concrete_Read = (SET_HH_TEMU_CONCRETE_READ)dlsym( parser_so_handle,
						  // "_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_E"
// "_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_E"
//"_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_EPFvS0_S0_SG_E"						 ////_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_E
// " _Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_EPFvS0_S0_SG_ESK_"

//"_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_EPFvS0_S0_SG_ESK_"
//"_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_EPFvS0_S0_SG_ESK_PFvS0_jiE"
//"_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_EPFvS0_S0_SG_ESK_PFvS0_jE"
//"_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_EPFvS0_S0_SG_ESK_PFvS0_jiE"
//"_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_ijPS0_SG_EPFvS0_S0_SG_ESK_PFvS0_jiEPi"
"_Z25Set_HH_TEMU_concrete_readPjhPvPFijiS0_EPFviiiS0_EPFvjiS0_ES4_PFyjiPhEPFyiiiS7_EPFyjiyS7_EPFyiiiyS7_ES_PFiS0_S0_iS_PS0_SG_EPFvS0_S0_SG_ESK_PFvS0_jiEPi"
);
  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "Set_HH_TEMU_Concrete_Read( )");
    return NULL;
  }// end of if( )  


  // printf("11111=-- OK !\n");
  // _Z16Get_HH_TEMU_InfoPjS_S_PP12_tpage_entryPyPhS_S4_
  // _Z16Get_HH_TEMU_InfoPjS_S_PP12_tpage_entryPyPhS_S4_
  Get_HH_Temu_Info = (GET_HH_TEMU_INFO)dlsym(parser_so_handle, "_Z16Get_HH_TEMU_InfoPjS_S_PP12_tpage_entryPyPhS_S4_");
  if(dlerror( ) != NULL)
  {
    printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "Get_HH_TEMU_Info( )");
    return NULL;
  }// end of if( )  

  HH_GetConcreteMemData = (GETCONCRETEMEMDATA)dlsym(parser_so_handle, "_Z18GetConcreteMemDatajiPv");
  if(dlerror( ) != NULL)
  {
    printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "GetConcreteMemData( )");
    return NULL;
  }// end of if( )  
  /* ---------------------------------------------------------------------------------------------------- */
  // These functions let IR_SymExe.so know how to interact with TEMU's abstract machine states !





  // IR SymExe utils : The symbolic execution engine for a single asm-instruction !
  /* ---------------------------------------------------------------------------------------------------- */
  symexe_asm_vine_block = (SYMEXE_ASM_VINE_BLOCK)dlsym( parser_so_handle,
							// "_Z21symexe_asm_vine_blockPvPS_S0_ijjPFiS_S0_S_ijjjjE"
							"_Z21symexe_asm_vine_blockPvPS_S0_ijjPFiS_S0_S_ijjjjEi"
						      );

  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "symexe_asm_vine_block( )");
    return NULL;
  }// end of if( )
  /* ---------------------------------------------------------------------------------------------------- */

  
  
  Obtain_stp_utils_From_plugin = (OBTAIN_STP_UTILS_FROM_PLUGIN)dlsym( parser_so_handle,
//"_Z28Obtain_stp_utils_From_pluginPFPvvEPFvcEPFS_S_EPFS_S_S_S_EPFS_S_PcS_EPFS_S_S8_iiEPFS_S_S_EPFiS_S_ES7_S5_S5_SE_S7_PFS_S_PS_iES7_SJ_S7_S7_PFS_S_S_S_S_ESE_S7_SL_PFvS_S_EPFvS_S_iEPFvS_PS8_PmEPFvS_S_SQ_SR_EPFvS_ESX_SX_SV_SX_SN_SE_SG_SE_PFiS_ESX_SX_SZ_PFjS_EPFyS_EPFS_S_iES5_PFS_S_S8_EPFS_S_ijEPFS_S_iyEPFS_S_jES7_PFS_S_iS_S_ES7_S1F_S7_S1F_S7_S1F_S1F_S1F_S1F_S7_S7_S7_S7_S7_S7_S7_S7_SE_S7_S7_S7_SE_PFS_S_iS_ES1H_S1H_S1H_S7_S7_S7_PFS_S_S_iiEPFS_S_S_iES1L_S17_PFS_S_S_S_iEPFS_S_S_S_S_iEPFS8_S_ES1R_S15_SZ_PFvPFvPKcEESG_SX_"
//"_Z28Obtain_stp_utils_From_pluginPFPvvEPFvcEPFS_S_EPFS_S_S_S_EPFS_S_PcS_EPFS_S_S8_iiEPFS_S_S_EPFiS_S_ES7_S5_S5_SE_S7_PFS_S_PS_iES7_SJ_S7_S7_PFS_S_S_S_S_ESE_S7_SL_PFvS_S_EPFvS_S_iEPFvS_PS8_PmEPFvS_S_SQ_SR_EPFvS_ESX_SX_SV_SX_SN_SE_SG_SE_PFiS_ESX_SX_SZ_PFjS_EPFyS_EPFS_S_iES5_PFS_S_S8_EPFS_S_ijEPFS_S_iyEPFS_S_jES7_PFS_S_iS_S_ES7_S1F_S7_S1F_S7_S1F_S1F_S1F_S1F_S7_S7_S7_S7_S7_S7_S7_S7_SE_S7_S7_S7_SE_PFS_S_iS_ES1H_S1H_S1H_S7_S7_S7_PFS_S_S_iiEPFS_S_S_iES1L_S17_PFS_S_S_S_iEPFS_S_S_S_S_iEPFS8_S_ES1R_S15_SZ_PFvPFvPKcEESG_SX_SX_S5_S7_"
"_Z28Obtain_stp_utils_From_pluginPFPvvEPFvcEPFS_S_EPFS_S_S_S_EPFS_S_PcS_EPFS_S_S8_iiEPFS_S_S_EPFiS_S_ES7_S5_S5_SE_S7_PFS_S_PS_iES7_SJ_S7_S7_PFS_S_S_S_S_ESE_S7_SL_PFvS_S_EPFvS_S_iEPFvS_PS8_PmEPFvS_S_SQ_SR_EPFvS_ESX_SX_SV_SX_SN_SE_SG_SE_PFiS_ESX_SX_SZ_PFjS_EPFyS_EPFS_S_iES5_PFS_S_S8_EPFS_S_ijEPFS_S_iyEPFS_S_jES7_PFS_S_iS_S_ES7_S1F_S7_S1F_S7_S1F_S1F_S1F_S1F_S7_S7_S7_S7_S7_S7_S7_S7_SE_S7_S7_S7_SE_PFS_S_iS_ES1H_S1H_S1H_S7_S7_S7_PFS_S_S_iiEPFS_S_S_iES1L_S17_PFS_S_S_S_iEPFS_S_S_S_S_iEPFS8_S_ES1R_S15_SZ_PFvPFvPKcEESG_SX_SX_S5_S7_PFSH_PiE"
//"_Z28Obtain_stp_utils_From_pluginPFPvvEPFvcEPFS_S_EPFS_S_S_S_EPFS_S_PcS_EPFS_S_S8_iiEPFS_S_S_ES7_S5_S5_SE_S7_PFS_S_PS_iES7_SH_S7_S7_PFS_S_S_S_S_ESE_S7_SJ_PFvS_S_EPFvS_S_iEPFvS_PS8_PmEPFvS_S_SO_SP_EPFvS_ESV_SV_ST_SV_SL_SE_PFiS_S_ESE_PFiS_ESV_SV_SZ_PFjS_EPFyS_EPFS_S_iES5_PFS_S_S8_EPFS_S_ijEPFS_S_iyEPFS_S_jES7_PFS_S_iS_S_ES7_S1F_S7_S1F_S7_S1F_S1F_S1F_S1F_S7_S7_S7_S7_S7_S7_S7_S7_SE_S7_S7_S7_SE_PFS_S_iS_ES1H_S1H_S1H_S7_S7_S7_PFS_S_S_iiEPFS_S_S_iES1L_S17_PFS_S_S_S_iEPFS_S_S_S_S_iEPFS8_S_ES1R_S15_SZ_PFvPFvPKcEESX_SV_"
				 );
  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "Obtain_stp_utils_From_plugin( )");
    return NULL;
  }// end of if( )


#ifdef H_DEBUG_TEST
  Get_temu_dbgutil = (GET_TEMU_DBGUTIL)dlsym( parser_so_handle,
					      "_Z16get_temu_dbgutilPFvPvPcS0_iEPFvS_S_S_S_E"
					    );
  if(dlerror( ) != NULL)
  {
    term_printf("Module IR_SymEXE.so ---- function %s loading failure !\n", "Get_temu_dbgutil( )");
    return NULL;
  }// end of if( )
#endif

  /*
  term_printf( "Module IR_SymEXE.so ---- function %s addr is 0x%8x",
	       "Set_HH_TEMU_Concrete_Read",
	       Obtain_stp_utils_From_plugin
	     );
   */

  /* ---------------------------------------------------------------------------------------------------- */

   /*
  term_printf( "vc_bvSignExtend is 0x%8x\n",
	       vc_bvSignExtend
	     );
    */

/*
  


 */

  function_map_init();


// #ifndef HHUI_FUNC_SUMMARY_ENABLED  
  /* HHui comments at Sep 11th, 2011 
     NOTE: no matter what circumstances it may be, init_hookapi( ) is absolutely neccessary !
  */ 
  init_hookapi( );
// #endif


  procmod_init();


  // File API-hooking !
  /* ================================================================================================ */

#ifdef HHUI_SYMEXE_ONLY_CARE_FOR_INTERESTED_SOURCE
  /* we should notify to temu that these files were the interested potential 
     taint source for our target program.
   */
  H_intersted_file_init_2_temu( &(my_interface.interested_file_names),
				&(my_interface.interested_file_count)
			      );
#endif

  init_filehandle_entry_list( );

  // hook the API openfile( )
  HHui_OpenFile_Hooking( );

  // hook the API CreateFileA & CreateFileW
  HHui_CreateFile_Hooking( );

  // hook the API readfile( )
  HHui_ReadFile_Hooking(&HHui_VC);

  // hook the file-mapping related APIs
  init_fileMapping_list( );
  HHui_CreateFileMapping_Hooking(&HHui_VC);
  my_interface.fetch_fileMappinghandle_entry_by_handle = fetch_fileMappinghandle_entry_by_handle;


  // hook the API SetFilePointer( )
  HHui_SetFilePointer_Hooking( );

  // hook the API CloseHandle( )
  HHui_CloseHandle_Hooking( ) ;
  
  // util for Readfile( )
  my_interface.fetch_filehandle_entry_by_fd = fetch_filehandle_entry_by_fd;

  // util for OpenFile( )
  my_interface.add_filehandle_to_list = add_filehandle_to_list;

  // util for CreateFileMapping( )
  my_interface.add_fileMappinghandle_to_list = add_fileMappinghandle_to_list;

  // util for CloseFile( )
  my_interface.delete_filehandle_from_list = delete_filehandle_from_list;

  // util for malloc( )
  my_interface.add_entry_to_heap_data_list = add_entry_to_heap_data_list;

  // util for free( )
  my_interface.delete_entry_from_heap_data_list = delete_entry_from_heap_data_list;

  /* ================================================================================================ */
  // File API-hooking !



  // HHui_ReadFile_Hooking(HVC * hvc)

  // initialize module info list containing the infos of the modules that should be monitored 
  init_module_list( );
  

  // callback when module loaded for building-up the module list
  loadmodule_notify = (loadmodule_notify_t)HHui_load_module;

  removeproc_notify = (removeproc_notify_t)HHui_remove_proc;
  
  // callback to gain the information for the specific process  
  // createproc_notify = (createproc_notify_t)HHui_CreateProcessNotify;


  loadmainmodule_notify = (loadmainmodule_notify_t)H_Load_MainModule_Notify;


  xed_tables_init( );
  xed_state_zero(&xedState);
  xed_state_init( &xedState, 
		  XED_MACHINE_MODE_LEGACY_32, 
		  XED_ADDRESS_WIDTH_32b, 
		  XED_ADDRESS_WIDTH_32b
		);

  		
  my_interface.plugin_cleanup 	 = my_cleanup;

  // my_interface.taint_record_size = sizeof(taint_record_t);
  my_interface.taint_record_size = sizeof(H_taint_record_t);


  // NO_PROPAGATE is applied !
  my_interface.taint_propagate 	 = my_taint_propagate;


  my_interface.guest_message	 = my_guest_message;
  my_interface.block_begin	 = my_block_begin;

  my_interface.insn_begin	 = my_insn_begin;
  my_interface.insn_end		 = my_insn_end;

  my_interface.term_cmds	 = my_term_cmds;
  my_interface.info_cmds	 = my_info_cmds;

  // my_interface.send_keystroke	 = my_send_keystroke;
/*
  my_interface.nic_recv		 = my_nic_recv;
  my_interface.nic_send		 = my_nic_send;
 */

  my_interface.monitored_cr3	 = 0;

  my_interface.before_taint_propagate = my_before_taint_propagate;

  // conditional jmps
  my_interface.cjmp		 = my_cjmp;

  // my_interface.HHui_conjmp	= my_conjmp;


  // utils for taint-instruction filtering !
  /* --------------------------------------------------------------------------------- */
  my_interface.reg_read	= reg_read_callback;
  my_interface.mem_read = mem_read_callback;

  my_interface.reg_write = reg_write_callback;
  my_interface.mem_write = mem_write_callback;

  my_interface.HHui_symbolic_addressing_check = mysymbolic_addressing_check;
  /* --------------------------------------------------------------------------------- */ // utils for taint-instruction filtering !



  my_interface.HHui_write_memory_access   = HHui_memory_write_access;

  my_interface.HHui_write_register_access = HHui_write_register_access;

  my_interface.HHui_modify_EFLAGS_access  = HHui_modify_EFLAGS_access;

  // my_interface.get_insn_dst_concrete_value = H_get_insn_dst_concrete_value;


  my_interface.BFS_restore_HVM_state_from_snapshot = BFS_restore_HVM_state_from_snapshot;

  my_interface.obtain_vad = WINDOWS_obtain_vad;

  my_interface.IsInMonitoredModules = IsInOurMonitoredModules;


  /* --------------------------------------------------------------------------------- */  
  param = (PHVM_param_t)malloc(sizeof(HVM_param_t));
  param->cur_proc_terminated = &cur_proc_terminated;
  param->hvc		     = &HHui_VC;
  param->path_expr	     = &path_Expr;


  // hooking util for malloc( ) and free( )
  HHui_heapdata_Hooking(param);

/*
#ifdef HHUI_FUNC_SUMMARY_ENABLED
  param->local_func_expr	    = NULL;
#endif
*/
  // param->HHui_current_monitored_eip = &HHui_current_monitored_eip;
  



  my_interface.hvm_load = HHui_vm_loadcb;
  /*
  register_savevm( "HVM_state",
		   0,
		   1,
		   hvm_savecb,
		   hvm_loadcb, // several updates !
		   param
		 );
  */
  /* --------------------------------------------------------------------------------- */
  // register branching-saving/loading utils

  
  // list keeping stp-variables !  
  init_stp_vlist( );

  // HHui added for call-analysis at August 16th, 2011
  H_callstack_list_init( );
  H_callstack_snapshot_util_init( );
  my_interface.call_analysis = H_call_analysis;


  HHui_init_tc_vaddr_list( );

  // records memory symbolic changes for branch_update_vm_state !
  HHui_encap_taintcheck_virtmem_register( );


  // HHui added for LEN-analysis at August 15th, 2011
  H_taint_origin_list_init( );


#ifdef HHUI_FUNC_SUMMARY_ENABLED
  // HHui added for function-summary analysis at August 24th, 2011
  my_interface.h_taintcheck_virtmem_hookfn = taintcheck_virtmem_hookfn;

  my_interface.is_in_focused_module 	 = 0;

  my_interface.focused_func_started      = 0;
  my_interface.func_postcondition_enable = 0;

  my_interface.cur_func_summ_entry       = NULL;

  my_interface.pre_post_cond_snapshot    = 0;

  func_summ_taintcheck_register( );

  init_func_ret_hook_list( );
  register_func_hook( );
#endif


  // my_interface.last_func_postcondition_enable = 0;

  // STP initialization !
  /* ------------------------------------------------- */
  HHui_VC = vc_createValidityChecker( ) ;
  my_interface.hvc = HHui_VC;

  vc_setFlags('n');
  vc_setFlags('p');

// original !
  vc_setFlags('d');
  vc_setFlags('c');

  // VC for current execution path !
  path_Expr = vc_trueExpr(HHui_VC);

  vc_registerErrorHandler( stp_error_handler );
  /* ------------------------------------------------- */ // STP initialization !

/*
#ifdef HHUI_API_CALL_CHECK_TAINT_PARAMETRE
  my_interface.HHui_record_error_expr_2_file = APIHooking_record_ERROR_2file;
#endif
*/

  my_interface.HHui_encap_taintcheck_taint_virtmem = HHui_encap_taintcheck_taint_virtmem;

#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  my_interface.current_monitored_thread = 0;
#endif


// we should mask symbolic-execution when encountering some special function-hooks
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    my_interface.is_in_cur_interested_func = 0;
#endif

// denoting whether or not any taint has appeared so as to determine the SYM-EXE's beginning.
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
    my_interface.symexe_enabled_for_taint = 0;
#endif


#ifdef HHUI_DEBUG_MODIFY_STATE
    my_interface.dbg_enable_taint = 0;
#endif 

#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT    
    init_thread_context_list( );
#endif

// should we use protocol analysis results ??
#ifdef H_USE_PROTOCOL_ANALYSIS
    h_TEMU_build_protocol_analysis_util( );

    file_protocol_list_init( );    
#endif

#ifdef H_DBG_CHECK_MONITORED_MACHINE_STATE
    dbg_set_dbgutil_4_temu( );
#endif

    return &my_interface;
}// end of init_plugin( )


