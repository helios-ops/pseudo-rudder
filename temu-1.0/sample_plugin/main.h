/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED

	#include <inttypes.h>
	#include "H_cpu.h"

	#include "hc_interface.h"

        #include "branch_save.h"
// Symbolic execution engine
// typedef int ( * SYMEXE_ASM_VINE_BLOCK )(HVC hvc) ;
/*
       		    symexe_asm_vine_block( HHuiVC,
					   &predicate_expr,
					   &branch_addr,

					   H_predicate,
					   tbranch,
					   fbranch,
					   branch_save   
					 );	
 */
typedef int ( * SYMEXE_ASM_VINE_BLOCK )( HVC         hvc, 
					 HExpr    *  path_expr,
					 HExpr    *  pred_expr, //uint32_t *  ir_fbranch,

					 int	     H_predicate,
					 uint32_t    tbranch,
					 uint32_t    fbranch,
					 BRANCH_SAVE mybranch_save,

					 int	     isREP
				       ) ;



// IR lifting related functions
/* ==================================================================================================================================================== */
typedef int (* ASM_TO_VINE_IR)( unsigned char * inst_bytes,
		      	 	uint32_t	inst_vaddr,  // virtual address for the istruction
				uint32_t 	inst_len
		       	      );

typedef void (* PRINT_CURRENT_VINE_IR)( void (*hterm_printf)( const char * fstr, ... )
				      );

typedef void (* INIT_TRANSLATION)( char *   prog_name,
				   uint32_t base_va,
				   uint32_t size,
				   void (*term_printf)( const char * fstr, ... )
				 );

typedef void (* CLEANUP_TRANSLATION)( );


	// 读取机器信息
typedef void (* SET_HH_TEMU_CONCRETE_READ)( uint32_t * con_general_register,
					    uint8_t    con_general_register_bitmap,
		
					    void *     con_mem_map,		
	
					    int (* f_read_mem)(uint32_t vaddr, int len, void *buf),
		      			    void (* f_read_register)(int reg_id, void *buf),

					    void (* f_write_mem)(uint32_t vaddr, int len, void *buf), 
					    void (* f_write_register)(int reg_id, int reg_offset, int reg_size, void *buf),

					    uint64_t (* f_taintcheck_memory_check)(uint32_t addr, int size,  uint8_t * records),
					    uint64_t (* f_taintcheck_register_check)(int reg, int offset, int size, uint8_t * records),

					    uint64_t (* f_taintcheck_taint_memory)(uint32_t addr, int size, uint64_t taint, uint8_t * records),
					    uint64_t (* f_taintcheck_taint_register)(int reg, int offset, int size, uint64_t taint, uint8_t * records),
					    uint32_t * my_HH_vad_root,
					    int ( *my_HH_build_symaddr_invalid_constraint)( HVC        hvc,
				       							    HExpr      symaddr_expr,
					  	            	                	    int        access_mode,      
									        /* 1 - read; 2 - write; 4 - execute */
								                	    uint32_t * vad_root,
				       					        	    HExpr *    out_of_range_expr,
					 					            HExpr *    invalid_access_expr
				      	           				          ),

					    void (*symaddr_obtain_stack_range_constraint)( HVC     hvc,
											   HExpr   symaddr,
											   HExpr * out_of_range_constraint
										         ),

					    void (*symaddr_stack_eip_overwritten_constraint)( HVC     hvc,
									       		      HExpr   symaddr,
									             HExpr * out_of_range_constraint
									           	    ),

					    void (*HH_error_testcase_generate_4_expr)( HExpr    path_expr,
										       uint32_t category_id,
										       int	local_id
								       	             ),

					    // switches for several vulnerability scanning policies.
					    /* ======================================================================= */
					    int * H_vulscan_once_enough_err_found
					    /* ======================================================================= */
			      		  );



/* 封装给外部插件提供的完全接口，便于本部件获取 Temu 相关的信息外部的完全信息 */
typedef	void (* GET_HH_TEMU_INFO)( uint32_t *  	    TEMU_EFLAGS,   // TEMU_cpu_eflags
			       	   uint32_t *  	    TEMU_EIP,
			       	   uint32_t *       TEMU_CPU_REGS, // array of CPU general-purpose registers, such as R_EAX, R_EBX
				   tpage_entry_t ** TEMU_PAGE_TABLE,

 		    		   uint64_t *	    HH_regs_bitmap,  // taint regs
				   uint8_t  *	    HH_regs_records,
		    
			           uint32_t *       HH_eflags_bitmap, // taint EFLAGS
				   uint8_t  *	    HH_eflags_records
			     	 );

typedef int (* GETCONCRETEMEMDATA)( uint32_t  address, 
			 	    int       len, 
			 	    void *    buf
		       		  );
	

// provide to 'IR_SymExe.so' the dbg-utils for diagnoses during runtime.
typedef void (*GET_TEMU_DBGUTIL)( void (*my_dbg_dump_expr)( HExpr  expr,
							    char * filename,
							    char * tcfilename,
							    int    category
							  ),

			          void (*my_predicate_change)( HVC   hvc,
						               HExpr pred_expr,
					       	      	       HExpr prev_total_expr,
					       	      	       HExpr total_expr
			     	    			     )
			        );
/*===================================================================================================================================================*/	
// IR lifting related functions



#endif
