#ifndef H_INSN_EFFECT_RESTORE_H
	#define H_INSN_EFFECT_RESTORE_H

	#include <inttypes.h>

	#include "H_mem_map.h"


	typedef enum opnd_type
	{
		OPND_REG_VALUE = 0,
		OPND_MEM_VALUE
	}opnd_type_t;


	

	typedef struct insn_dst_opnd
	{		
		uint32_t     	       con_value;

		opnd_type_t	       type;
		uint32_t	       addr;
		
		int		       byte_num;
		
		// HHui patched at April 6th, 2012
		int		       isWritten; // for ESI and EDI
		struct insn_dst_opnd * next ;
	}Insn_dst_opnd, *PInsn_dst_opnd;



	typedef struct insn_dst_list
	{
		PInsn_dst_opnd head;
		PInsn_dst_opnd end;
		
		int	       count;
	}Insn_dst_list, *PInsn_dst_list;


        // main plugin utils
	/* --------------------------------------------------------------------------------------------------------- */
	void init_insn_dst_list( );
	void free_insn_dst_list( );

	void add_insn_dst_opnd( uint32_t     con_value,
				uint32_t     addr,
				opnd_type_t  type,
				int	     byte_num
		      	      );


	// void display_insn_total_dst_opnds( );
	void iterate_display_insn_total_dst_opnds( );



	/* in case when we found that the instruction lastly executed was not taint-propagation-related, 
	   we would clear the relevant taint-status if the relevant operands are tainted previously !
	 */	
	void iterate_and_taint_clear_list( );

	// same functionality as the above exception in that it's related to EFLAGS
	void concrete_insn_clear_eflags( );
	/* --------------------------------------------------------------------------------------------------------- */ // main plugin utils



	// SYM-EXE utils
	/* --------------------------------------------------------------------------------------------------------- */
	void H_read_concrete_register( int    reg_idx, 
		     	     	       int    reg_offset, 
		      	       	       int    reg_size,
		     	      	       void * buf
		   	     	     );

	void H_read_concrete_mem( uint32_t vaddr, 
		 		  int	   len, 
			 	  void *   buf
	      			);


	
	void H_write_concrete_register( int    reg_idx, 
			      	        int    reg_offset, 
				        int    reg_size,
				        void * buf		       
			     	      );

	void H_write_concrete_mem( uint32_t vaddr, 
				   int 	    len, 
				   void *   buf
				 );
	/* --------------------------------------------------------------------------------------------------------- */ // SYM-EXE utils




	// intermediate concrete values' storage locations for SYM-EXE
	/* --------------------------------------------------------------------------------------------------------- */
	extern uint32_t H_general_registers[8];
	extern uint8_t  H_general_registers_bitmap;

        // memory operands
	extern H_mem_mapping_list_t H_map ;
	/* --------------------------------------------------------------------------------------------------------- */



#endif


