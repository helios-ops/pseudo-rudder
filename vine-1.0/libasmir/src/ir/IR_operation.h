#ifndef HH_IR_OPERATION_H
	#define HH_IR_OPERATION_H

	
	// extern "C"
	//{
		int HH_translate_ASM_to_VineIR( unsigned char * inst_bytes,
				      	      	address_t       inst_vaddr,  // virtual address for the istruction
						unsigned	inst_len
					      );

		void HH_print_cur_vine_ir( );

		void HH_Init_Translation( char *   prog_name,
					  uint32_t base_va,
					  uint32_t size,
					  void (*term_printf)( const char * fstr, ... )
					);

		void HH_Cleanup_Translation( );
	//}



	typedef struct IR_module
	{
	    uint32_t 	       base_va;
	    uint32_t 	       size;
	    uint32_t 	       rebase_offset;

	    asm_program_t *    prog_t;
	    vine_blocks_t *    vine_total_blocks;

	    struct IR_module * next;
	}IR_module_t, *PIR_module_t;


	typedef struct IR_module_list
	{
	    struct IR_module * head;
	    struct IR_module * end;

	    int  count;
	}IR_module_list_t, *PIR_module_list;

#endif
