#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>

#include "ir_printer.h"
#include "../src/include/irtoir.h"
#include "IR_operation.h"
#include "../../../VEX/pub/libvex.h"

VexArch vexarch_of_prog(asm_program * prog);
	
using namespace std;

extern IR_module_list_t  ir_module_list;


/* translate a single ASM-instruction to vine-IR.
 */
vine_block_t * HH_asm_insn_2_vine_ir( PIR_module_t module_entry,
									       uint32_t     	insn_vaddr,
									       uint8_t *    	insn_bytes,
									       uint32_t     	insn_count
								 	     )
{
     VexArch	    guest;
     asm_program_t * h_prog     = NULL;
     vine_block_t 	* h_vine_ir = NULL;
     Instruction		* h_insn      = NULL;

     vector<vine_block_t *> h_vec;

     h_insn  		   = new Instruction;
     h_insn->address  = insn_vaddr;
     h_insn->length    = insn_count;
     h_insn->bytes     = insn_bytes;

     h_prog     = module_entry->prog_t;         
     guest       = vexarch_of_prog(h_prog);
     h_vine_ir = new vine_block_t;
     h_vine_ir->inst = h_insn;

     if(!is_special(h_insn))
     {
	   h_vine_ir->vex_ir = translate_insn( guest,
					   				   insn_bytes,
			   					          insn_vaddr
					  			        );
     }
     else
     {
	   h_vine_ir->vex_ir = NULL;
     }// end of if(!is_special(h_insn))

     h_vec.push_back(h_vine_ir);

     h_vec = generate_vine_ir( h_prog,
			      			      h_vec
			    			    );
    
     return h_vine_ir;
}// end of HH_asm_insn_2_vine_ir( )




