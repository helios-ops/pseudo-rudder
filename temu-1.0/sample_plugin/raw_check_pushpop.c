/* This module checks if instruction is push/pop-like before execution so as to 
   conserve the semantics' completeness during CON/SYM execution.

   Hard-Coding for x86-instruction not recommended, here I just make the decision from a 
   temporary implementation perspective. 
   [TO DO: a more elegant handling method in future !]
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <H_test_config.h>
#include "../taintcheck.h"
#include "../TEMU_main.h"

/* return value:
   1 ---- PUSH; (not including immediates' PUSH!)
   2 ---- POP;
   0 ---- none of the above 2.
 */
int isPushPop(uint32_t inst_addr)
{
    char opcode = 0;
    
    TEMU_read_mem( inst_addr,
		   1,
		   &opcode
		 );

    /* NOTE: Here I just consider the PUSH/POPs not including those
 	     operand is a segment-register! [HHuiFixme ???]
     */

    // PUSH
    if( (opcode == 0xFF) || (opcode == 0x50) ) 
    {
	return 1;
    }// end of if(opcode)

    // POP
    if( (opcode == 0x8F) || (opcode == 0x58) ) 
    {
	return 2;
    }// end of if(opcode)

    return 0;
}// end of isPushPop( )
