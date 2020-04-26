#include <stdlib.h>
#include <inttypes.h>

#include "hc_interface.h"
#include "H_taint_record.h"
#include "TEMU_main.h"


#define EFLAGS_BITS_COUNT 12

extern uint32_t * HH_eflags_bitmap  ; //!<bitmap for eflags
extern uint8_t  * HH_eflags_records ; //!<taint records for eflags

/*
	typedef struct H_taint_record
	{
		HExpr  	  h_expr;
		uint32_t  origin;		
		uint32_t  offset;

	}H_taint_record_t;
*/


char * eflag_bit_name[12] = { "CF", // 0
			      NULL, // 1
			      "PF", // 2
			      NULL, // 3
			      "AF", // 4
			      NULL, // 5
			      "ZF", // 6
			      "SF", // 7
			      "TF", // 8
			      "IF", // 9
			      "DF", // 10
			      "OF", // 11
			    };


void sym_monitor_EFLAGS( )
{
    char * 	       str_bit_expr = NULL;
    H_taint_record_t * record 	    = NULL;
    HExpr	       bit_expr	    = NULL;


    for(int i = 0; i < EFLAGS_BITS_COUNT; i = i + 1)
    {
	// this bit is tainted !
	if( *HH_eflags_bitmap & (1 << i) )
	{
	    record	 = (H_taint_record_t *)( (uint32_t)HH_eflags_records + sizeof(H_taint_record_t) * i 
					       );			   
	    bit_expr	 = record->h_expr;

	    str_bit_expr = exprString(bit_expr);
	
	    if( eflag_bit_name[i] != NULL )
	    {
		
		term_printf( "%s is tainted ---- symbolic-expression is %s\n", // isBool = %d \n",
			     eflag_bit_name[i],
			     str_bit_expr// ,
			     // vc_isBool( bit_expr )
			   );

		

	    }// end of if( )		

	}// end of if( )

    }// end of for{ }

}// end of sym_monitor_EFLAGS( )


int symcheck_EFLAG(uint16_t pred_bits)
{
    // uint32_t jcc_pred_bits = get_jcc_pred(insn_va);
    char * 	       str_bit_expr = NULL;
    H_taint_record_t * record 	    = NULL;
    HExpr	       bit_expr	    = NULL;

    if(pred_bits == 0)
    {
	term_printf("pred_bits == 0 !\n");
    }// end of if(pred_bits)


    for(int i = 0; i < EFLAGS_BITS_COUNT; i = i + 1)
    {
	if( ( 1 << i ) & pred_bits )
	{
	    if( *HH_eflags_bitmap & (1 << i) )
	    {	
		/*
		record = (H_taint_record_t *)( (uint32_t)HH_eflags_records + sizeof(H_taint_record_t) * i 
					     );			   
		bit_expr     = record->h_expr;
		str_bit_expr = exprString(bit_expr);

		term_printf( "%s is tainted ---- symbolic-expression is %s\n", // isBool = %d \n",
			     eflag_bit_name[i],
			     str_bit_expr
			     // vc_isBool( bit_expr )
			   );
		
		*/
	        return 1;
	    }// end of if( )


	}// end of if( )

    }// end of for{ }

    return 0;

}// end of symcheck_EFLAG( )









