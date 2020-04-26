#include <stdlib.h>
#include <inttypes.h>
#include <malloc.h>

#include "hc_interface.h"
#include "stp_variables.h"

#include "H_cpu.h"
#include "../taintcheck.h"

#include "H_taint_record.h"

#include "../TEMU_main.h"

#include "H_pseudo_x86_cpu.h"

#include "HH_encap_taintcheck.h"

#include "H_test_config.h"

/* -------------------------------------------------------------------------------------------------------- */
extern tpage_entry_t **	 tpage_table; 	   //!<memory page table

extern plugin_interface_t  my_interface;


extern uint64_t * 	HH_regs_bitmap;    //!<bitmap for registers
extern uint8_t  * 	HH_regs_records;   //!<taint records for registers

extern uint32_t * 	HH_eflags_bitmap;  //!<bitmap for eflags
extern uint8_t  * 	HH_eflags_records; //!<taint records for eflags


static int RAM_total_size    = 0;
static int tpage_entry_count = 0;
/* -------------------------------------------------------------------------------------------------------- */



/* This function would be called when a pre-stored branch is loaded 
   in order to build for it a correct concrete machine state.
 */
int branch_update_VM_total_states( HVC   hvc,
				   HExpr branch_expr
				 )
{   int	    x_count   = 0;
    HExpr * x_exprs   = obtaint_stp_vars_array(&x_count);

    term_printf( "stp_variables' count is %d\n",
		 x_count
	       );

    /*
    term_printf( "branch_update_VM_total_states( ) : branch_expr = %s\n",
		 exprString(branch_expr)
	       );
    */

    HExpr   pred_expr = NULL;

    if(x_count == 0)
    {
	return 0;
    }// end of if( )

    if( predicate_form_build( hvc,
			      branch_expr,
			      x_exprs,    // total unit-var-exprs			   
			      x_count,
			      &pred_expr
			    ) == 0
      )
    {
	term_printf( "predicate_form_build( ) --- error !\n"
		   );
	return 0;
    }// end of if( )

    

    // Now do the actual concrete value calculation !
    /* ---------------------------------------------------------------------------- */
    if( update_SYMVM_registers_with_stp_cons( hvc,
					      // branch_expr,
					      pred_expr
			      		    ) &&
        update_SYMVM_memory_with_stp_cons( hvc,
				           // branch_expr,
					   pred_expr
			      	         ) &&
	update_SYMVM_EFLAGS_with_stp_cons( hvc,
				           // branch_expr,
					   pred_expr
			      	         )
      )
    {
	vc_DeleteExpr(pred_expr);
	return 1;
    }// end of if( )
    /* ---------------------------------------------------------------------------- */

    vc_DeleteExpr(pred_expr);
    return 0;
    
}// end of branch_update_VM_total_states( )



int update_SYMVM_registers_with_stp_cons( HVC     hvc,
					  // HExpr   path_expr,
					  HExpr   pred_expr
			      		)
{
    int  i 	    = 0;
    int  j	    = 0;
    uint32_t tbmap  = 0;
    uint32_t res    = 0;

    uint32_t regval = 0;
    uint32_t regidx = -1 ;

    uint32_t mask   = 0;

    HExpr dst_expr = NULL;

    H_taint_record_t * records;
    
    // uint32_t org_reg_val = 0;   
    records = (H_taint_record_t *)malloc(sizeof(H_taint_record_t) * 4);

    // checks for 8 general-purpose registers
    for(i=0; i<8; i=i+1)
    {
	// temu_plugin->x86_cpu = env;

	regval = 0;

	term_printf("HHHHHHHHHHHHHHHHHHHHHHHH\n");
	tbmap = taintcheck_register_check( i,
					   0,
					   4,
					   records
					 );
/*
	regidx = Convert_taint_reg_to_TEMU_reg( i * 4,
						4
					      );

	term_printf( "branch-state-update : obtainted TEMU register index = %d\n",
		     regidx
		   );

	TEMU_read_register( regidx,
			    &regval
			  );
 */
	term_printf( "x86_cpu is at address 0x%x\n",
		     my_interface.x86_cpu
		   );

	regval = ( ( (Ppseudo_x86_cpu_t)(my_interface.x86_cpu)
		   )->regs
		 )[i];


	HType  dst_type = NULL;

	if(tbmap != 0)
	{
	    for(j=0; j<4; j=j+1)
	    {
		if( ( tbmap & (1 << j) 
		    ) == 1
		  )
		{
		    dst_expr = ( (H_taint_record_t *)( (uint32_t)records + j * sizeof(H_taint_record_t)
						     ) 
			       )->h_expr;


		    /*
		    dst_type = vc_getType( hvc,
					   dst_expr
				 	 );		    
		     */
		    dst_type = vc_bvType( hvc,
					  8
					);
		    res = stp_formula_solve( hvc,
					     dst_expr,
					     dst_type,
					     pred_expr
			      		   );

		    mask   = ( 1 << ( (j + 1) * 8 
				    ) 
			     ) - 
			     ( 1 << 
			       (j * 8)
			     );
		    
		    mask   = (1 << 32) - mask;

		    regval = regval & mask;
			
		    regval = regval | ( res << (j * 8) );

		    /*
		    TEMU_write_register( regidx,
					 &regval
				       );
		    
		    term_printf( "branching state restore ---- write to register at tc_index=%d, TEMU_index=%d \n",
				 i,
				 regidx
			       );		    
		    */
		 }// end of if( )

	     }// end of for{j}

/*
	     TEMU_write_register( regidx,
				  &regval
				);
 */
	     ( ( (Ppseudo_x86_cpu_t)(my_interface.x86_cpu)
	       )->regs
	     )[i] = regval;
		    

	     term_printf( "branching state restore ---- write to register at tc_index=%d, TEMU_index=%d, value=0x%x\n",
			  i,
			  regidx,
			  regval
			);

	 }// end of if(tbmap)

    }// end of for{i}

    free(records);


    term_printf("register tc-restoration completed !\n");

    return 1;	


}// end of update_SYMVM_with_stp_cons( )



/* in this case, what was done was targetting towards PHYSICAL_MEM_ADDRESS !
 */
int update_SYMVM_memory_with_stp_cons( HVC   hvc,
				       // HExpr path_expr,
				       HExpr pred_expr
			      	     )
{
    uint8_t mem_val ;
    HExpr   dst_expr;
    HType   dst_type = vc_bvType( hvc, 
				  8
				);

    uint64_t tbitmap = 0;

    PHH_encap_tc_vaddr_entry_t entry = h_encap_vaddr_tclist.head;
    H_taint_record_t * records = NULL;

    for(int i=0; i<h_encap_vaddr_tclist.count; i=i+1)
    {
	records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t) * entry->size
					    );

	tbitmap = taintcheck_check_virtmem( entry->vaddr,
					    entry->size,
					    records
					  );	
	
	if(tbitmap != 0)
        {
	    for(int j=0; j<(entry->size); j=j+1)
	    {
		if(tbitmap & (1 << j))
		{
    		    dst_expr = ( (H_taint_record_t *)( ( (uint32_t)records 
						       ) + 
						       j * sizeof(H_taint_record_t) 
						     ) 
			       )->h_expr;

		    mem_val = stp_formula_solve( hvc,
					     	 dst_expr,
						 dst_type,
					     	 pred_expr
			      		       );

		    TEMU_write_mem( entry->vaddr + j,
				    // entry->size,
				    1,
				    &mem_val
				  );

		    // as TEMU_write_mem( ) would clean up the corresponding taint-record, I make the patch to restore the orginal records
		    /* ----------------------------------------------------------------------------------------------------------------- */
		    taintcheck_taint_virtmem( entry->vaddr + j,
					      1,
					      1,
					      ( (uint32_t)records + j * sizeof(H_taint_record_t) )
					    );
		    /* ----------------------------------------------------------------------------------------------------------------- */

		    
		    term_printf( "writing to virtmem[0x%x] = 0x%x\n", //expr = %s",
				 entry->vaddr + j,
				 mem_val // ,
				 /*
				 exprString( ( (H_taint_record_t *)( (uint32_t)records + j * sizeof(H_taint_record_t) 
								   )
					     )->h_expr
					   )
				 */
			       );



		}// end of if( )

	    }// end of for{ }

	}// end of if( )
	
	entry = entry->next;

	free(records);

	
    }// end of for{ }


    /*
    if(RAM_total_size == 0)
    {
	RAM_total_size    = H_get_ram_size( );
	tpage_entry_count = RAM_total_size / 64;
    }// end of if( )

    tpage_table	  = Get_tpage_table( );

    term_printf( "RAM_total_size = 0x%x, tpage_entry_count = %d, tpage_table is at address 0x%x\n",
		 RAM_total_size,
		 tpage_entry_count,
		 tpage_table
	       );

    dst_type = vc_bvType( hvc,
			  8
			);	

    for(int i=0; i<tpage_entry_count; i=i+1)
    {
	if(tpage_table[i] != NULL)
        {

	    term_printf( "tpage_table[0x%x] = 0x%x\n", 
			 i,
			 tpage_table[i]
		       );

	    term_printf( "tpage_table[%d]->bitmap = 0x%x\n", 
			 i,
			 (tpage_table[i])->bitmap
		       );

	    // 64 bytes per unit
	    if( (tpage_table[i])->bitmap )
	    {
		// test individually the 64 bytes in the unit
		for(int j=0; j<64; j=j+1)
		{
		    // this byte is tainted !
		    if( ( (uint64_t)( (tpage_table[i])->bitmap ) ) & 
			( (uint64_t)( 1 << j ) )
		      )
		    {
			dst_expr =  ( (H_taint_record_t *)( (uint32_t)( ( (tpage_table[i])->records ) 
								      ) + 
							    j * sizeof(H_taint_record_t)
							  )
				    )->h_expr;

			term_printf( "aaaaaa!, sizeof(H_taint_record_t)=%d\n",
				     sizeof(H_taint_record_t)
				   );


			mem_val = stp_formula_solve( hvc,
					     	     dst_expr,
						     dst_type,
					     	     pred_expr
			      		   	   );

			term_printf( "Physical address 0x%x --- tc-restoration !\n",
				     (uint32_t)(i * 64 + j)
				   );

			// now update the concrete machine state of the tainted mem-location by PHYSICAL_ADDRESS writing !
			cpu_physical_memory_rw( (i * 64 + j), // physical address of the mem-location
						&mem_val,
						1,
						1  // is_write !
					      );

		    }// end of if( )

		}// end of for{ }
	    }// end of if( )
		
	}// end of if( )

    }// end of for{ }
    */


    // free(records);
    term_printf("memory tc-restoration completed !\n");
    
    return 1;

}// end of update_SYMVM_memory_with_stp_cons( )



#ifndef H_EFLAG_CARED_BIT_COUNT
    #define H_EFLAG_CARED_BIT_COUNT 7
#endif
static int eflag_bit_indices[H_EFLAG_CARED_BIT_COUNT] = { 0,  // CF
							  2,  // PF
							  4,  // AF
							  6,  // ZF
							  7,  // SF
							  10, // DF
							  11  // OF
							 };


int update_SYMVM_EFLAGS_with_stp_cons( HVC   hvc,
				       // HExpr path_expr, // constraint for current branch
				       HExpr pred_expr
				     )
{
    uint32_t bit_value = 0;
    uint32_t bit_index = 0;
    HExpr    dst_expr  = NULL;

    HType    dst_type  = NULL;


    for(int i=0; i<H_EFLAG_CARED_BIT_COUNT; i=i+1)
    {
	// a tainted EFLAG bit 
	if( ( *HH_eflags_bitmap ) & 
	    ( 1 << eflag_bit_indices[i] )
	  )
	{
	    bit_index = eflag_bit_indices[i];
	    
	    dst_expr  = ( (H_taint_record_t *)( (uint32_t)HH_eflags_records + 
					        bit_index * sizeof(H_taint_record_t)
					      )
			)->h_expr;


/*
	    dst_type = vc_bvType( hvc,
				  1
				);
 */
/*
	 pred_stp_formula_solve( HVC   hvc,				
			    	 HExpr formula_expr,
				 HExpr pred_expr
			       )
 */

	    bit_value = pred_stp_formula_solve( hvc,
				      	        dst_expr,
					        pred_expr
			      		      );
/*
	    TEMU_EFLAGS_write( bit_index,
			       bit_value
			     );
 */
	    if(bit_value != -1)
	    {
		if(bit_value != 0)
		{
		    bit_value = 1;
		}// end of if( )
		
	        ( (Ppseudo_x86_cpu_t)(my_interface.x86_cpu)
	        )->eflags = 
	        ( (Ppseudo_x86_cpu_t)(my_interface.x86_cpu)
	        )->eflags | (bit_value << eflag_bit_indices[i]) ;

	    }// end of if( )



		    

	}// end of if( )

    }// end of for{ }


    term_printf("EFLAGS tc-restoration completed !\n");

    return 1;
}// end of update_SYMVM_EFLAGS_with_stp_cons( )








