/* Restore the concrete values of the dst operatands of the taint instruction for SYMBOLIC-EXECUTION
 */
#include <inttypes.h>
#include <malloc.h>

#include "H_test_config.h"

#include "../TEMU_main.h"

#include "Reg_convert.h"

#include "H_mem_map.h"
#include "insn_effect_restore.h"

Insn_dst_list h_insn_dst_list;


// TEMU CPU states before instruction's execution
/* ------------------------------------------------------------------------------- */
uint32_t H_general_registers[8];

uint8_t  H_general_registers_bitmap;
/* EAX, ECX, EDX, EBX, ESP, SBP, ESI, EDI */


/* ------------------------------------------------------------------------------- */





/* ------------------------------------------------------------------------------- */
extern uint32_t   modified_EFLAGS;

extern uint32_t * HH_eflags_bitmap;  //!<bitmap for eflags
extern uint8_t  * HH_eflags_records; //!<taint records for eflags


/* ------------------------------------------------------------------------------- */



void init_insn_dst_list( )
{
    /* ------------------------------------------------------------------------ */
    for(int i=0; i<8; i=i+1)
    {
	H_general_registers[i] = 0;
    }// end of for{ }

    H_general_registers_bitmap = 0;
    /* ------------------------------------------------------------------------ */

    init_H_mem_map( );

    h_insn_dst_list.head  = NULL;
    h_insn_dst_list.end   = NULL;

    h_insn_dst_list.count = 0;
}// end of init_insn_dst_list( )



void free_insn_dst_list( )
{
    free_H_mem_map( );

    PInsn_dst_opnd pre_entry  = NULL;
    PInsn_dst_opnd post_entry = h_insn_dst_list.head;
    
    while(post_entry != NULL)
    {
	pre_entry  = post_entry->next;
	free(post_entry);
	
	post_entry = pre_entry;
    }// end of while{ }


    h_insn_dst_list.head = NULL;
    h_insn_dst_list.end  = NULL;

    h_insn_dst_list.count = 0 ;


    H_general_registers_bitmap = 0;
}// end of free_insn_dst_list( )



void add_insn_dst_opnd( uint32_t     con_value,
			uint32_t     addr,
			opnd_type_t  type,
			int	     byte_num
		      )
{
    uint32_t reg_idx = 0;

    // HHui patched at March 16th, 2012 (For parsing sym-insn like mov al, [eax])
    /* ------------------------------------------------------------------------------ */
    if(type == OPND_REG_VALUE)
    {
	// for each GP-register, we only store the originally obtained complete concrete value !
	if( H_general_registers_bitmap & (1 << (addr / 4)) )
	{
	    // HHui patched at April 6th, 2012
	    /* ------------------------------------------------------------------------------ */

	    if( (addr / 4) == 6 ) // R_ESI
	    {		
		(h_insn_dst_list.head)->isWritten = 1;		
	    }// end of if((addr / 4))

	    if( (addr / 4) == 7 ) // R_EDI
	    {
		((h_insn_dst_list.head)->next)->isWritten = 1;
	    }// end of if((addr / 4))
	    /* ------------------------------------------------------------------------------ */
	    // HHui patched at April 6th, 2012

	    return;
	}// end of if(H_general_registers_bitmap)
    }// end of if(type)

    // PInsn_dst_opnd con_insn_opnd = malloc( sizeof(Insn_dst_opnd) * byte_num );
    PInsn_dst_opnd con_insn_opnd = malloc( sizeof(Insn_dst_opnd) );

    con_insn_opnd->con_value = con_value;
    con_insn_opnd->addr	     = addr;

    con_insn_opnd->type	     = type;
    con_insn_opnd->byte_num  = byte_num;
    con_insn_opnd->next	     = NULL;

    // HHui patched at April 6th, 2012
    /* ------------------------------------------------------------------------------ */
    con_insn_opnd->isWritten = 0;
    /* ------------------------------------------------------------------------------ */



    // HHui patched at March 16th, 2012 (For parsing sym-insn like mov al, [eax])
    /* ------------------------------------------------------------------------------ */
    if(type == OPND_REG_VALUE)
    {
	/*
	// for each GP-register, we only store the originally obtained complete concrete value !
	if( H_general_registers_bitmap & (1 << (addr / 4)) )
	{
	    
	}// end of if(H_general_registers_bitmap)
	*/

	reg_idx = Convert_taint_reg_to_TEMU_reg( ( (addr / 4) * 4 ),
						 4 // entry->byte_num
					       );
	TEMU_read_register( reg_idx,
			    &(con_insn_opnd->con_value)
			  );

	H_general_registers_bitmap = H_general_registers_bitmap | (1 << (addr / 4));

        con_insn_opnd->byte_num  = 4;
        con_insn_opnd->addr	 = ((addr / 4) * 4);
    }// end of if(type)
    /* ------------------------------------------------------------------------------ */
    
    if( h_insn_dst_list.count == 0 )
    {
	h_insn_dst_list.head = con_insn_opnd;
	h_insn_dst_list.end  = con_insn_opnd;
    }
    else
    {
	(h_insn_dst_list.end)->next = con_insn_opnd;
	h_insn_dst_list.end	    = con_insn_opnd;	
    }// end of if( )

    h_insn_dst_list.count = h_insn_dst_list.count + 1;

}// end of add_insn_dst_opnd( )



void iterate_display_insn_total_dst_opnds( )
{
    if(h_insn_dst_list.count == 0)
    {
	term_printf("No concrete dst values yet !\n");
	return;
    }// end of if( )

    PInsn_dst_opnd entry    = h_insn_dst_list.head;

    char * 	   reg_name = NULL;
    int		   reg_id   = 0 ;
    char * 	   reg_pos  = NULL;

    while(entry != NULL)
    {
	switch(entry->type)
	{
	    case OPND_REG_VALUE:
	    {
		H_general_registers_bitmap = H_general_registers_bitmap | (1 << (entry->addr / 4) );

		// concrete register !
		reg_id   = Convert_taint_reg_to_TEMU_reg( entry->addr, 
							  entry->byte_num
					      	        );

		reg_name = GetRegNameFromId(reg_id);

		term_printf( "%s =  %8x, size = %d\n",
			      reg_name,
			      entry->con_value,
			      entry->byte_num
			   );

		
		reg_pos = (char *)( (unsigned long)( H_general_registers + (entry->addr / 4) ) + (entry->addr % 4) );

		switch(entry->byte_num)
		{
		    case 1:
		    {
			*( (uint8_t *)reg_pos ) = entry->con_value;
			break;
		    }
		    case 2:
		    {
			*( (uint16_t *)reg_pos ) = entry->con_value;
			break;
		    }
		    case 4:
		    {
			*( (uint32_t *)reg_pos ) = entry->con_value;
			break;
		    }
		}// end of switch{ }

		break;
	    }
	    case OPND_MEM_VALUE:
	    {
		// concrete memory data !		
		term_printf( "[0x%8x] = %8x, size = %d\n",
			     entry->addr,
			     entry->con_value,
			     entry->byte_num
			   );		

		// memory !
		add_H_mem_map_entry( entry->addr,
				     entry->byte_num,
				     entry->con_value
			  	   );	

		break;
	    }
	}// end of switch{ }

	entry = entry->next;
    }// end of while{ }

}// end of display_insn_total_dst_opnds( )





// temp storages for concrete memories' calculations
/* ----------------------------------------------------------------------------------------- */
void H_read_concrete_mem( uint32_t vaddr, 
		 	  int	   len, 
			  void *   buf
	      		)
{    
    uint32_t offset = 0;

    H_mem_mapping_entry_t * entry = find_H_mem_map_entry( vaddr,
				    		          len
							);
    if(entry != NULL)
    {
	offset = vaddr - (entry->vaddr);

    #ifdef H_DEBUG_TEST
        if( !( (offset == 0) && 
	       (len == entry->size)
	     )
	  )
	{
	    term_printf("mismatch concrete memory reading !\n");
	}// end of if(offset)
    #endif

	switch(len)
	{
	    case 1:
	    {
		*( (uint8_t *)buf ) = *( (uint8_t *)( ( (uint32_t)( &(entry->con_value) 
							          ) + offset
						      )
					            )
				       );
		break;
	    }
	    case 2:
	    {
		/*
		// HHui patched at March 16th, 2012
		// ------------------------------------------------------------------------
		if(entry->byte_num == 1)
		{
		    *(uint8_t *)buf) = entry->con_value;
		    
		}
		else
		{
		// ------------------------------------------------------------------------
		*/

		*( (uint16_t *)buf ) = *( (uint16_t *)( ( (uint32_t)( &(entry->con_value) 
							            ) + offset
						        )
					              )
				        );
		break;
	    }
	    case 4:
	    {
		*( (uint32_t *)buf ) = *( (uint32_t *)( ( (uint32_t)( &(entry->con_value) 
							            ) + offset
						        )
					              )
				        );
		break;
	    }
	}// end of switch{ }
	return ;
    }// end of if( )

    TEMU_read_mem( vaddr,
		   len,
		   buf
		 );

}// end of H_read_concrete_mem( )



// writing would only target to the temp locations or not

void H_write_concrete_mem( uint32_t vaddr, 
			   int 	    len, 
			   void *   buf
			 )
{
    H_mem_mapping_entry_t * entry = find_H_mem_map_entry( vaddr,
				    		          len
							);    
    if(entry != NULL)
    {

    #ifdef H_DEBUG_TEST
        if( !( ((vaddr - entry->vaddr) == 0) && 
	       (len == entry->size)
	     )
	  )
	{
	    term_printf("mismatch concrete memory writing !\n");
	}// end of if(offset)
    #endif

        switch(len)
        {
   	    case 1:
	    {
	        *( (uint8_t *)( (uint32_t)&(entry->con_value) + vaddr - entry->vaddr
			      )
		 ) = *( (uint8_t *)buf );
	        break;
	    }
	    case 2:
	    {
	        *( (uint16_t *)( (uint32_t)&(entry->con_value) + vaddr - entry->vaddr
			      )
		 ) = *( (uint16_t *)buf );
	        break;
	    }
	    case 4:
	    {
	        *( (uint32_t *)( (uint32_t)&(entry->con_value) + vaddr - entry->vaddr
			      )
		 ) = *( (uint32_t *)buf );
	        break;
	    }
        }// end of switch{ }

    }// end of if( )


}// end of H_write_concrete_mem( )

/* ----------------------------------------------------------------------------------------- */ // temp storages for concrete memories' calculations




// temp storages for concrete registers' calculations
/* ----------------------------------------------------------------------------------------- */
void H_read_concrete_register( int    reg_idx, 
		     	       int    reg_offset, 
		      	       int    reg_size,
		     	       void * buf
		   	     )
{
    uint32_t reg_pos = 0 ;

    /*
    #ifdef H_DEBUG_TEST
    if(reg_size != 4)
    {
	term_printf("mismatch concrete register reading !\n");
    }// end of if(reg_size)
    #endif
    */

    if( ( H_general_registers_bitmap & (1 << reg_idx)  ) == 0
      )
    {
	reg_pos = Convert_taint_reg_to_TEMU_reg( reg_idx * 4 + reg_offset,
						 reg_size
					       );

	if( reg_pos != ((1 << 32) - 1) )
	{
	   /*
  	   term_printf( "H_read_concrete_register( ) reading concrete register value for regidx = %d, regoffset = %d, ",
			 reg_idx,
			 reg_offset
		      );		
	    */
	    TEMU_read_register( reg_pos,
			        buf
			      );
	    /*
	    term_printf( "value is 0x%x\n",
			 ( (reg_offset == 0) ? *( (uint32_t *)buf ) : *( (uint16_t *)buf ) )
		       );
	     */
	}// end of if( )

	return;

    }// end of if( )
    
     /*
    term_printf( "conc_ H_read_concrete_register( ) reading concrete register value for regidx = %d, regoffset = %d, ",
		 reg_idx,
		 reg_offset
	       );
     */

    reg_pos = (uint32_t)H_general_registers + reg_idx * sizeof(uint32_t) + reg_offset ;

    switch(reg_size)
    {
	case 1:
	{
	    *( (uint8_t *)buf )  = *( (uint8_t *)reg_pos );
	    /*
	    term_printf( "value is 0x%x\n",
			 *( (uint8_t *)buf )
	 	       );
	     */
	    break;
	}
	case 2:
	{
	    *( (uint16_t *)buf ) = *( (uint16_t *)reg_pos );
	    /*
	    term_printf( "value is 0x%x\n",
			 *( (uint16_t *)buf )
	 	       );
	     */
	    break;
	}
	case 4:
	{
	    *( (uint32_t *)buf ) = *( (uint32_t *)reg_pos );
	    /*
	    term_printf( "value is 0x%x\n",
			 *( (uint32_t *)buf )
	 	       );
	     */
	    break;
	}
    }// end of switch{ }



}// end of H_read_concrete_register( )




void H_write_concrete_register( int    reg_idx, 
		      	        int    reg_offset, 
			        int    reg_size,
			        void * buf		       
		     	      )
{
    uint32_t reg_pos = ( (uint32_t)( H_general_registers + reg_idx ) + reg_offset 
	      	       );

    switch(reg_size)
    {
	case 1:
	{
	    *( (uint8_t *)reg_pos ) = *( (uint8_t *)buf );
	    break;
	}
	case 2:
	{
	    *( (uint16_t *)reg_pos ) = *( (uint16_t *)buf );	    
	    break;
	}
	case 4:
	{
	    *( (uint32_t *)reg_pos ) = *( (uint32_t *)buf );	    
	    break;
	}
    }// end of switch{ }

}// end of H_write_register( )

/* ----------------------------------------------------------------------------------------- */ // temp storages for concrete registers' calculations




/* in case when we found that the instruction lastly executed was not taint-propagation-related, 
   we would clear the relevant taint-status if the relevant operands are tainted previously !
 */
void iterate_and_taint_clear_list( )
{
    if(h_insn_dst_list.count == 0)
    {
	// term_printf("No concrete dst values yet !\n");
	return;
    }// end of if( )

    PInsn_dst_opnd entry    = h_insn_dst_list.head;

    char * 	   reg_name = NULL;
    int		   reg_id   = 0 ;
    char * 	   reg_pos  = NULL;

    while(entry != NULL)
    {
	switch(entry->type)
	{
	    case OPND_REG_VALUE:
	    {
		// HHui patched at April 6th, 2012
		/* for pre-stored ESI and EDI, we should clean for the current instruction
		   the corresponding taint-states only when these 2 registers are actually
		   written during the instruction's execution.
		 */
		/* ------------------------------------------------------------------- */
		// ESI
		if(h_insn_dst_list.head == entry)
		{
		    if(entry->isWritten == 0)
		    {
			// goto ITCL_TAINTCLEAN;
			goto ITCL_NEXT_ROUND;
		    }// end of if(entry->isWritten)
		}// end of if(h_insn_dst_list.head)

		// EDI
		if((h_insn_dst_list.head)->next == entry)
		{
		    if(entry->isWritten == 0)
		    {
			goto ITCL_NEXT_ROUND;
		    }// end of if(entry->isWritten)
		}// end of if(h_insn_dst_list.head)
		/* ------------------------------------------------------------------- */
		// HHui patched at April 6th, 2012

ITCL_TAINTCLEAN:
		// concrete register !
		if( taintcheck_register_check( (entry->addr / 4),
					       (entry->addr % 4),
					       entry->byte_num,
					       NULL
					     ) != 0
		  )
		{
		    taintcheck_taint_register( (entry->addr / 4),
					       (entry->addr % 4),
					       entry->byte_num,
					       0,
					       NULL
					     );				    
		}// end of if( )
		
		break;
	    }
	    case OPND_MEM_VALUE:
	    {
		// concrete memory data !	
		if( taintcheck_check_virtmem( entry->addr,
					      entry->byte_num,
					      NULL
					    ) != 0
		  )
		{
		    taintcheck_taint_virtmem( entry->addr,
					      entry->byte_num,
					      0,
					      NULL
					    );
		}// end of if( )
/*
		if( ( entry->addr <= 0x12FAF4 ) && 
		    ( (entry->addr + entry->byte_num) >= 0x12FAF4 )
		  )
		{
		    term_printf( "fffffffffffffff vaddr_lb = 0x%x, vaddr_hb = 0x%x\n",
				 entry->addr,
				 entry->addr + entry->byte_num
			       );
		}// end of if( )
 */
		break;
	    }
	}// end of switch{ }

ITCL_NEXT_ROUND:
	entry = entry->next;
    }// end of while{ }
}// end of iterate_and_taint_clear_list( )



void concrete_insn_clear_eflags( )
{
    int bit_indices[9] = { 0,  // CF
			   2,  // PF
			   4,  // AF
			   6,  // ZF
			   7,  // SF
			   8,  // TF
			   9,  // IF
			   10, // DF
			   11  // OF			   
			 };

    uint32_t mask = 0;

    for(int i = 0; i < 9; i = i + 1)
    {
	if( ( 1 << bit_indices[i] ) & modified_EFLAGS 
	  )
	{
	    // mask = ( 1 << 32 ) - ( 1 << bit_indices[i] );
	    mask = ( 1 << 32 ) - 1;
	    mask = mask - ( 1 << bit_indices[i] );
	    	    
	    *HH_eflags_bitmap = *HH_eflags_bitmap & mask;
	    // *HH_eflags_bitmap = *HH_eflags_bitmap & 
	}// end of if( )

    }// end of for{ }



}// end of concrete_insn_clear_eflags( )




/* checks for a single JCC instruction if relevant  
 */
int jcc_is_predicate_tainted(uint8_t * insn_bytes)
{


    

    /*
    for(int i = 0; i < 9; i = i + 1)
    {
	if( ( 1 << bit_indices[i]
	    ) & modified_EFLAGS 
	  )
	{
	    
	}// end of if( )

    }// end of for{ }
    */


}// end of jcc_is_predicate_tainted( )


















