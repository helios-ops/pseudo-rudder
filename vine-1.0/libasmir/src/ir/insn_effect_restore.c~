/* Restore the concrete values of the dst operatands of the taint instruction for SYMBOLIC-EXECUTION
 */
#include <inttypes.h>
#include <malloc.h>

// #include "TEMU_main.h"
#include "GetTemuData.h"

#include "Reg_convert.h"

#include "H_mem_map.h"
#include "insn_effect_restore.h"


Insn_dst_list h_insn_dst_list;


// TEMU CPU states before instruction's execution
/* ------------------------------------------------------------------------------- */
uint32_t * H_general_registers;

uint8_t  * H_general_registers_bitmap;
/* EAX, ECX, EDX, EBX, ESP, SBP, ESI, EDI */


/* ------------------------------------------------------------------------------- */



void init_insn_dst_list( )
{
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



}// end of free_insn_dst_list( )



void add_insn_dst_opnd( uint32_t     con_value,
			uint32_t     addr,
			opnd_type_t  type,
			int	     byte_num
		      )
{
    uint32_t reg_idx = 0;

    PInsn_dst_opnd con_insn_opnd = malloc( sizeof(Insn_dst_opnd) * byte_num );

    con_insn_opnd->con_value = con_value;
    con_insn_opnd->addr	     = addr;

    con_insn_opnd->type	     = type;
    con_insn_opnd->byte_num  = byte_num;
    con_insn_opnd->next	     = NULL;

    
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
    H_mem_mapping_entry_t * entry = find_H_mem_map_entry( vaddr,
				    		          len
							);
    if(entry != NULL)
    {
	switch(len)
	{
	    case 1:
	    {
		*( (uint8_t *)buf ) = *( (uint8_t *)vaddr );
		break;
	    }
	    case 2:
	    {
		*( (uint16_t *)buf ) = *( (uint16_t *)vaddr );
		break;
	    }
	    case 4:
	    {
		*( (uint32_t *)buf ) = *( (uint32_t *)vaddr );
		break;
	    }
	}// end of switch{ }
	return ;
    }// end of if( )


    GetConcreteMemData( vaddr,
			len,
		  	buf
		      );

}// end of H_read_concrete_mem( )



// writing would only target to the temp locations or not
/*
void H_write_concrete_mem(uint32_t vaddr, int len, void *buf)
{
    H_mem_mapping_entry_t * entry = find_H_mem_map_entry( vaddr,
				    		          len
							);
    switch(len)
    {
	case 1:
	{
	     = *( (uint8_t *)buf )
	    break;
	}
	case 2:
	{
 	    
	    break;
	}
	case 4:
	{
	    
	    break;
	}
    }// end of switch{ }
    */
// }// end of H_write_concrete_mem( )

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

    if( ( H_general_registers_bitmap & (1 << reg_idx)  ) == 0
      )
    {
	reg_pos = Convert_taint_reg_to_TEMU_reg( reg_idx * 4 + reg_offset,
						 reg_size
					       );

	if( reg_pos != ((1 << 32) - 1) )
	{
	    GetConcreteRegData( reg_pos,
				buf
			      );
	    return;

	}// end of if( )

    }// end of if( )
    

    reg_pos = ( (uint32_t)( H_general_registers + reg_idx ) + reg_offset 
	      );

    switch(reg_size)
    {
	case 1:
	{
	    *( (uint8_t *)buf )  = *( (uint8_t *)reg_pos );
	    break;
	}
	case 2:
	{
	    *( (uint16_t *)buf ) = *( (uint16_t *)reg_pos );
	    break;
	}
	case 4:
	{
	    *( (uint32_t *)buf ) = *( (uint32_t *)reg_pos );
	    break;
	}
    }// end of switch{ }

}// end of H_read_concrete_register( )



/*
void H_write_register( int    reg_idx, 
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
	     *( (uint8_ t *)reg_pos ) = *( (uint8_t *)buf );
	    break;
	}
	case 2:
	{
	    *( (uint16_ t *)reg_pos ) = *( (uint16_t *)buf );	    
	    break;
	}
	case 4:1
	{
	    *( (uint32_ t *)reg_pos ) = *( (uint32_t *)buf );	    
	    break;
	}
    }// end of switch{ }

}// end of H_write_register( )
*/

/* ----------------------------------------------------------------------------------------- */ // temp storages for concrete registers' calculations









