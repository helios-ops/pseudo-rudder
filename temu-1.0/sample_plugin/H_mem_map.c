#include "H_mem_map.h"
#include <malloc.h>

#include <stdlib.h>

H_mem_mapping_list_t H_map;


void init_H_mem_map( )
{
    H_map.head  = NULL;
    H_map.end   = NULL;
  
    H_map.count = 0;

}// end of init_H_mem_map( )



void free_H_mem_map( )
{
    H_mem_mapping_entry_t * entry = H_map.head;
    

    while(entry != NULL)
    {
	H_map.head = entry->next;
	
	free(entry);

	entry = H_map.head;

    }// end of while{ }

    H_map.count = 0;

    // term_printf("free_H_mem_map( )\n");

}// end of free_H_mem_map( )



void add_H_mem_map_entry( uint32_t addr,
			  uint32_t size,
			  uint32_t con_value
			)
{
    H_mem_mapping_entry_t * entry = (H_mem_mapping_entry_t *)malloc(sizeof( H_mem_mapping_entry_t) );
    entry->vaddr     = addr ;
    entry->size	     = size ;
    entry->con_value = con_value;
    entry->next	     = NULL;    

    if(H_map.count == 0)
    {
	H_map.head = entry;
	H_map.end  = entry;
    }
    else
    {
	(H_map.end)->next = entry;
	(H_map.end)	  = entry;
    }// end of if( )    

    H_map.count = H_map.count + 1;

}// end of add_H_mem_map_entry( )




H_mem_mapping_entry_t * find_H_mem_map_entry( uint32_t vaddr,
				              uint32_t size
					    )
{
    H_mem_mapping_entry_t * entry = H_map.head;

    while(entry != NULL)
    {
	if( ((vaddr/4)*4) == entry->vaddr )
	{
	    return entry;
	}// end of if( )

	entry = entry->next;

    }// end of while{ }

    return NULL;
}// end of find_H_mem_map_entry( )







