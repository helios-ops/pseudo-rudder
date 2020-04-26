#include <stdlib.h>
#include <malloc.h>
#include "H_malloc_data.h"

H_malloc_data_list_t H_heap_list;

void H_heap_data_list_init( )
{
    H_heap_list.head  = NULL;
    H_heap_list.end   = NULL;
    H_heap_list.count = 0;
}// end of H_heap_data_list_init( )


// util for malloc( )
void add_entry_to_heap_data_list( uint32_t addr,
			   	  uint32_t size
			  	)
{
    H_malloc_data_t * entry = (H_malloc_data_t *)malloc(sizeof(H_malloc_data_t));
    entry->next = NULL;
    entry->addr = addr;
    entry->size = size;
    
    if(H_heap_list.head == NULL)
    {
	H_heap_list.head = entry;
	H_heap_list.end  = entry;
    }
    else
    {
	(H_heap_list.end)->next = entry;
	H_heap_list.end		= entry;
    }// end of if(H_heap_list.head)

    H_heap_list.count = H_heap_list.count + 1;
}// end of add_entry_to_heap_data_list( )


// util for free( )
void delete_entry_from_heap_data_list(uint32_t addr)
{
    H_malloc_data_t * entry      = H_heap_list.head;
    H_malloc_data_t * pre_entry  = NULL;
    H_malloc_data_t * post_entry = NULL;

    while(entry != NULL)
    {
	if(entry->addr == addr)
	{
	    if(entry == H_heap_list.head)
	    {
		H_heap_list.head = (H_heap_list.head)->next;
		free(entry);
	    }
	    else
	    {
		post_entry 	= entry->next;
		pre_entry->next = post_entry;
		free(entry);		
	    }// end of if(entry)

	    return;
	}// end of if(entry->addr)

	pre_entry = entry;
	entry     = entry->next;
    }// end of while{entry}

}// end of delete_entry_from_heap_data_list( )


void heap_data_list_delete( )
{
    H_malloc_data_t * entry = H_heap_list.head;
    while(entry != NULL)
    {
	H_heap_list.head = entry->next;
	free(entry);

	entry = H_heap_list.head;
    }// end of while{entry}

    H_heap_list.head  = NULL;
    H_heap_list.end   = NULL;
    H_heap_list.count = 0;
}// end of heap_data_list_delete( )


int Find_heap_entry_by_vaddr( uint32_t   vaddr,
			      uint32_t * heap_hlimit
			    )
{
    H_malloc_data_t * entry = H_heap_list.head;
    while(entry != NULL)
    {
	if( (entry->addr <= vaddr) &&
	    ( ( (entry->addr + entry->size) ) > vaddr )
	  )
	{
	    *heap_hlimit = entry->addr + entry->size;
	    return 1;
	}// end of if()

	entry = entry->next;
    }// end of while{entry}

    return 0;
}// end of Find_heap_entry_by_vaddr( )







