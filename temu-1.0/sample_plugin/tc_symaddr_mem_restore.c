#include <stdlib.h>
#include <malloc.h>

// #include "H_taint_record.h"
#include "tc_symaddr_mem_restore.h"
#include "../taintcheck.h"


static tc_symaddr_mem_addr_list_t symaddr_mem_addr_list;


void init_tc_symaddr_mem_restore_list( )
{
    symaddr_mem_addr_list.head  = NULL;
    symaddr_mem_addr_list.tail  = NULL;

    symaddr_mem_addr_list.count = 0;
}// end of init_tc_symaddr_mem_restore_list( )


void add_tc_symaddr_mem_addr_entry_to_list( uint32_t	       vaddr,
					    uint32_t 	       size,
					    uint64_t 	       taint_bmap,
					    H_taint_record_t * records
					  )
{
    Ptc_symaddr_mem_addr_entry_t entry = (Ptc_symaddr_mem_addr_entry_t)malloc( sizeof(tc_symaddr_mem_addr_entry_t) );
    entry->vaddr   = vaddr;
    entry->size    = size;
    entry->tc_bmap = taint_bmap;        
    entry->records = (H_taint_record_t *)malloc(sizeof(H_taint_record_t) * size);
    for(int i=0; i<sizeof(H_taint_record_t) * size; i=i+1)
    {
	*( (char *)( (uint32_t)(entry->records) + i
		   )
   	 ) = *( (char *)( (uint32_t)records + i
			)
	      );
    }// end of for{i}
    
    entry->next  = NULL;
    
    if(symaddr_mem_addr_list.head == NULL)
    {
	symaddr_mem_addr_list.head = entry;
	symaddr_mem_addr_list.tail = entry;
    }
    else
    {
	(symaddr_mem_addr_list.tail)->next = entry;
	symaddr_mem_addr_list.tail = (symaddr_mem_addr_list.tail)->next;
    }// end of if(symaddr_mem_addr_list.head)

    symaddr_mem_addr_list.count = symaddr_mem_addr_list.count + 1;
}// end of add_tc_symaddr_mem_addr_entry_to_list( )


/* SYM-ADDR: restore Symbolic machine state before IR-SYMEXE */
void delete_restore_tc_symaddr_mem_list( )
{
    Ptc_symaddr_mem_addr_entry_t entry = symaddr_mem_addr_list.head;
    for(int i=0; i<symaddr_mem_addr_list.count; i=i+1)
    {
	taintcheck_taint_virtmem( entry->vaddr,
				  entry->size,
				  entry->tc_bmap,
				  entry->records
				);

	// HHui Fixed at March 15th, 2012: previous memory-leak !
	free(entry->records);

	free(symaddr_mem_addr_list.head);
	entry = entry->next;
	symaddr_mem_addr_list.head = entry;
    }// end of for{i}

    symaddr_mem_addr_list.head  = NULL;
    symaddr_mem_addr_list.tail  = NULL;
    symaddr_mem_addr_list.count = 0;
}// end of delete_restore_tc_symaddr_mem_list( )



