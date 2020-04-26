#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <inttypes.h>

#include "../taintcheck.h"
#include "../TEMU_main.h"
#include "taintcheck_hook.h"
#include "H_taint_record.h"
#include "expr_condition.h"
#include "function_summary.h"


static h_func_taint_mem_record_list_t * func_summ_mem_list;

char h_reg_TEMU_index[8] = { R_EAX,
			     R_ECX,
			     R_EDX,
			     R_EBX,
			     R_ESP,
			     R_EBP,
			     R_ESI,
			     R_EDI
			   }; 

uint32_t h_TEMU_cpu_wr_index[8] = { eax_reg,
				    ecx_reg,
				    edx_reg,
				    ebx_reg,
				    esp_reg,
				    ebp_reg,
				    esi_reg,
				    edi_reg
				  };

void func_taint_memory_record_list_init(h_func_taint_mem_record_list_t * mem_data)
// void func_taint_memory_record_list_init( )
{    
    func_summ_mem_list 	      = mem_data;

    func_summ_mem_list->head  = NULL;
    func_summ_mem_list->end   = NULL;
    func_summ_mem_list->count = 0;
    // func_summ_mem_list->next  = NULL;

    // ( (func_summ->summary_conditions).post_mem_cond ).

}// end of func_taint_memory_record_list_init( )


void func_taint_memory_record_list_restore(h_func_taint_mem_record_list_t * mem_data)
{
    func_summ_mem_list = mem_data;
}// end of func_taint_memory_record_list_restore( )


h_func_taint_mem_record_entry_t * Find_mem_entry_in_func_mem_taint_list( uint32_t 			    vaddr,
									 h_func_taint_mem_record_entry_t ** pre_entry
								       )
{
    h_func_taint_mem_record_entry_t * entry = NULL;

    if(func_summ_mem_list == NULL)
    {
	*pre_entry = NULL;
	return NULL;
    }// end of if(func_summ_mem_list)

    entry      = func_summ_mem_list->head;
    *pre_entry = NULL;

    while(entry != NULL)
    {
	if(entry->vaddr == vaddr)
	{
	    return entry;
	}// end of if(entry->vaddr)

	*pre_entry = entry;
	entry      = entry->next;
    }// end of while{entry}
    
    return NULL;
}// end of Find_mem_entry_in_func_mem_taint_list( )


// callback invoked when mem[vaddr] is tainted
void H_func_add_taint_memory_record_entry( uint32_t 	      vaddr,
					   H_taint_record_t * record
					 )
{
    int i = 0;
    h_func_taint_mem_record_entry_t * pre_entry = NULL;
    h_func_taint_mem_record_entry_t * entry     = NULL;

    if(func_summ_mem_list == NULL)
    {
	return;
    }// end of if(func_summ_mem_list)

    entry = Find_mem_entry_in_func_mem_taint_list( vaddr,
						   &pre_entry
						 );    
    if(entry == NULL)
    {
	entry = (h_func_taint_mem_record_entry_t *)malloc(sizeof(h_func_taint_mem_record_entry_t));
	entry->vaddr  = vaddr;
/*
	memcpy( &(entry->record),
		record,
		sizeof(H_taint_record_t)
 	      );
 */
	for(i = 0; i < sizeof(H_taint_record_t); i = i + 1)
	{
	    *( ((char *)(&(entry->record))) + i) = *( ( (char *)record ) + i);
	}// end of for{i}

	entry->next = NULL;

	if(func_summ_mem_list->head == NULL)
	{
	    func_summ_mem_list->head = entry;
	    func_summ_mem_list->end  = entry;
	}
	else
	{
	    (func_summ_mem_list->end)->next = entry;
	    func_summ_mem_list->end	    = entry;
	}// end of if(mem_list.head)	

	func_summ_mem_list->count = func_summ_mem_list->count + 1;
    }
    else
    {
	// here is just update !
	for(i = 0; i < sizeof(H_taint_record_t); i = i + 1)
	{
	    *( ((char *)(&(entry->record))) + i) = *( ( (char *)record ) + i);
	}// end of for{i}
	/*
	memcpy( &(entry->record),
		record,
		sizeof(H_taint_record_t)
 	      );
	*/
    }// end of if(entry)

}// end of H_func_add_taint_memory_record_entry( )



// callback invoked when mem[vaddr]'s taint status is cleared
void H_func_delete_taint_memory_record_entry(uint32_t vaddr)
{
    h_func_taint_mem_record_entry_t * pre_entry = NULL;

    if(func_summ_mem_list == NULL)
    {
	return;
    }// end of if(func_summ_mem_list)

    h_func_taint_mem_record_entry_t * entry     = Find_mem_entry_in_func_mem_taint_list( vaddr,
											 &pre_entry
										       );    
    if(entry != NULL)
    {
	if(entry == func_summ_mem_list->head)
	{
	    func_summ_mem_list->head = NULL;
	}
	else
	{
	    pre_entry->next = entry->next;
	}// end of if(entry)

	if(entry == func_summ_mem_list->end)
	{
	    func_summ_mem_list->end = pre_entry;
	}// end of if(entry)

	free(entry);
    }// end of if(entry)
}// end of H_func_delete_taint_memory_record_entry( )


void func_taint_memory_record_list_delete(h_func_taint_mem_record_list_t * mem_data)
{
    h_func_taint_mem_record_entry_t * entry = NULL;

    if(mem_data == NULL)
    {
	return;
    }// end of if(func_summ_mem_list)
    entry = mem_data->head;

    while(entry != NULL)
    {
	mem_data->head = entry->next;
	free(entry);	

	entry = mem_data->head;
    }// end of while{entry}

}// end of func_taint_memory_record_list_delete( )


void taintcheck_virtmem_hookfn( uint32_t 	   vaddr,
				uint32_t	   size,
				uint32_t	   tcbmap,
				H_taint_record_t * records
		    	      )
{
    int i = 0;

    if(func_summ_mem_list == NULL)
    {
	return;
    }// end of if(func_summ_mem_list)

    if(tcbmap == 0)
    {
	for(i = 0; i < size; i = i + 1)
	{
	    H_func_delete_taint_memory_record_entry(vaddr + i);
	}// end of for{i}
    }
    else
    {
	for(i = 0; i < size; i = i + 1)
	{
	    if( (tcbmap & (1 << i)) != 0 )
	    {
		H_func_add_taint_memory_record_entry( (vaddr + i),
						      &(records[i])
					  	    );	
	    }// end of if(tcbmap)
	}// end of for{i}

    }// end of if(tcbmap)
    
}// end of taintcheck_virtmem_hookfn( )


void Copy_taint_mem_list( h_func_taint_mem_record_list_t * src_list,
			  h_func_taint_mem_record_list_t * dst_list
		        )
{
    h_func_taint_mem_record_entry_t * src_entry  = src_list->head;
    h_func_taint_mem_record_entry_t * dst_entry1 = NULL;
    h_func_taint_mem_record_entry_t * dst_entry2 = NULL;

    dst_list->head = NULL;
    dst_list->end  = NULL;

    while(src_entry != NULL)
    {
	dst_entry2 = (h_func_taint_mem_record_entry_t *)malloc(sizeof(h_func_taint_mem_record_entry_t));
	if(dst_entry1 != NULL)
	{
	    dst_entry1->next = dst_entry2;
	}
        else
	{
	    dst_list->head = dst_entry2;
	}// end of if(dst_entry2)

	dst_entry2->vaddr  = src_entry->vaddr;
	dst_entry2->record = src_entry->record;
	dst_entry2->next   = NULL;
	
	dst_entry1 = dst_entry2;
	src_entry  = src_entry->next;
    }// end of while{src_entry}

    dst_list->end = dst_entry1;
    dst_list->count = src_list->count;
}// end of Copy_taint_mem_list( )






