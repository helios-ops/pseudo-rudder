#include "insn_taint_state.h"

H_TAINTINFO_LIST taint_info_list;

void init_taintinfo_list( )
{
	taint_info_list.head  = NULL;
	taint_info_list.end   = NULL;

	taint_info_list.count = 0;
}// end of init_taintinfo_list( )


void delete_taintinfo_list( )
{
	if(taint_info_list.count == 0)
	{
		return ;
	}// end of if( )

	PH_TAINTINFO_ENTRY entry     = taint_info_list.head;
	PH_TAINTINFO_ENTRY pre_entry = NULL;

	while(entry != NULL)
	{
		pre_entry = entry;
		entry 	  = entry->next;
		
		free(pre_entry->dst_taint_record);
		free(pre_entry);
	}// end of while{ }

}// end of delete_taintinfo_list( )


/*
		struct H_taintinfo_ENTRY
		{
			char 		   type;
			char		   size;
			uint8_t		   taint;				
			int 		   mode;	
			uint32_t	   addr;

			H_taint_record_t * dst_taint_record;

			struct 	H_taintinfo_ENTRY * next;
	
		}H_TAINTINFO_ENTRY, *PH_TAINTINFO_ENTRY
 */
PH_TAINTINFO_ENTRY Add_taintinfo_entry( // int 		      src_opnd_num,
					// taint_operand_t  * src_opnds,
					taint_operand_t  * dst_opnd,
					int		   mode 
				      )
{
	int 		   i	 = 0;
	PH_TAINTINFO_ENTRY entry = NULL;

	if(taint_info_list.count == 0)
	{
		taint_info_list.head  = (PH_TAINTINFO_ENTRY)malloc( sizeof(H_TAINTINFO_ENTRY) );
		taint_info_list.end   = taint_info_list.head;
		taint_info_list.count = 1 ;
		
		entry		      = taint_info_list.head;
	}
	else
	{
		entry = (PH_TAINTINFO_ENTRY)malloc( sizeof(H_TAINTINFO_ENTRY) ) ;		
		// = taint_info_list.end;
		
	}// end of if( )
	
	entry->type  = dst_opnd->type;
	entry->size  = dst_opnd->size;
	entry->taint = dst_opnd->taint; // taint-bitmap
	entry->addr  = dst_opnd->addr;
	entry->mode  = mode;	

	
	entry->next  = NULL;		

	taint_info_list.end->next = entry ;
	taint_info_list.end 	  = entry ;
	
	(entry->dst_taint_record) = (H_taint_record_t *)malloc(sizeof(H_taint_record_t) * entry->size) ;
	for(i=0; i<entry->size; i=i+1)
	{
		(entry->dst_taint_record)[i].h_expr = ( ( (H_taint_record_t *)(dst_opnd->records) ) + i )->h_expr;
		(entry->dst_taint_record)[i].origin = ( ( (H_taint_record_t *)(dst_opnd->records) ) + i )->origin;
		(entry->dst_taint_record)[i].offset = ( ( (H_taint_record_t *)(dst_opnd->records) ) + i )->offset;
	}// end of for{ }

	taint_info_list.count = taint_info_list.count + 1;

}// end of Add_taintinfo_entry( )



