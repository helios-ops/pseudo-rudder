#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#include "H_taint_record.h"

extern HVC HHui_VC;

static H_taint_origin_list_t taint_org_list;

void H_taint_origin_list_init( )
{
    taint_org_list.head  = NULL;
    taint_org_list.end   = NULL;
    taint_org_list.count = 0;
}// end of H_taint_origin_list_init( )

// introduce a taint orgin
void add_record_to_H_taint_origin_list( uint32_t org_id,
					int	 org_type,
					uint32_t off_start,
					uint32_t off_end					
				      )
{
    char  buffer[50];
    int   count    = 0;
    HExpr tmp_expr = NULL;
    HExpr tmp_type = NULL;

    count = sprintf( buffer,
	    	     "str_%d_%d_len",
		     org_id,
		     org_type
	   	   );
    buffer[count] = '\0';

    H_taint_origin_t * entry = (H_taint_origin_t *)malloc(sizeof(H_taint_origin_t));
    entry->next              = NULL;
    entry->origin_id         = org_id;
    entry->origin_tp         = org_type;
    entry->off_start         = off_start;
    entry->off_end           = off_end;
    /*
    entry->taint_len_expr = vc_varExpr1( HHui_VC,
					 buffer,
					 32,
					 32
				       );
     */
    tmp_expr = vc_bv32ConstExprFromInt( HHui_VC,
					1
				      );
    tmp_type = vc_getType( HHui_VC,
			   tmp_expr
			 );
    entry->taint_len_expr = vc_varExpr( HHui_VC,
					buffer,
					tmp_type
				      );
    vc_DeleteExpr(tmp_expr);

    entry->byte_records_head  = (H_byte_taint_record_t *)malloc(sizeof(H_byte_taint_record_t));
    entry->byte_records_end   = entry->byte_records_head;
    entry->byte_records_count = 1;

    (entry->byte_records_head)->offset	      = off_start;

    (entry->byte_records_head)->len_hard_expr = NULL;
    tmp_expr = vc_bv32ConstExprFromInt( HHui_VC,
					(entry->off_end - entry->off_start)
				      );
    (entry->byte_records_head)->len_soft_expr = vc_eqExpr( HHui_VC,
							   entry->taint_len_expr,
							   tmp_expr
							 );
    vc_DeleteExpr(tmp_expr);

    if(taint_org_list.head == NULL)
    {
	taint_org_list.head = entry;
	taint_org_list.end  = entry;
    }
    else
    {
	(taint_org_list.end)->next = entry;
	taint_org_list.end	   = entry;
    }// end of if(taint_org_list)

    taint_org_list.count = taint_org_list.count + 1;
    
}// end of add_record_to_H_taint_origin_list( )


void H_taint_origin_list_delete( )
{
    H_taint_origin_t      * entry      = taint_org_list.head;
    H_byte_taint_record_t * byte_entry = NULL;

    while(entry != NULL)
    {
	taint_org_list.head = entry->next;

	/* -------------------------------------------------------- */
	byte_entry = entry->byte_records_head;
	if(byte_entry != NULL)
	{
	    while(byte_entry != entry->byte_records_end)
    	    {
	        entry->byte_records_head = entry->next;
	        free(byte_entry);
	        byte_entry = byte_entry->next;
	    }// end of while{byte_entry}

	    free(entry->byte_records_end);
	}// end of if(byte_entry)

	free(entry);
	/* -------------------------------------------------------- */

	entry = taint_org_list.head;
    }// end of while{entry}

}// end of H_taint_origin_list_delete( )


HExpr find_len_expr_by_taint_record( uint32_t org_id,
				     int      org_type,
				     uint32_t offset
				   )
{
    H_taint_origin_t * t_origin = taint_org_list.head;
    HExpr tmp_expr1 = NULL;
    HExpr tmp_expr2 = NULL;

    while(t_origin != NULL)
    {
	if( (org_id == (t_origin->origin_id | 0x80000000)) &&
	// if( (t_origin->origin_id == (org_id | 0x80000000)) &&
	    (t_origin->origin_tp == org_type) &&
	    ( (t_origin->off_start <= offset) &&
	      (t_origin->off_end > offset)
	    )
	  )
	{
	    if(t_origin->off_start == offset)
	    {
		return t_origin->taint_len_expr;
	    }// end of if(t_origin)

	    tmp_expr1 = vc_bv32ConstExprFromInt( HHui_VC,
						 (offset - t_origin->off_start)
					       );

	    tmp_expr2 = vc_bvMinusExpr( HHui_VC,
				        32,
					t_origin->taint_len_expr,
					tmp_expr1
				      );
	    return tmp_expr2;
	    

	}// end of if(t_origin)

	t_origin = t_origin->next;
    }// end of while{t_origin}

    return NULL;
}// end of find_len_expr_by_taint_record( )



