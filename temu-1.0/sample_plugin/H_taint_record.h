#ifndef HH_H_taint_record_H
	#define HH_H_taint_record_H

	#include <inttypes.h>
	#include "hc_interface.h"
	

	typedef struct H_taint_record
	{
	    HExpr     h_expr;
	    int	      type;    
	    /* type:
	       1 --- disk; 
	       2 --- keyboard; 
	       4 --- function summary parametre (either stack-para or register-para)
	     */

	    uint32_t  origin; 
	    /* orgin:
	       when 'H_taint_record' is introduced from function-summary calculation, 
	       'origin' denotes the specific function's entry address!
	     */

	    uint32_t  offset;
	}H_taint_record_t;

	
	typedef struct H_byte_taint_record
	{
	    int   offset;

	    // hard and soft constraints for inputs' length from this ptr to the end
	    HExpr len_hard_expr; // post constraint brought up the the processing logic of the monitored program
	    HExpr len_soft_expr; // intrinsic constraint brought up by the original concrete inputs

	    struct H_byte_taint_record * next;
	}H_byte_taint_record_t, *PH_byte_taint_record_t;


	// records every time a taint-group was introduced
	typedef struct H_taint_origin
	{
	    HExpr     taint_len_expr;
	    uint32_t  origin_id;
	    int	      origin_tp;
	    uint32_t  off_start;
	    uint32_t  off_end;

	    H_byte_taint_record_t * byte_records_head;
	    H_byte_taint_record_t * byte_records_end;
	    int			    byte_records_count;

	    struct H_taint_origin * next;
	}H_taint_origin_t, *PH_taint_origin_t;
	

	typedef struct H_taint_origin_list
	{
	    H_taint_origin_t * head;
	    H_taint_origin_t * end;

	    int count; 	     
	}H_taint_origin_list_t, *PH_taint_origin_list_t;

	// extern FILE *my_log;

	void H_taint_origin_list_init( );	
	void add_record_to_H_taint_origin_list( uint32_t org_id,
						int	 org_type,
						uint32_t off_start,
						uint32_t off_end					
				      	      );
	void H_taint_origin_list_delete( );

	HExpr find_len_expr_by_taint_record( uint32_t org_id,
					     int      org_type,
					     uint32_t offset
					   );
#endif
