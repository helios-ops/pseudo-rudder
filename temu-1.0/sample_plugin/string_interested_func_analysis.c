#include <inttypes.h>
#include <malloc.h>
#include "../TEMU_main.h"
#include "../shared/hookapi.h"
#include "hc_interface.h"
#include "H_taint_record.h"
#include "module_notify.h"
#include "H_malloc_data.h"
#include "H_hookdata.h"

#include "H_test_config.h"


extern HVC      HHui_VC;
extern HExpr    path_Expr;

extern char     monitored_proc[128];
extern uint32_t HHui_target_cr3;

void vul_length_potential_check( uint32_t vul_length,
				 HExpr    len_expr
			       )
{
    char *   tmp_str_expr = NULL;
    HExpr    tmp_expr1 = NULL;
    HExpr    tmp_expr2 = NULL;
    HExpr    tmp_expr3 = NULL;
    HExpr    tmp_expr4 = NULL;
    int	     qresult   = 0;

    tmp_expr1 = vc_bv32ConstExprFromInt( HHui_VC,
					 vul_length
				       );
    tmp_expr2 = vc_bvGeExpr( HHui_VC,
			     len_expr,
			     tmp_expr1
			   );
    tmp_expr3 = vc_andExpr( HHui_VC,
			    path_Expr,
			    tmp_expr2
			  );
    tmp_expr4 = vc_notExpr( HHui_VC,
			    tmp_expr3
			  );
    vc_push(HHui_VC);
    qresult = vc_query( HHui_VC,
			tmp_expr4
		      );	
    vc_pop(HHui_VC);

    // there exists a potential stack-overflow vulnerability!
    if(qresult == 0)
    {
	// tmp_str_expr = exprString(tmp_expr3);
	APIHooking_record_ERROR_2file( tmp_expr3,
				       1
				     );
	// free(tmp_str_expr);
    }// end of if(qresult)

    vc_DeleteExpr(tmp_expr4);
    vc_DeleteExpr(tmp_expr3);
    vc_DeleteExpr(tmp_expr2);
    vc_DeleteExpr(tmp_expr1);
}// end of vul_length_potential_check( )



int _strcpy_hook_ret(void * opaque)
{
    term_printf("_strcpy( ) returned !\n");        
    return 0;
}// end of _strcpy_hook_ret( )


int _strcpy_hook_call(void * opaque)
{
    uint32_t ret_eip 	  = 0;
    uint32_t src_str_addr = 0;
    uint32_t dst_str_addr = 0;
    uint64_t tc_bmap	  = 0;

    uint32_t cr3;
    uint32_t eip_base	  = 0;
    uint32_t heap_hlimit  = 0;

    uint32_t vul_length   = 0;
    HExpr    len_expr     = NULL;
    char *   tmp_str_expr = NULL;
    int      qresult	  = 0;


    H_taint_record_t org_record;    

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(HHui_target_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( HHui_target_cr3 != 0 ) && 
	( cr3 != HHui_target_cr3 )
      )
    {
	return 0;
    }// end of if( )

    if(Find_Module_for_VA(*TEMU_cpu_eip) == NULL)
    {
	return 0;
    }// end of if(Find_Module_for_VA)

    term_printf("_strcpy( ) called !\n");

    // checks if src string is tainted !
    /* ------------------------------------------------------------------ */
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 8,
		   4,
		   &src_str_addr
		 );

    tc_bmap = taintcheck_check_virtmem( src_str_addr,
					1,
					NULL
				      );
    if(tc_bmap == 0)
    {
	return 0;
    }// end of if(tc_bmap)
    /* ------------------------------------------------------------------ */


    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
	  	   4,
		   &dst_str_addr
	         );
    
/*
    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );
    hookapi_hook_return( ret_eip,
			 _strcpy_hook_ret,
			 NULL,
			 0
		       );
 */
    /* here, we check which length would cause an overflow problem, then
       generate a pseudo error instance, leaving alone the corresponding 
       constraint for each byte for the next RUN-REPAIR step.
     */

    /* here, we suppose the maximum LEN */
    taintcheck_check_virtmem( src_str_addr,
			      1,
			      &org_record
			    );
    len_expr = find_len_expr_by_taint_record( org_record.origin,
					      org_record.type,
				     	      org_record.offset
				  	    );
    tmp_str_expr = exprString(len_expr);
    term_printf( "len_expr : %s\n", 
		 tmp_str_expr
	       );
    free(tmp_str_expr);

    if( Find_callstack_by_vaddr( dst_str_addr,
			         &eip_base
			       ) == 1	
      )
    {
	// stack-overflow checking
	vul_length = eip_base - dst_str_addr;
	
	// generate a possible-overflow assertion and checks it with current path's constraint
	vul_length_potential_check( vul_length,
				    len_expr
				  );
    }
    else if( Find_heap_entry_by_vaddr( dst_str_addr,
			      	       &heap_hlimit
			  	     ) == 1
	   )	
    {
	// heap-overflow checking
	vul_length = heap_hlimit - dst_str_addr;

	// generate a possible-overflow assertion and checks it with current path's constraint
	vul_length_potential_check( vul_length,
				    len_expr
				  );	
    }// end of if( Find_callstack_by_vaddr( ) )

    
    return 0;
}// end of _strcpy_hook_call( )


int _strlen_hook_ret(void * opaque)
{
    int   bitnum_low  = 0;
    int   bitnum_high = 0;
    H_normal_data_t * hookdata = (H_normal_data_t *)opaque;

    HExpr tmp_expr = NULL;
    H_taint_record_t * records  = (H_taint_record_t *)malloc( 4 * sizeof(H_taint_record_t) );
    H_taint_record_t org_record;

    uint32_t str_addr;    
    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
		   4,
		   &str_addr
		 );

    taintcheck_check_virtmem( str_addr,
			      1,
			      &org_record
			    );

    /* here, we suppose the maximum LEN */
    tmp_expr = find_len_expr_by_taint_record( org_record.origin,
					      org_record.type,
				     	      org_record.offset
				  	    );

    for(int i = 0; i < 4; i = i + 1)
    {
	bitnum_low  = i * 8;
	bitnum_high = (i + 1) * 8 - 1;

	records[i].h_expr = vc_bvExtract( HHui_VC,
					  tmp_expr,
					  bitnum_high,
					  bitnum_low
		    			);

    }// end of for{i}
    taintcheck_taint_register( R_EAX,
			       0,
			       4,
			       15,
			       records
			     );

    hookapi_remove_hook(hookdata->handle);
    free(hookdata);

    return 0;
}// end of _strlen_hook_ret( )


int _strlen_hook_call(void * opaque)
{
    uint32_t str_addr = 0;
    uint64_t tc_bmap  = 0;
    uint32_t ret_eip  = 0;
    uint32_t cr3;
    H_normal_data_t * hookdata = NULL;

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(HHui_target_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( HHui_target_cr3 != 0 ) && 
	( cr3 != HHui_target_cr3 )
      )
    {
	return 0;
    }// end of if( )    

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
		   4,
		   &ret_eip
		 );

    // checks if src string is tainted !
    /* ------------------------------------------------------------------ */
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
		   4,
		   &str_addr
		 );

    tc_bmap = taintcheck_check_virtmem( str_addr,
					1,
					NULL
				      );
    if(tc_bmap == 0)
    {
	return 0;
    }// end of if(tc_bmap)
    /* ------------------------------------------------------------------ */

    hookdata = (H_normal_data_t *)malloc(sizeof(H_normal_data_t));    
    hookdata->handle = hookapi_hook_return( ret_eip,
					    _strlen_hook_ret,
					    hookdata,
					    sizeof(H_normal_data_t)
				          );    

    return 0;
}// end of _strlen_hook_call( )

