#include <inttypes.h>
#include <malloc.h>
#include "../TEMU_main.h"
#include "../TEMU_lib.h"
#include "../taintcheck.h"
#include "H_hookdata.h"
#include "hc_interface.h"
#include "record_potential_error2file.h"
#include "H_malloc_data.h"
#include "H_taint_record.h"
#include "H_test_config.h"

extern HVC   HHui_VC;
extern HExpr path_Expr;
extern plugin_interface_t my_interface;


// function's local path-constraint expressed through function's formal parametres.
extern HExpr * func_precondition_expr; 

/* function's local path-constraint expressed through function's actual parametres.
   ( effective only when the function is calculated for a new pre-post condition-pair )
*/
extern HExpr   func_local_ending_expr;



static int _malloc_hook_return(void * opaque)
{
    H_normal_data_t * hookdata = (H_normal_data_t *)opaque;
    uint32_t size = 0;
    uint32_t addr = 0;

    TEMU_read_mem( TEMU_cpu_regs[R_ESP], // size: 1st parametre in the callstack 
		   4,
		   &size
		 );
    
    TEMU_read_register( eax_reg,
			&addr
		      );
    if(addr != 0)
    {
	if(my_interface.add_entry_to_heap_data_list != NULL)
	{
	    my_interface.add_entry_to_heap_data_list( addr,
				  	              size
			  	    		    );
	}// end of if(my_interface.add_entry_to_heap_data_list)
    }// end of if(addr)

    hookapi_remove_hook(hookdata->handle);
    free(hookdata);    

#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    my_interface.is_in_cur_interested_func = 0;
#endif

    return 0;
}// end of _malloc_hook_return( )



int _malloc_hook_call(void * opaque)
{
    H_normal_data_t * hookdata = NULL;
    uint32_t cr3     = 0;
    uint32_t ret_eip = 0;

    int i = 0;
    uint64_t tcbmap  = 0;
    H_taint_record_t h_records[4]; 
    HExpr    tmp_expr1 = NULL;
    HExpr    tmp_expr2 = NULL;
    HExpr    tmp_expr3 = NULL;
    HExpr    tmp_expr4 = NULL;

    int      qresult   = 0;
    uint32_t tmp_value = 0;
    char *   tmp_str   = NULL;

/*
    // compositional symbolic execution 
    if(my_interface.is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)
*/
    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(my_interface.monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( my_interface.monitored_cr3 != 0 ) && 
	( cr3 != my_interface.monitored_cr3 )
      )
    {
	return 0;
    }// end of if(temu_plugin)
    
#ifdef HHUI_INTERESTED_FUNCTION_SYMEXE_MASK    
    my_interface.is_in_cur_interested_func = 1;
#endif

    
#ifdef HHUI_API_CALL_CHECK_TAINT_PARAMETRE
    tcbmap = taintcheck_check_virtmem( (TEMU_cpu_regs[R_ESP] + 4),
				       4,
				       h_records
				     );
    if(tcbmap != 0)
    {
	if(tcbmap & 1)
	{
	    tmp_expr1 = (h_records[0]).h_expr;
	}
	else
	{
	    TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4),
			   1,
			   &tmp_value
			 );
	    tmp_expr1 = vc_bvConstExprFromInt( HHui_VC,
					       8,
					       tmp_value
					     );
	}// end of if(tcbmap)

	for(i = 1; i < 4; i = i + 1)
	{
	    if(tcbmap & (1 << i))
	    {
	        tmp_expr2 = (h_records[i]).h_expr;
	    }
	    else
	    {
	        TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4 + i),
			       1,
			       &tmp_value
			     );
	        tmp_expr2 = vc_bvConstExprFromInt( HHui_VC,
					           8,
					           tmp_value
					         );
	    }// end of if(tcbmap)

	    tmp_expr1 = vc_bvConcatExpr( HHui_VC,
					 tmp_expr2,
					 tmp_expr1
				       );
	}// end of for{i}

	tmp_expr2 = vc_bvConstExprFromInt( HHui_VC,
					   32,
					   0
					 );		
	tmp_expr3 = vc_bvLeExpr( HHui_VC,
				 tmp_expr1,
				 tmp_expr2
			       );

	vc_push(HHui_VC);

#ifdef HHUI_FUNC_SUMMARY_ENABLED
	if(func_precondition_expr != NULL)
	{
/* HHui Fixme : for a more complete expression */
/* --------------------------------------------------------------------------- */
	    tmp_expr4 = vc_andExpr( HHui_VC,
				    *func_precondition_expr,
				    tmp_expr3
				  );
/* --------------------------------------------------------------------------- */

	    qresult   = vc_query( HHui_VC,
			        vc_notExpr( HHui_VC,
					    tmp_expr4					    
				          )
			      );
	}
	else
	{
#endif
	    tmp_expr4 = vc_andExpr( HHui_VC,
				    path_Expr,
				    tmp_expr3
				  );

	    qresult = vc_query( HHui_VC,
			        vc_notExpr( HHui_VC,
					    tmp_expr4
				          )
			      );

#ifdef HHUI_FUNC_SUMMARY_ENABLED
	}// end of if(func_precondition_expr)
#endif
	vc_pop(HHui_VC);

	if(qresult == 0)
	{
	    term_printf("We find a parametre-error in _malloc( ) !\n");

	    // tmp_str = exprString(tmp_expr4);
	    APIHooking_record_ERROR_2file( tmp_expr4,
					   0
					 );	    
	    // free(tmp_str);

	}// end of if(qresult)
    }// end of if(tcbmap)
#endif

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );
    
    hookdata = (H_normal_data_t *)malloc(sizeof(H_normal_data_t));
    hookdata->handle = hookapi_hook_return( ret_eip,
					    _malloc_hook_return,
		         		    hookdata,  		    // parametre for _malloc_hook_return( )
		         		    sizeof(H_normal_data_t) // parametre size
		      			  );

    return 0;
}// end of _malloc_hook_call( )



int _free_hook_call(void * opaque)
{
    uint32_t cr3   = 0;
    uint32_t vaddr = 0;
    // compositional symbolic execution 
    if(my_interface.is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(my_interface.monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( my_interface.monitored_cr3 != 0 ) && 
	( cr3 != my_interface.monitored_cr3 )
      )
    {
	return 0;
    }// end of if(temu_plugin)

    
    TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4),
		   4,
		   &vaddr
		 );    
    delete_entry_from_heap_data_list(vaddr);

    return 0;

    return 0;    
}// end of _free_hook_call( )

