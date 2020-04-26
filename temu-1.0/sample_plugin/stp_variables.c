#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <inttypes.h>
#include <string.h>

#include "hc_interface.h"
#include "stp_variables.h"

#include "H_test_config.h"


stp_variable_list_t stp_vlist;




// functions
/* ------------------------------------------------------------------------------------------------------ */
void init_stp_vlist( )
{
    stp_vlist.head  = NULL;
    stp_vlist.end   = NULL;

    stp_vlist.count = 0;
}// end of init_stp_vlist( )


void add_stp_vlist_entry(HExpr v_expr)
{    
    Pstp_variable_entry_t entry = NULL;

    if(Is_expr_in_stplist(v_expr) != 0)
    {
	return;
    }// end of if(Is_expr_in_stplist)

    entry = (Pstp_variable_entry_t)malloc(sizeof(stp_variable_entry_t));
    entry->v_expr = v_expr;
    entry->next   = NULL;


    if(stp_vlist.head == NULL)
    {
	stp_vlist.head = entry;	
	stp_vlist.end  = entry;
    }
    else
    {
	(stp_vlist.end)->next = entry;
	stp_vlist.end         = entry;
    }// end of if( )

    stp_vlist.count = stp_vlist.count + 1;

}// end of add_stp_vlist_entry( )


void delete_stp_vlist( )
{

    if(stp_vlist.count == 0)
    {
	return;
    }// end of if( )

	
    Pstp_variable_entry_t entry = (stp_vlist.head)->next;

    while(stp_vlist.head != NULL)
    {
	free(stp_vlist.head) ;
	stp_vlist.head = entry;
		
	if(entry == NULL)
	{
	    break;
	}// end of if( )

	entry = (stp_vlist.head)->next;

    } // end of while{ }	       


    stp_vlist.count = 0;
    stp_vlist.head  = NULL;
    stp_vlist.end   = NULL;

}// end of delete_stp_vlist( )



HExpr * obtaint_stp_vars_array(int * count)
{
    if(stp_vlist.count == 0)
    {
	return NULL;
    }// end of if( )

    char *  tmp_str  = NULL;
    int     i 	     = 0;
    HExpr * expr_arr = (HExpr *)malloc(sizeof(HExpr) * stp_vlist.count);

    Pstp_variable_entry_t entry = stp_vlist.head;
    while(entry != NULL)
    {

#ifdef HHUI_FUNC_SUMMARY_ENABLED
// filter out formal-parametres' concrete evaluations
	term_printf( "stored varible value : %x --- this ptr is %x --- ",
		     entry->v_expr,
		     *( (uint32_t *)(entry->v_expr) )
		   );	

	tmp_str = exprString(entry->v_expr);

	term_printf( "stored varible : %s\n",
		     tmp_str
		   );

	if( strstr( tmp_str,
		    "func"
		  ) != NULL
	  ) 
	{	    
	    entry = entry->next;	    
	    free(tmp_str);

	    continue;
	}
	else
	{
	    free(tmp_str);
	}// end of if()
#endif

	expr_arr[i] = entry->v_expr;

	i = i + 1;	
	entry = entry->next;
    }// end of while{ }

#ifdef HHUI_FUNC_SUMMARY_ENABLED
    *count = i;
#else
    *count = stp_vlist.count;
#endif

    return expr_arr;

}// end of obtaint_stp_vars_array( )


int Is_expr_in_stplist(HExpr expr)
{
    Pstp_variable_entry_t entry = stp_vlist.head;
#ifdef H_DEBUG_TEST
    char * tmp_str1 = exprString(expr);
    char * tmp_str2 = NULL;
#endif

    while(entry != NULL)
    {
	if(entry->v_expr == expr)
	{
#ifdef H_DEBUG_TEST
    	    free(tmp_str1);
	    free(tmp_str2);
#endif
	    return 1;
	}// end of if(entry->v_expr)

#ifdef H_DEBUG_TEST
	tmp_str2 = exprString(entry->v_expr);
	if( strcmp( tmp_str1,
		    tmp_str2
		  ) == 0
	  )
	{
    	    free(tmp_str1);
	    free(tmp_str2);
	    return 1;
	}// end of if(strcmp(...))
#endif
	entry = entry->next;
    }// end of while{entry}

#ifdef H_DEBUG_TEST
    free(tmp_str1);
#endif
    return 0;
}// end of Is_expr_in_stplist( )


#ifdef H_DEBUG_TEST
void stp_var_dump( )
{
    char * tmp_str = NULL;
    Pstp_variable_entry_t entry = stp_vlist.head;
    while(entry != NULL)
    {
	tmp_str = exprString(entry->v_expr);
	term_printf( "stp_var:%s\n",
		     tmp_str
		   );
	free(tmp_str);

	entry = entry->next;
    }// end of while{entry}
}// end of stp_var_dump( )
#endif

/* ------------------------------------------------------------------------------------------------------ */
// fucntions







