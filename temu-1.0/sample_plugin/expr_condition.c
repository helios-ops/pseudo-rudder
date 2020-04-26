#include <stdlib.h>
#include <inttypes.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "taintcheck_hook.h"
#include "expr_condition.h"
#include "function_summary.h"
#include "../TEMU_main.h"
#include "hc_interface.h"
#include "H_taint_record.h"
#include "../taintcheck.h"

#include "H_test_config.h"

#include "record_potential_error2file.h"

extern HVC  HHui_VC;
extern char h_reg_TEMU_index[8];
extern uint32_t h_TEMU_cpu_wr_index[8];

extern uint64_t * HH_regs_bitmap;



/* =================================================================================================================== */
/* NOTE: when function summary mechanism is adpted, 'path_Expr' would be suspended for calculating at the hook-point 
	 of the head a particular hooked function, during which 'func_precondition_expr' would be calculated for CJmps
	 instead. At the end of the hooked function, the literals of the calculated formula 'func_precondition_expr'
	 would be substituted by those corresponding actual parametric taints, with the derived new formula instance 
	 appended to the tail of 'path_Expr' representing the SYM-EXE result of this execution instance.
 */

// denoting function's local path-constraint expressed through formal parametres !
extern HExpr * func_precondition_expr; 

// denoting a resultant global-expr oriented constraint of a function's local execution expressed through actual parametres!
extern HExpr   func_local_ending_expr;

// denoting current global path-constraint
extern HExpr   path_Expr;


// called at the end of the end of the hooked function to reflect this function's execution effects to global 'path_Expr'.
/*
void func_summ_path_expr_local_2_global(void * func_m_entry)
{
    HExpr tmp_expr1 = NULL;
    HExpr tmp_expr2 = NULL;    	  
    function_summary_entry_t * entry = func_m_entry;

    // if(entry->curr_post_condition != NULL)
    if(func_precondition_expr != NULL)
    {
	

        path_Expr = vc_andExpr( HHui_VC,
			        path_Expr,
			        tmp_expr1
			      );
    }// end of if()
    
}// end of func_summ_path_expr_local_2_global( )
*/
/* =================================================================================================================== */


int H_build_formal_actual_expr_correspondence( void 		 	* func_m_entry,
					       HExpr		       ** formal_exprs,
					       HExpr 		       ** actual_exprs			 
					     )
{
    int count = 0;
    int i     = 0;
    int j     = 0;

    uint64_t tcbmap  = ( (function_summary_entry_t *)func_m_entry )->real_stackarg_tcbmap;
    char *   tmp_str = NULL;

    for(i = 0; i < 64; i = i + 1)
    {
	if( (tcbmap & ( (uint64_t)((uint64_t)1 << i) ) ) != 0 )
	{
	    count = count + 1;
	}// end of if(func_m_entry)
    }// end of for{i}

    HExpr *	       org_formal_exprs   = ( (function_summary_entry_t *)func_m_entry )->stackarg_exprs;
    H_taint_record_t * real_actual_params = ( (function_summary_entry_t *)func_m_entry )->real_stackargs;

    *formal_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
    *actual_exprs = (HExpr *)malloc(sizeof(HExpr) * count);

    for(i = 0; i < 64; i = i + 1)
    {
	if( (tcbmap & ( (uint64_t)((uint64_t)1 << i) )) != 0 )
	{
	    (*formal_exprs)[j] = org_formal_exprs[i];
	    /*
	    tmp_str = exprString((*formal_exprs)[j]);
	    term_printf( "formal_expr = %s ---- ",
			 tmp_str
		       );
	    free(tmp_str);
	    */

	    (*actual_exprs)[j] = real_actual_params[i].h_expr;
		
	    /*
	    tmp_str = exprString((*actual_exprs)[j]);
	    term_printf( "actual_expr = %s ---- ",
			 tmp_str
		       );
	    free(tmp_str);
	    */
	    j = j + 1;
	}// end of if(func_m_entry)
    }// end of for{i}

    return count;    
}// end of H_build_formal_actual_expr_correspondence( )


void h_condition_list_init(h_condition_list_t * cond_list)
{
    cond_list->head  = NULL;
    cond_list->end   = NULL;
    cond_list->count = 0;
}// end of h_condition_list_init( )


void delete_entry_from_h_condition_list( h_condition_list_t  * cond_list, 
					 h_condition_entry_t * entry
				       )
{
    if(entry == cond_list->head)
    {
	cond_list->head		= entry->next;	
	(cond_list->head)->prev = NULL;
    }
    else if(entry == cond_list->end)
    {
	cond_list->end	       = entry->prev;
	(cond_list->end)->next = NULL;
    }
    else
    {
	(entry->prev)->next = entry->next;
	(entry->next)->prev = entry->prev;
    }// end of if(entry)

    func_taint_memory_record_list_delete( &(entry->post_mem_cond) );
    free(entry);

    cond_list->count = cond_list->count - 1;
}// end of delete_entry_from_h_condition_list( )


h_condition_entry_t * add_entry_to_h_condition_list(h_condition_list_t * cond_list)
{
    h_condition_entry_t * entry = (h_condition_entry_t *)malloc(sizeof(h_condition_entry_t));

    entry->prev	      = NULL;
    entry->next	      = NULL;
    entry->reg_exprs  = NULL;
    entry->reg_ids    = NULL;
    entry->reg_count  = 0;

    // denoting whether or not this condition_entry currently could be applied to other callage or not !
    entry->calculated = 0;

    // Now introduce a new pre-condition for this function
    entry->pre_condition = vc_trueExpr(HHui_VC);
    // entry->pre_condition = H_build_general_postcondition_predicate( entry );

    if(cond_list->head == NULL)
    {
	cond_list->head = entry;
	cond_list->end  = entry;
    }
    else
    {
	(cond_list->end)->next = entry;
	entry->prev	       = cond_list->end;
	cond_list->end	       = entry;
    }// end of if(cond_list->head)

    cond_list->count = cond_list->count + 1;

    func_taint_memory_record_list_init( &(entry->post_mem_cond) );
    
    return entry;
}// end of add_entry_to_h_condition_list( )


void h_condition_list_delete(h_condition_list_t * cond_list)
{
    h_condition_entry_t * entry  = cond_list->head;
    h_condition_entry_t * entry1 = NULL;

    while(entry != NULL)
    {
	func_taint_memory_record_list_delete( &(entry->post_mem_cond) );	
	entry1 = entry;

	entry = entry->next;
	free(entry);
    }// end of while{entry}

}// end of h_condition_list_delete( )



/* checks whether any precondition is satisfied so as to apply function's calculated postconditions.
   if a pre-condition is satisfied, the field 'func_m_entry->curr_post_condition' would be set to the 
   specific entry. 
*/
int func_summ_test_precondition(void * func_m_entry)
{
    function_summary_entry_t * entry = func_m_entry;

    HExpr tmp_expr1 = NULL;
    HExpr tmp_expr2 = NULL;
    HExpr tmp_expr3 = vc_trueExpr(HHui_VC);
    HExpr tmp_expr4 = NULL;
    HExpr tmp_expr5 = NULL;


    h_condition_entry_t * cond_entry = NULL;

    char * tmp_str  = NULL;
    int   qresult   = 0;

    int i     = 0;
    int j     = 0;
    int index = 0;

    uint32_t esp    = 0;
    uint32_t value  = 0;
    uint32_t tcbmap = 0;

    esp = entry->stack_base;
    /*
    TEMU_read_register( esp_reg,
			&esp
		      );
    */

    if((entry->summary_conditions).count == 0)
    {
	return 0;    
    }// end of if()	
    
    if( (entry->argsize == 0) && 
	(entry->regarg_mask == 0)
      )
    {
        // non-preconditions at all !
	entry->curr_post_condition = (entry->summary_conditions).head;
	return 1;
    }// end of if(entry->argsize)


/* --------------------------------------------------------------------------------------- */
    // builds current stack-parametres' expression
    for(i = 0; i < entry->argsize; i = i + 1)
    {
	TEMU_read_mem( esp + 4 + i,
		       1,
		       &value
		     );

	tmp_expr1 = vc_bvConstExprFromInt( HHui_VC,
					   8,
					   value
					 );
	
	// tmp_str = exprString((entry->stackarg_exprs)[i]);
	// term_printf("%s\n", tmp_str);

	tmp_expr2 = vc_eqExpr( HHui_VC,
			       tmp_expr1,
			       (entry->stackarg_exprs)[i]
			     );
	tmp_expr3 = vc_andExpr( HHui_VC,
			        tmp_expr3,
				tmp_expr2
			      );
    }// end of for{i}

    // builds current register-parametres' expression  
    index = 0;
  
#ifndef H_FUNC_SUMM_STACKPARAM_ONLY
    for(i = 0; i < 8; i = i + 1)
    {	
	if( (entry->regarg_mask & (1 << i)) != 0 )
	{
	    TEMU_read_register( h_TEMU_cpu_wr_index[i],
			        &value
			      );
	    tmp_expr1 = vc_bv32ConstExprFromInt( HHui_VC,					       
					         value
					       );
	    tmp_expr2 = vc_eqExpr( HHui_VC,
				   tmp_expr1,
				   // (entry->regarg_exprs)[i]
				   (entry->regarg_exprs)[index]
				 );

	    tmp_expr3 = vc_andExpr( HHui_VC,
				    tmp_expr3,
				    tmp_expr2
				  );

	    index = index + 1;
	}// end of if(entry)	
    }// end of for{i}
#endif
/* --------------------------------------------------------------------------------------- */



    /* after the total parametre-expressions have been built, we would check 
       if it do satisfy any pre-calculated pre-conditions so as to make the 
       neccessary application of the corresponding post-conditions.
    */
    cond_entry = (entry->summary_conditions).head;
/*
    term_printf( "\ncurrent summary condition count for this function is %d\n",
		 (entry->summary_conditions).count
	       );
 */
    while(cond_entry != NULL)
    {
	/*
	tmp_str = exprString(cond_entry->pre_condition);
	term_printf( "querying for precondition : %s\n",
		     tmp_str
		   );
	free(tmp_str);

	tmp_str = exprString(tmp_expr3);
	term_printf( "querying for expr : %s\n",
		     tmp_str
		   );
	free(tmp_str);
	*/
	if(cond_entry->calculated == 0)
	{
	    cond_entry = cond_entry->next;
	    continue;
	}// end of if(cond_entry->calculated)

	tmp_expr4 = vc_andExpr( HHui_VC,
				tmp_expr3,
				cond_entry->pre_condition
			      );

	tmp_expr5 = vc_notExpr( HHui_VC,
				tmp_expr4
			      );
	/*
	tmp_str = exprString(tmp_expr5);
	term_printf( "querying for %s\n",
		     tmp_str
		   );
	free(tmp_str);
	*/

	vc_push(HHui_VC);
	qresult = vc_query( HHui_VC,
			    tmp_expr5
			  );
	vc_pop(HHui_VC);

	if(qresult == 0)
	{
	    // term_printf("a pre-condition does satisfy !\n");
	    entry->curr_post_condition = cond_entry;
	    
	    return 1;
	}// end of if(qresult)

	vc_DeleteExpr(tmp_expr5);
	vc_DeleteExpr(tmp_expr4);

	cond_entry = cond_entry->next;
    }// end of while{cond_entry}
    
    return 0;
}// end of func_summ_test_precondition( )



HExpr H_build_general_postcondition_predicate( // h_func_taint_mem_record_list_t * mem_list,
					       void * f_entry  // function_summary_entry_t 
					     )
{
    function_summary_entry_t * func_m_entry = (function_summary_entry_t *)f_entry;

    // h_func_taint_mem_record_entry_t * entry = mem_list->head;

    H_taint_record_t * A_stackargs = func_m_entry->real_stackargs;
    HExpr * 	       F_stackargs = func_m_entry->stackarg_exprs;
    uint64_t           tcbmap      = func_m_entry->real_stackarg_tcbmap;

    H_taint_record_t * A_regargs   = func_m_entry->real_regargs;   // actual register parametres
    HExpr *	       F_regargs   = func_m_entry->regarg_exprs;   // formal register parametres ---8 '32-bits-expr's
    uint32_t	       A_regtcbmap = func_m_entry->real_reg_tcbmap;// actual byte-wise tcbmap
    
    int	     i = 0;    
    int      j = 0;
    int      k = 0;
	
    uint32_t local_tcbmap = 0;

    HExpr tmp_expr1 = NULL;
    HExpr tmp_expr2 = NULL;

    char * tmp_str1 = NULL;
    char * tmp_str2 = NULL;


    term_printf( "tcbmap = %x\n",
		 tcbmap
	       );

    // build stack-argument-predicate !
    /* --------------------------------------------------------------------------------------------------- */
    for(i = 0; i < func_m_entry->argsize; i = i + 1)
    {
	if( (tcbmap & (1 << i)) != 0 )
	{
	    
/*
	    tmp_str1 = exprString((A_stackargs[i]).h_expr);
	    term_printf( "actual stack parametre expr is %s\n",
			 tmp_str1
		       );
	    free(tmp_str1);

	    tmp_str2 = exprString(F_stackargs[i]);	    
	    term_printf( "formal stack parametre expr is %s\n",
			 tmp_str2
		       );
	    free(tmp_str2);
*/	    	    

	    tmp_expr1 = vc_eqExpr( HHui_VC,
				   (A_stackargs[i]).h_expr, // actual parametre
				   F_stackargs[i] 	    // formal parametre
				 );
	    if(j == 0)
	    {
		tmp_expr2 = tmp_expr1;
	    }
	    else
	    {
		tmp_expr2 = vc_andExpr( HHui_VC,
					tmp_expr2,
					tmp_expr1
				      );
	    }// end of if(j)

	    j = j + 1;

	}// end of if(tcbmap)

	// entry = entry->next;	
	// i = i + 1;
    }// end of for{i}
    /* --------------------------------------------------------------------------------------------------- */


    j = 0;
    k = 0;
    // build register argument predicate !
    /* --------------------------------------------------------------------------------------------------- */
#ifndef H_FUNC_SUMM_STACKPARAM_ONLY
    for(i = 0; i < 8; i = i + 1)
    {
	local_tcbmap = ( ( A_regtcbmap & (0xF << (i * 4)) ) >> (i * 4) );
	if(local_tcbmap != 0)
	{
	    for(j = 0; j < 4; j = j + 1)
	    {
		if(local_tcbmap & (1 << j))	    
	        {
	            tmp_expr1 = vc_eqExpr( HHui_VC,
				           A_regargs[i*4 + j].h_expr, // actual parametre
					   //F_regargs[i*4 + j]	      // formal parametre
					   vc_bvExtract( HHui_VC,
						  	 F_regargs[i],
							 ((j + 1) * 8) - 1,
							 (j * 8)
						       )
				         );

		    tmp_expr2 = vc_andExpr( HHui_VC,
					    tmp_expr2,
					    tmp_expr1
					  );
	            // j = j + 1;
	        }// end of if(A_tcbmap)
	    }// end of for{j}
	}// end of if(local_tcbmap)
    }// end of for{i}
#endif
    /* --------------------------------------------------------------------------------------------------- */

    return tmp_expr2;
}// end of H_build_general_postcondition_predicate( )



void mem_states_postcondition_apply( h_func_taint_mem_record_list_t * mem_list,
				     function_summary_entry_t *       func_m_entry,
				     // HExpr			      common_predicate
				     HExpr *			      formal_exprs,
				     HExpr * 			      actual_exprs,
				     int			      count
				   )
{
    h_func_taint_mem_record_entry_t * entry = mem_list->head;

    H_taint_record_t * A_stackargs = func_m_entry->real_stackargs;
    HExpr * 	       F_stackargs = func_m_entry->stackarg_exprs;
    uint64_t           tcbmap      = func_m_entry->real_stackarg_tcbmap;

    HExpr tmp_expr1 = NULL;
    HExpr tmp_expr2 = NULL;

    char * tmp_str  = NULL;

    int    b_find   = 0;
    char * tmp_str1 = NULL;
    char * tmp_str2 = NULL;

    /*
    vc_push(HHui_VC);		
    vc_assertFormula( HHui_VC,
		      common_predicate
		    );
    */
    int i = 0;

/*
    for(i = 0; i < count; i = i + 1)
    {
	tmp_str = exprString(formal_exprs[i]);
	term_printf( "formal mem-parametre %d ---- %s, ",
		     i,
		     tmp_str
		   );
	free(tmp_str);

	tmp_str = exprString(actual_exprs[i]);
	term_printf( "actual mem-parametre %d ---- %s, ",
		     i,
		     tmp_str
	           );
	free(tmp_str);
    }// end of for{i}
*/
    while(entry != NULL)
    {	
	/*	
	tmp_expr2 = vc_simplify( HHui_VC,
				 (entry->record).h_expr
			       );
	*/

/*
	tmp_str = exprString((entry->record).h_expr);
	term_printf( "original mem-expr is %s\n",
		     tmp_str
		   );
	free(tmp_str);
*/
	/* -------------------------------------------------------------- */
	b_find = 0;
	tmp_str1 = exprString( (entry->record).h_expr );
	for(i = 0; i < count; i = i + 1)
	{
	    tmp_str2 = exprString(formal_exprs[i]);
	    
	    if( strstr( tmp_str1,
			tmp_str2
		      ) != NULL )
	    {
		b_find = 1;
		free(tmp_str2);
		break;
	    }// end of if(strstr( ))

	    free(tmp_str2);
	}// end of for

	free(tmp_str1);
	/* -------------------------------------------------------------- */


	if( ( b_find == 0 ) && 
	    ( getExprKind((entry->record).h_expr) != 1 ) // not a single variable !
	  )
	{
	    goto MEM_RESTORE_AGAIN;
	}// end of if(b_find)

	(entry->record).h_expr = H_var_substitute_4expr( HHui_VC,
	 			 		  	 (entry->record).h_expr,
							 formal_exprs,
							 actual_exprs,
							 count,
							 NULL // H_TEMU_printExpr
					      	       );
/*
	tmp_str = exprString((entry->record).h_expr);
	term_printf( "changed mem-expr is %s\n",
		     tmp_str
		   );
	free(tmp_str);
*/
	// HHui Fixme ??
	(entry->record).type   = (A_stackargs[0]).type;
	(entry->record).origin = (A_stackargs[0]).origin;
	(entry->record).offset = 0;

	taintcheck_taint_virtmem( entry->vaddr,
				  1,
				  1,
				  &(entry->record)
				);	

MEM_RESTORE_AGAIN:
	entry = entry->next;	
    }// end of while{entry}

    // vc_pop(HHui_VC);
}// end of mem_states_postcondition_apply( )



void register_states_postcondition_apply( h_condition_entry_t *      cond_entry,
					  function_summary_entry_t * func_m_entry,
					  HExpr			     common_predicate
					)
{
    int i     = 0;
    int j     = 0;
    int index = 0;
    HExpr *	       F_regargs = func_m_entry->regarg_exprs;   // formal register parametres --- 32-bits expr
    // uint8_t	       F_regmask = func_m_entry->regarg_mask;    // denoting this register is used as a parametre

    H_taint_record_t * A_regargs = func_m_entry->real_regargs;   // actual register parametres
    uint32_t	       A_tcbmap  = func_m_entry->real_reg_tcbmap;// actual byte-wise tcbmap

    HExpr *	       Result_reg_exprs = cond_entry->reg_exprs; // destination expr --- 4 records per GP-register


    HExpr 	       tmp_expr1 = NULL;
    HExpr 	       tmp_expr2 = NULL;
    HExpr	       tmp_expr3 = NULL;

    H_taint_record_t   records[4];
    uint32_t	       taint_bmap     = 0;
    uint32_t 	       tmp_taint_bmap = 0;

    /*
    vc_push(HHui_VC);
    vc_assertFormula( HHui_VC,
		      common_predicate
		    );
    */

    // final symbolic-values
    for(i = 0; i < cond_entry->reg_count; i = i + 1)
    {
	index = cond_entry->reg_ids[i] - R_EAX;

	// formal parametre
	// if( F_regmask & (1 << index) )

	tmp_taint_bmap = A_tcbmap & (0xF << (4 * index)) >> (4 * index) ;	

	// actually tainted register when function is called !
	if(tmp_taint_bmap != 0)
	{
	    for(j = 0; j < 4; j = j + 1)
	    {
		taint_bmap = 0;

		if( A_tcbmap & (0x1<<j) ) 
		{
		    taint_bmap = taint_bmap | (1 << j);

		    records[j].h_expr = vc_simplify( HHui_VC,
			    		 	     Result_reg_exprs[4 * index + j] 
			   	         	   );			
		
		    records[j].type   = A_regargs[index].type;
		    records[j].origin = A_regargs[index].origin;
		    records[j].offset = A_regargs[index].offset;
		}// end of if(A_tcbmap)
	    }// end of for{j}

	    taintcheck_taint_register( cond_entry->reg_ids[i],
				       0,
				       4,
				       taint_bmap,
				       records
				     );
	    memset( records,
		    '\0',
		    sizeof(H_taint_record_t) * 4
		  );
	}
	else
	{
	    taintcheck_taint_register( cond_entry->reg_ids[i],
				       0,
				       4,
				       0x0, // taint !
				       NULL
				     );
	}// end of if(F_regmask)
	
    }// end of for{i}

    // vc_pop(HHui_VC);
}// end of register_states_postcondition_apply( )



void func_summ_postcondition_apply(void * func_m_entry)
{
    int    i       = 0;
    char * tmp_str = NULL;

    function_summary_entry_t * entry = (function_summary_entry_t *)func_m_entry;
    h_condition_entry_t * cond_entry = entry->curr_post_condition;

    h_func_taint_mem_record_list_t * mem_list = (h_func_taint_mem_record_list_t *)( &(cond_entry->post_mem_cond) );

/*
    HExpr common_predicate = H_build_general_postcondition_predicate( // mem_list,
					       			      func_m_entry
								    );
*/

    HExpr * formal_exprs     = NULL;
    HExpr * org_formal_exprs = NULL;

    HExpr * actual_exprs = NULL;

    int count = H_build_formal_actual_expr_correspondence( func_m_entry,
					       		   &formal_exprs,
					                   &actual_exprs			 
					     		 );
    
    org_formal_exprs = (HExpr *)malloc(sizeof(HExpr) * count);
    for(i = 0; i < count; i = i + 1)
    {
	org_formal_exprs[i] = formal_exprs[i];
    }// end of for{i}
    

    HExpr localpath_expr   = NULL;

    char * tmp_str1 = NULL;
    char * tmp_str2 = NULL;

    // if(common_predicate != NULL)
    if(count != 0)
    {	
	/*
	vc_push(HHui_VC);

	vc_assertFormula( HHui_VC,
			  common_predicate
			);
	

	tmp_str1 = exprString(common_predicate);
	term_printf( "common_predicate : %s\n",
		     tmp_str1
		   );
	free(tmp_str1);
	*/

        // memory states modification
        mem_states_postcondition_apply( mem_list,
				        func_m_entry,
					formal_exprs,
					actual_exprs,
					count
					// common_predicate
					
				      );
#ifndef H_FUNC_SUMM_STACKPARAM_ONLY
        // GP-register states modification
	/*
        register_states_postcondition_apply( cond_entry,
					     func_m_entry,
					     common_predicate
				           );
	*/
#endif

	// global path-constraint modification
	// if(cond_entry->local_path_constraint != NULL)
	if(cond_entry->pre_condition != NULL)
	{	    	  
	    /*
	    for(i = 0; i < count; i = i + 1)
	    {
		formal_exprs[i] = org_formal_exprs[i];

		tmp_str = exprString(formal_exprs[i]);
		term_printf( "formal mem-parametre %d ---- %s, ",
			     i,
			     tmp_str
			   );
		free(tmp_str);

		tmp_str = exprString(actual_exprs[i]);
		term_printf( "actual mem-parametre %d ---- %s, ",
			     i,
			     tmp_str
			   );
		free(tmp_str);
	    }// end of for{i}
	    */

	    tmp_str = exprString(cond_entry->pre_condition);
	    term_printf( "\n------------------------------ applying formal cond-expr: ------------------------------\n%s\n",
			 tmp_str
		       );
	    free(tmp_str);
	    term_printf( "\n----------------------------------------------------------------------------------------\n");

  	    localpath_expr = H_var_substitute_4expr( HHui_VC,
	 			   		     cond_entry->pre_condition,
						     formal_exprs,
						     actual_exprs,
						     count,
						     NULL // H_TEMU_printExpr
				      		   );

	    /*
	    tmp_str1 = exprString(localpath_expr);
	    term_printf( "changed local expr : %s\n",
			 tmp_str1
		       );
	    free(tmp_str1);
	    */

	    /*
	    tmp_str1 = exprString(cond_entry->pre_condition);
	    term_printf( "original local expr : %s\n",
			 tmp_str1
		       );
	    free(tmp_str1);
	    */

	    // pointer to local path-constraint with regard to function's actual parametres
	    func_local_ending_expr = localpath_expr;

	    // record the total effects of the execution of this function with regard to its actual parametres !
	    // ((function_summary_entry_t *)func_m_entry)->curr_local_expr = localpath_expr;
	    

	    // func_precondition_expr = &( ((function_summary_entry_t *)func_m_entry)->curr_local_expr );

	    /*
	    localpath_expr = vc_simplify( HHui_VC,
					  cond_entry->pre_condition
					);
	    */

	    // localpath_expr = cond_entry->pre_condition;


/*
	    path_Expr = vc_andExpr( HHui_VC,
				    path_Expr,
				    localpath_expr
			          );
 */
	    if(entry->last_func != NULL)
	    {
		term_printf( "func_end: restore to the context of the last function---[0x%x] !\n",
			     ( (function_summary_entry_t *)(entry->last_func) )->vaddr
			   );

	        ( (entry->last_func)->curr_post_condition )->pre_condition = 
						vc_andExpr( HHui_VC,
							    ( (entry->last_func)->curr_post_condition )->pre_condition,
							    localpath_expr
							  );
	    }
	    else
	    {
	        path_Expr = vc_andExpr( HHui_VC,
				        path_Expr,
				        localpath_expr
			              );
	    }// end of if(entry)
	}// end of if(cond_entry)

//	vc_pop(HHui_VC);
    }// end of if(common_predicate)
	

    free(formal_exprs);
    free(actual_exprs);
}// end of func_summ_postcondition_apply( )



/* As memory effects stored in mem_list, local-path-constraint accumulated in 
   'local_path_constraint' of 'func_m_entry->curr_post_condition', both along
   execution, we only cares about GP-registers and local-path-constraint here. 
*/
void postcondition_calculate(void * func_m_entry)
{
    h_condition_entry_t * cond_entry = ( (function_summary_entry_t *)func_m_entry )->curr_post_condition;
    HExpr    common_predicate = NULL;

    int      count    = 0;
    int      i        = 0;
    int	     j	      = 0;
    int	     k	      = 0;
    uint64_t tcbmap   = 0;
    HExpr    tmp_expr = NULL;

    H_taint_record_t records[4];    
    

    if(cond_entry == NULL)
    {
	return;
    }// end of if(cond_entry)

    h_func_taint_mem_record_list_t * mem_list = NULL;

    /*
    mem_list	     = (h_func_taint_mem_record_list_t *)( &(cond_entry->post_mem_cond) );
    common_predicate = H_build_general_postcondition_predicate( // mem_list,
					       			func_m_entry
							      );    
    if(common_predicate == NULL)
    {
	return;
    }// end of if(common_predicate)
    */

    for(i = 0; i < 8; i = i + 1)
    {
	tcbmap = (*HH_regs_bitmap) & ( 0xF << (h_reg_TEMU_index[i] * 4) );
	if(tcbmap != 0)
	{
	    count = count + 1;
	}// end of if(tcbmap)
    }// end of for{i}

    if(count == 0)
    {
	cond_entry->reg_ids   = NULL;
	cond_entry->reg_exprs = NULL;
	cond_entry->reg_count = 0;

	cond_entry->calculated = 1;
	return;
    }// end of if(count)

    cond_entry->reg_ids   = (uint8_t *)malloc(sizeof(uint8_t) * count);
    cond_entry->reg_exprs = (HExpr *)malloc(sizeof(HExpr) * count * 4);
    cond_entry->reg_count = count;

    k = 0;
    for(i = 0; i < 8; i = i + 1)
    {
	tcbmap = taintcheck_register_check( h_reg_TEMU_index[i],
					    0,
					    4,
					    records
					  );
	if(tcbmap != 0)
	{
	    for(j = 0; j < 4; j = j + 1)
	    {
		(cond_entry->reg_exprs)[k * 4 + j] = records[j].h_expr;
	    }// end of for{j}

	    k = k + 1;
	}// end of if(tcbmap)
    }// end of for{i}

    cond_entry->calculated = 1;

}// end of postcondition_calculate( )



void Copy_condition( h_condition_entry_t * src_cond_entry, 
		     h_condition_entry_t * dst_cond_entry
		   )
{
    Copy_taint_mem_list( &(src_cond_entry->post_mem_cond),
			 &(dst_cond_entry->post_mem_cond)
		       );
}// end of Copy_condition( )


h_condition_entry_t * expr_cond_branch_save(void * func_entry)
{
    h_condition_entry_t * cond_entry = 
		add_entry_to_h_condition_list( &( ( (function_summary_entry_t *)func_entry 
					     	  )->summary_conditions
						) 
					     );
    
    Copy_condition( ( (function_summary_entry_t *)func_entry )->curr_post_condition, 
		    cond_entry
		  );

    return cond_entry;
}// end of expr_cond_branch_save( )


void func_dump_total_precondition(void * func_entry)
{
    h_condition_entry_t * cond_entry = ( ( (function_summary_entry_t *)func_entry )->summary_conditions ).head;
    int  fd    = 0;
    int  id    = 0;
    char buffer[1024];
    int  count = 0;
    char str_filename[100];
    char * tmp_str = NULL;

    umask(0);
    
    count = sprintf( str_filename,
		     "func_%x_precondition",
		     ( (function_summary_entry_t *)func_entry )->vaddr
		   );
    str_filename[count] = '\0';

    fd = open( str_filename,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );

    if(fd >= 0)
    {
	while(cond_entry != NULL)
	{
	    // if(cond_entry->calculated != 0)
	    // {
		id = id + 1;
		count = sprintf( buffer,
				 "func_preecondition_%d: ---- calculate = %d\n",
				 id,
				 cond_entry->calculated
			       );
		buffer[count] = '\0';
		write( fd,
		       buffer,
		       count
		     );

		tmp_str = exprString(cond_entry->pre_condition);
		write( fd,
	       	       tmp_str,
		       strlen(tmp_str)
	     	     );		
		free(tmp_str);

		write( fd,
		       "\n",
		       1
		     );
	    // }// end of if(cond_entry->calculated)

	    cond_entry = cond_entry->next;
	}// end of while{cond_entry}

        close(fd);
    }// end of if(fd)

}// end of func_dump_total_precondition( )






