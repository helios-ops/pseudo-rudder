#include <stdio.h>
#include <inttypes.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

#include "../TEMU_main.h"
#include "HVM_state.h"

#include "hc_interface.h"


// several global configuration switches
#include "H_test_config.h"

#include "stp_variables.h"

#include "taintcheck_hook.h"
#include "expr_condition.h"
#include "function_summary.h"

#include "H_testcase_generation.h"

extern plugin_interface_t my_interface;


extern int isREP;
extern uint32_t HHui_current_monitored_eip;

/* ------------------------------------------------------------------------------------------------ */
// function's current local-pre-condition expressed through local function's formal parametres
extern HExpr * func_precondition_expr;

// function's current local-pre-condition expressed through local function's actual parametres
extern HExpr   func_local_ending_expr;
/* ------------------------------------------------------------------------------------------------ */

#ifdef H_DEBUG_TEST
int H_predicate_count = 0;
void predicate_change( HVC   hvc,
		       HExpr pred_expr,
		       HExpr prev_total_expr,
		       HExpr total_expr
		     )
{
    HExpr  tmp_expr  = NULL;
    HExpr  tmp_expr1 = NULL;

    int    isSAT    = -1;
    int    isSAT1   = -1;

    int    dmp_fd   = -1;
    char * tmp_str  = NULL;

    H_predicate_count = H_predicate_count + 1;
    if(H_predicate_count == 23)
    {
	term_printf("desired 23 predicate\n");
    }// end of if(H_predicate_count)

    tmp_expr = vc_notExpr( hvc,
			   total_expr
			 );

    vc_push(hvc);
    isSAT = vc_query( hvc,
	    	      tmp_expr
	    	    );
    vc_pop(hvc);

    if(isSAT != 0)
    {	
	dbg_testcase_generate_4_expr( "err_path_tc",
				      prev_total_expr
			            );
	
	dbg_testcase_generate_4_expr( "err_pred_tc",
				      pred_expr
			            );

	term_printf("contradictory predicate !\n");
	tmp_str = exprString(total_expr);
	umask(0);
	dmp_fd = open( "err_path_dump",
		       (O_CREAT | O_RDWR),
		       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		     );
	write( dmp_fd,
	       tmp_str,
	       strlen(tmp_str)
	     );
	close(dmp_fd);
	free(tmp_str);

	tmp_str = exprString(pred_expr);
	umask(0);
	dmp_fd = open( "err_predicate_dump",
		       (O_CREAT | O_RDWR),
		       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		     );
	write( dmp_fd,
	       tmp_str,
	       strlen(tmp_str)
	     );
	close(dmp_fd);
	free(tmp_str);
    }// end of if(isSAT)

    vc_DeleteExpr(tmp_expr);
}// end of predicate_change( )
#endif

int branch_save( HVC      HHui_VC,
		 HExpr *  path_Expr,       	      // IN-OUT
		 HExpr    predicate_expr,
		 int      H_predicate,

		 uint32_t tbranch,
		 uint32_t fbranch,	   

		 uint32_t ir_true_real_fbranch_addr,  // calculated IR true branch !		 
		 uint32_t ir_false_real_tbranch_addr  // calculated IR false branch !
	       )
{
    term_printf( "tbranch is %x, fbranch is %x",
		 tbranch,
		 fbranch
	       );

#ifdef H_DEBUG_TEST
    if(tbranch != 0)
    {
	if( ( tbranch != ir_true_real_fbranch_addr ) && 
	    ( tbranch != ir_false_real_tbranch_addr )
	  )
	{
	    if(fbranch != 0)
	    {
		if( ( fbranch != ir_true_real_fbranch_addr ) && 
		    ( fbranch != ir_false_real_tbranch_addr )
		  )
		{
	            term_printf("fucking branch-calculation \n");
		
		    // HHui added at March 6th, 2012
		    return 0;
		}// end of if(fbranch)
	    }// end of if(fbranch)
	}// end of if(tbranch)
    }
#endif

    if(ir_true_real_fbranch_addr != 0)
    {
	return branch_save_ir_true( HHui_VC,
				    path_Expr,
				    predicate_expr,
				    H_predicate,
				    tbranch,
				    fbranch,
				    ir_true_real_fbranch_addr
				  );
    }
    else 
    {
	return branch_save_ir_false( HHui_VC,
				     path_Expr,
				     predicate_expr,
				     H_predicate,
				     tbranch,
				     fbranch,
				     ir_false_real_tbranch_addr
				   );	
    }// end of if( )

}// end of branch_save( )



/* return the current branch's selection. 
   1 --- true 
   0 --- false
 */
int branch_save_ir_true( HVC      HHui_VC,
			 HExpr *  path_Expr,       // IN-OUT
			 HExpr    predicate_expr,
			 int      H_predicate,

			 uint32_t tbranch,
			 uint32_t fbranch,	   

			 uint32_t ir_true_real_fbranch_addr 	   // calculated IR false branch !		 
		       )
{
        h_condition_entry_t * cond_entry = NULL;

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
/*
	int count = 0;
	HExpr * stp_vars = obtaint_stp_vars_array(&count);


	vc_push(HHui_VC);
	int hqres = vc_query( HHui_VC,
			     vc_notExpr( HHui_VC,
					 predicate_expr
				       )
			   );
	
	HWholeCounterExample hswc = vc_getWholeCounterExample(HHui_VC);
	HExpr data = vc_getTermFromCounterExample( HHui_VC,
					      	   stp_vars[0],
						   hswc
				    		 );
	vc_pop(HHui_VC);

	term_printf( "[0] = 0x%x satisfying predicate !\n",
		     getBVInt(data)
		   );
	free(stp_vars);
*/
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */


    func_local_ending_expr = NULL;

    char * str_branch_type = NULL;

    HType  path_expr_type  = vc_getType( HHui_VC,
					 *path_Expr
				       );
    HType  pred_expr_type  = vc_getType( HHui_VC,
					 predicate_expr
				       );

    char * str_path_type   = typeString(path_expr_type);
    char * str_pred_type   = typeString(pred_expr_type);

#ifdef H_DEBUG_TEST
    HExpr tmp_expr = *path_Expr;
#endif

    term_printf( "\npath_Expr's type is %s, predicate_expr's type is %s\n",
		 str_path_type,
		 str_pred_type
	       );

    free(str_path_type);
    free(str_pred_type);
/*
    vc_push(HHui_VC);
    vc_query( HHui_VC,
	      predicate_expr
	    );    
    vc_pop(HHui_VC);
 */
    HExpr another_local_expr = NULL;

    HExpr branch_expr = NULL;
    int	  is_SAT      = 0;

    int   ir_true_or_false = 0;

    HExpr * formal_param_exprs = NULL;
    HExpr * actual_param_exprs = NULL;
    int     param_count	       = 0;		 
    char *  tmp_expr_str       = NULL;

    if(predicate_expr != NULL)
    {
	term_printf( "\nH_predicate = %d\n",
		     H_predicate
		   );

	tmp_expr_str = exprString(predicate_expr);
	term_printf( "predicate is %s\n",
		     tmp_expr_str
		   );
	free(tmp_expr_str);

	if(H_predicate == 0)
	{
	    // really takes false branch !
	    if(fbranch == ir_true_real_fbranch_addr)
	    {
		// CJMP true-case eip == real false		
	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		if( (func_precondition_expr != NULL) &&
		    (*func_precondition_expr != NULL)
		  )
		{
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
				              *func_precondition_expr,
				              vc_notExpr( HHui_VC,
					                  predicate_expr
					                )
				            );
		    */

		    // current global path
		    branch_expr = *path_Expr;

		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
				              	     *func_precondition_expr,
				             	     vc_notExpr( HHui_VC,
					             		 predicate_expr
					                       )
				            	   );

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          predicate_expr
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			    func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			     another_local_expr,
									     formal_param_exprs,
									     actual_param_exprs,
									     param_count,
									     NULL
									   );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)

		    // }// end of if(func_local_ending_expr)

		    // current local path expressed through function's actual parametres !
		}
		else
		{
	    #endif		
		
		another_local_expr = NULL;
		term_printf("ggggggggg-d\n");

		branch_expr = vc_andExpr( HHui_VC,
				          *path_Expr,
				          vc_notExpr( HHui_VC,
					              predicate_expr
					            )
				        );

		*path_Expr = vc_andExpr( HHui_VC,  
			          	 *path_Expr,
					 predicate_expr
				       );
		     
	    #ifdef H_DEBUG_TEST
 		// H_predicate_count = H_predicate_count + 1;
		predicate_change( HHui_VC,
				  predicate_expr,
				  tmp_expr,
		    		  *path_Expr
		     		);
	    #endif

	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)
	    #endif

		// indicating IR-true is taken
		ir_true_or_false = 1;
	    }
	    else // if(fbranch)
	    {

	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		// local function-precondition	
		if( (func_precondition_expr != NULL) &&
		    (*func_precondition_expr != NULL)
		  )
		{
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
				              *func_precondition_expr,						          
					      predicate_expr
				            );	
		    */

		    // current global path
		    branch_expr = *path_Expr;

		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
				              	     *func_precondition_expr,
					      	     predicate_expr
				            	   );	

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          vc_notExpr( HHui_VC,
								      predicate_expr
								    )
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			     func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			      another_local_expr,
									      formal_param_exprs,
									      actual_param_exprs,
									      param_count,
									      NULL
									    );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)
		    // }// end of if(func_local_ending_expr)
		}
		else
		{
	    #endif
	            // CJMP false-case eip == real false
		    branch_expr = vc_andExpr( HHui_VC,
				              *path_Expr,        
					      predicate_expr
				            );	

		    another_local_expr = NULL;

		    *path_Expr = vc_andExpr( HHui_VC,  
			        	     *path_Expr,
					     vc_notExpr( HHui_VC,
					                 predicate_expr
					               )
				           );

	        #ifdef H_DEBUG_TEST
		    // inc_H_predicate_count( );
		    predicate_change( HHui_VC,
				      vc_notExpr( HHui_VC,
					          predicate_expr
					        ),
				      tmp_expr,
				      *path_Expr
				    );
		#endif

	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)
	    #endif
		// indicating IR-false is taken
		ir_true_or_false = 0;

	    }// end of if(fbranch == ir_true_real_fbranch_addr)
	}
	else // (H_predicate == 1)
	{
	    // really takes true branch !
	    if(tbranch == ir_true_real_fbranch_addr)
	    {
		term_printf("sxssd\n");
		// CJMP true-case eip == real true

	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		// local function-precondition
		if( (func_precondition_expr != NULL) &&
		    (*func_precondition_expr != NULL)
		  )
		{
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
				              *func_precondition_expr,
				              vc_notExpr( HHui_VC,
					                  predicate_expr  
					                )
				            );
		    */

		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
				              	     *func_precondition_expr,
				             	     vc_notExpr( HHui_VC,
					                         predicate_expr  
					                       )
				                   );
		    // current global path
		    branch_expr = *path_Expr;

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          predicate_expr
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			     func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			      another_local_expr,
									      formal_param_exprs,
									      actual_param_exprs,
									      param_count,
									      NULL
									    );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)
		    // }// end of if(func_local_ending_expr)
		}
		else
		{
	    #endif
		    another_local_expr = NULL;

		    branch_expr = vc_andExpr( HHui_VC,
				              *path_Expr,
				              vc_notExpr( HHui_VC,
					                  predicate_expr  
					                )
				            );
		    
		    *path_Expr = vc_andExpr( HHui_VC,  
			        	     *path_Expr,
					     predicate_expr
				           );
		    
	        #ifdef H_DEBUG_TEST
 		    //inc_H_predicate_count( );
		    predicate_change( HHui_VC,
				      predicate_expr,
				      tmp_expr,
		      		      *path_Expr
		     		    );
		#endif

	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)
	    #endif
		// indicating IR-true is taken
		ir_true_or_false = 1;
	    }
	    else
	    {
	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		// local function-precondition
		if( (func_precondition_expr != NULL) &&
		    (*func_precondition_expr != NULL)
		  )
		{		
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
				              *func_precondition_expr,						          
					      predicate_expr
				            );
		     */

		    /*
		    str_branch_type = exprString(*func_precondition_expr);
		    term_printf( "branch_save( ): local predicate expr is : %s",
				 str_branch_type
			       );
		    free(str_branch_type);
		    */

		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
				                     *func_precondition_expr,
					             predicate_expr
				            	   );

		    // current global path
		    branch_expr = *path_Expr;

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          vc_notExpr( HHui_VC,
								      predicate_expr
								    )
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			    func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			     another_local_expr,
									     formal_param_exprs,
									     actual_param_exprs,
									     param_count,
									     NULL
									   );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)
		    // }// end of if(func_local_ending_expr)
		}
		else
		{
	    #endif
		    another_local_expr = NULL;

		    // CJMP false-case eip == real false
		    branch_expr = vc_andExpr( HHui_VC,
				              *path_Expr,
					      predicate_expr
				            );

		    *path_Expr = vc_andExpr( HHui_VC,  
			        	     *path_Expr,
					     vc_notExpr( HHui_VC,
					                 predicate_expr
					               )
				           );	
	        #ifdef H_DEBUG_TEST
 		    predicate_change( HHui_VC,
				      vc_notExpr( HHui_VC,
					          predicate_expr
					        ),
				      tmp_expr,
		      		      *path_Expr
		     		    );
		#endif
	    
	    #ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)

	    #endif
		// indicating IR-false is taken
		ir_true_or_false = 0;

	    }// end of if(tbranch)

	}// end of if(H_predicate == 0)


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
/*
	int count1 = 0;
	HExpr * stp_vars1 = obtaint_stp_vars_array(&count1);

	vc_push(HHui_VC);
	int hqres1 = vc_query( HHui_VC,
			       vc_notExpr( HHui_VC,
					   *path_Expr
				         )
			     );
	
	HWholeCounterExample hswc1 = vc_getWholeCounterExample(HHui_VC);
	HExpr data1 = vc_getTermFromCounterExample( HHui_VC,
					      	    stp_vars1[0],
						    hswc1
				    		  );
	vc_pop(HHui_VC);

	term_printf( "[0] = 0x%x satisfying predicate !\n",
		     getBVInt(data1)
		   );
	free(stp_vars1);
*/
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
			
			

/* ++++++++++++++++++++++ HHui REP optimization ++++++++++++++++++++++ */
#ifdef H_SYMEXE_REP_OPTIMIZE
if(isREP == 0)
{
#endif
	// SAT tests for the other possible path-expr
	/* -------------------------------------------------------------------------------- */
	vc_push(HHui_VC);
/*
	HExpr temp_branch = vc_notExpr( HHui_VC,
				        branch_expr
				      );
	HType branch_tp = vc_getType( HHui_VC,
				      temp_branch
				    );
*/
	/*
	str_branch_type = typeString(branch_tp);

	term_printf( "branching type is %s\n",
		     str_branch_type
		   );
	free(str_branch_type);
	*/
/*
	str_branch_type = exprString(branch_expr);
        term_printf(str_branch_type);
	free(str_branch_type);
 */

	/*
	term_printf( "querying for expression : %s\n",
		     exprString(temp_branch)
		   );
	*/


	// checks for formula's validity
	if( (another_local_expr != NULL) &&
	    (func_local_ending_expr != NULL)
	  )
	{	    	    
	    is_SAT = vc_query( HHui_VC,
		  	       vc_notExpr( HHui_VC,
					   vc_andExpr( HHui_VC,
						       branch_expr,
						       func_local_ending_expr // another_local_expr
						     )
					 )
			     );
	}
	else
	{
	    is_SAT = vc_query( HHui_VC,
			       vc_notExpr( HHui_VC,
					   branch_expr
					 )
			     );
	}// end of if(another_local_expr)

	vc_pop(HHui_VC);
		  
	if(is_SAT != 2) // Error!
	{
	    if(is_SAT == 0) // is INVALID (what I really care about as Existence is sure !)
	    {
		// term_printf("my another branch would be added here !\n");
			// calculate the concrete value for predicate
		if(H_predicate == 0)
	   	{
		// real false branch !
		    ir_true_real_fbranch_addr = tbranch;
		    term_printf( "\nreal true branch queued ! --- addr is 0x%x\n",
				 tbranch
			       );
		}
		else
		{
		    ir_true_real_fbranch_addr = fbranch;
		    term_printf( "\nreal false branch queued ! --- addr is 0x%x\n",
				 fbranch
			       );
		}// end of if( )

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		// state saving --- both symbolic and concrete !
		if( (func_precondition_expr == NULL) ||
		    (*func_precondition_expr == NULL)
		  )
		{
#endif
		    add_HVM_state_entry( NULL,  		   // function's local constraint formula by actual params
					 NULL,			   // function's local constraint formula by formal params
					 branch_expr, 	           // constraint formula for this branch
		          	         ir_true_real_fbranch_addr // first instruction's VA in this branch
		      		       );



#ifdef HHUI_FUNC_SUMMARY_ENABLED
		}
		else
		{
		    cond_entry		      = expr_cond_branch_save(my_interface.cur_func_summ_entry);
		    cond_entry->pre_condition = another_local_expr;

		    add_HVM_state_entry( func_local_ending_expr,   // function's local constraint formula by actual params
					 cond_entry,		   // function's local constraint formula by formal params
					 branch_expr, 	           // constraint formula for this branch
		          	         ir_true_real_fbranch_addr // first instruction's VA in this branch
		      		       );

		    // h_condition_entry_t * expr_cond_branch_save(function_summary_entry_t * func_entry);
		}
#endif
	   }// end of if( )			    	   
	}// end of if(is_SAT != 2)
	/* -------------------------------------------------------------------------------- */ 
	// SAT tests for the other possible path-expr

#ifdef H_SYMEXE_REP_OPTIMIZE
}// end of if(isREP)
#endif
/* ++++++++++++++++++++++ HHui REP optimization ++++++++++++++++++++++ */



    }// end of if(pred_expr)


    return ir_true_or_false;
}// end of branch_save_ir_true( )






int branch_save_ir_false( HVC      HHui_VC,
			  HExpr *  path_Expr,       // IN-OUT
			  HExpr    predicate_expr,
			  int      H_predicate,

			  uint32_t tbranch,
			  uint32_t fbranch,	   

			  uint32_t ir_false_real_tbranch_addr 	   // calculated IR false branch !		 
		       )
{
    h_condition_entry_t * cond_entry = NULL;

    HExpr another_local_expr = NULL;
    HExpr branch_expr	     = NULL;
    int	  is_SAT      = 0;

    int   ir_true_or_false = 0;

    HExpr * formal_param_exprs = NULL;
    HExpr * actual_param_exprs = NULL;
    int     param_count	       = 0;	

#ifdef H_DEBUG_TEST
    HExpr tmp_expr = *path_Expr;
#endif

    func_local_ending_expr = NULL;

    if(predicate_expr != NULL)
    {
	term_printf( "\nH_predicate = %d\n",
		     H_predicate
		   );

	if(H_predicate == 0)
	{
	    // really takes false branch !
	    if(tbranch == ir_false_real_tbranch_addr)
	    {

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		// local function-precondition	
		if( (func_precondition_expr != NULL) && 
		    (*func_precondition_expr != NULL)
		  )
		{
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
			 		      *func_precondition_expr,
				              vc_notExpr( HHui_VC,
					                  predicate_expr
					                )
			                    );
		    */
		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
			 		      	     *func_precondition_expr,
				                     vc_notExpr( HHui_VC,
					                         predicate_expr
					                       )
			                           );

		    // current global path
		    branch_expr = *path_Expr;

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          predicate_expr
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			    func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			     another_local_expr,
									     formal_param_exprs,
									     actual_param_exprs,
									     param_count,
									     NULL
									   );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)
		    // }// end of if(func_local_ending_expr)
		}
		else
		{
#endif
		    another_local_expr = NULL;

		    // CJMP false-case eip == real true
		    branch_expr = vc_andExpr( HHui_VC,
			 		      *path_Expr,
				              vc_notExpr( HHui_VC,
					                  predicate_expr
					                )
			                    );

		    *path_Expr = vc_andExpr( HHui_VC,  
			   	    	     *path_Expr,
					     predicate_expr
				           );
	        #ifdef H_DEBUG_TEST
 		    predicate_change( HHui_VC,
				      predicate_expr,
				      tmp_expr,
		      		      *path_Expr
		     		    );
		#endif

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)
#endif

		// indicating IR-true is taken
		ir_true_or_false = 1;
	    }
	    else
	    {

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		// local function-precondition
		if( (func_precondition_expr != NULL) &&
		    (*func_precondition_expr != NULL)
		  )
		{
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
			 		      *func_precondition_expr,
					      predicate_expr
				            );
		    */

		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
			 		      	     *func_precondition_expr,
					     	     predicate_expr
				                   );
		    // current global path
		    branch_expr = *path_Expr;

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          vc_notExpr( HHui_VC,
								      predicate_expr
								    )
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			    func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			     another_local_expr,
									     formal_param_exprs,
									     actual_param_exprs,
									     param_count,
									     NULL
									   );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)
		    // }// end of if(func_local_ending_expr)
		}
		else
		{
#endif
		    another_local_expr = NULL;
		    
		    branch_expr = vc_andExpr( HHui_VC,
			 		      *path_Expr,						          
					      predicate_expr
				            );

	            // CJMP false-case eip == real false
		    *path_Expr = vc_andExpr( HHui_VC,  
			      	    	     *path_Expr,
					     vc_notExpr( HHui_VC,
					                 predicate_expr
					               )
				           );
	        #ifdef H_DEBUG_TEST
 		    predicate_change( HHui_VC,
				      vc_notExpr( HHui_VC,
					          predicate_expr
					        ),
				      tmp_expr,
		      		      *path_Expr
		     		    );
		#endif

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)
#endif
		// indicating IR-true is taken
		ir_true_or_false = 0;

	    }// end of if( )
	}
	else
	{
	    // really takes true branch !
	    if(fbranch == ir_false_real_tbranch_addr)
	    {

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		// local function-precondition
		if( (func_precondition_expr != NULL) &&
		    (*func_precondition_expr != NULL)
		  )
		{
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
				              *func_precondition_expr,
				              vc_notExpr( HHui_VC,
					                  predicate_expr  
					                )
				            );
		    */

		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
				              	     *func_precondition_expr,
				             	     vc_notExpr( HHui_VC,
					            	         predicate_expr  
					                       )
				            	   );
		
		    // current global path
		    branch_expr = *path_Expr;

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          predicate_expr
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			    func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			     another_local_expr,
									     formal_param_exprs,
									     actual_param_exprs,
									     param_count,
									     NULL
									   );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)
		    // }// end of if(func_local_ending_expr)
		}
		else
		{
#endif
		    another_local_expr = NULL;

		    // CJMP true-case eip == real true		  
		    branch_expr = vc_andExpr( HHui_VC,
				              *path_Expr,
				              vc_notExpr( HHui_VC,
					                  predicate_expr  
					                )
				            );

		    *path_Expr = vc_andExpr( HHui_VC,  
			        	     *path_Expr,
					     predicate_expr
				           );
	        #ifdef H_DEBUG_TEST
 		    predicate_change( HHui_VC,
				      predicate_expr,
				      tmp_expr,
		      		      *path_Expr
		     		    );
		#endif

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)
#endif
	    }
	    else
	    {
#ifdef HHUI_FUNC_SUMMARY_ENABLED
		// local function-precondition
		if( (func_precondition_expr != NULL) &&
		    (*func_precondition_expr != NULL)
		  )
		{
		    /*
		    branch_expr = vc_andExpr( HHui_VC,
				              *func_precondition_expr, 
					      predicate_expr
				            );
		    */

		    // another local path
		    another_local_expr = vc_andExpr( HHui_VC,
				              	     *func_precondition_expr, 
					      	     predicate_expr
				            	   );

		    // current global path
		    branch_expr = *path_Expr;

		    // current local path expressed through function's formal parametres !
		    *func_precondition_expr = vc_andExpr( HHui_VC,
						          *func_precondition_expr,
						          vc_notExpr( HHui_VC,
								      predicate_expr
								    )
						        );

		    // current local path expressed through function's actual parametres !
		    // if(func_local_ending_expr != NULL)
		    // {
    			param_count = H_build_formal_actual_expr_correspondence( my_interface.cur_func_summ_entry,
					          				 &formal_param_exprs,
					           				 &actual_param_exprs			 
					        			       );
			if(param_count != 0)
			{			    
			    func_local_ending_expr = H_var_substitute_4expr( HHui_VC,
						 			     another_local_expr,
									     formal_param_exprs,
									     actual_param_exprs,
									     param_count,
									     NULL
								  	   );
			}
			else
			{
			    func_local_ending_expr = NULL;
			}// end of if(param_count)

			if(formal_param_exprs != NULL)
			{
			    free(formal_param_exprs);
			}// end of if(formal_param_exprs)
			
			if(actual_param_exprs != NULL)
			{
			    free(actual_param_exprs);
			}// end of if(actual_param_exprs)
		    // }// end of if(func_local_ending_expr)
		}
		else
		{
#endif
		    another_local_expr = NULL;

		    // CJMP false-case eip == real true
		    branch_expr = vc_andExpr( HHui_VC,
				              *path_Expr,						          
					      predicate_expr
				            );

		    *path_Expr = vc_andExpr( HHui_VC,  
			        	     *path_Expr,
					     vc_notExpr( HHui_VC,
					                 predicate_expr
					               )
				           );
	        #ifdef H_DEBUG_TEST
 		    predicate_change( HHui_VC,
				      vc_notExpr( HHui_VC,
					          predicate_expr
					        ),
				      tmp_expr,
		      		      *path_Expr
		     		    );
		#endif

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		}// end of if(func_precondition_expr)
#endif
	    }// end of if( )

	}// end of if( )

			
			
/* ++++++++++++++++++++++ HHui REP optimization ++++++++++++++++++++++ */
#ifdef H_SYMEXE_REP_OPTIMIZE
if(isREP == 0)
{
#endif
	// SAT tests for the other possible path-expr
	/* -------------------------------------------------------------------------------- */
	vc_push(HHui_VC);

	// checks for formula's validity
	if( (another_local_expr != NULL) &&
	    (func_local_ending_expr != NULL)
	  )
	{
	    is_SAT = vc_query( HHui_VC,
			       vc_notExpr( HHui_VC,
				           vc_andExpr( HHui_VC,
					  	       branch_expr,
						       // another_local_expr
						       func_local_ending_expr
						     )
				         )
			     );
	}
	else
	{
	    is_SAT = vc_query( HHui_VC,
			       vc_notExpr( HHui_VC,
			  		   branch_expr
					 )
			     );
	}// end of if(another_local_expr)

	vc_pop(HHui_VC);
		  
	if(is_SAT != 2) // Error!
	{
	    if(is_SAT == 0) // is INVALID (what I really care about as Existence is sure !)
	    {
		// term_printf("my another branch would be added here !\n");
			// calculate the concrete value for predicate
		if(H_predicate == 0)
	   	{
		// real false branch !
		    ir_false_real_tbranch_addr = tbranch;
		    term_printf( "\nreal true branch queued ! --- addr is 0x%x\n",
				 tbranch
			       );
		}
		else
		{
		    ir_false_real_tbranch_addr = fbranch;
		    term_printf( "\nreal false branch queued ! --- addr is 0x%x\n",
				 fbranch
			       );
		}// end of if( )

#ifdef HHUI_FUNC_SUMMARY_ENABLED
		// state saving --- both symbolic and concrete !
		if( (func_precondition_expr == NULL) ||
		    (*func_precondition_expr == NULL)
		  )
		{
#endif
		    add_HVM_state_entry( NULL,			    // function's local path constraint
					 NULL,
					 branch_expr, 		    // constraint formula for this branch
		           	         ir_false_real_tbranch_addr // first instruction's VA in this branch
		      		       );
#ifdef HHUI_FUNC_SUMMARY_ENABLED
		}
		else
		{
		    cond_entry		      = expr_cond_branch_save(my_interface.cur_func_summ_entry);
		    cond_entry->pre_condition = another_local_expr;

		    if(func_local_ending_expr != NULL)
		    {
		        add_HVM_state_entry( func_local_ending_expr,    // function's local path constraint
					     cond_entry,
					     branch_expr, 		// constraint formula for this branch
		           	             ir_false_real_tbranch_addr // first instruction's VA in this branch
		      		           );
		    }
		    else
		    {
		        add_HVM_state_entry( NULL,			// function's local path constraint
					     cond_entry,
					     branch_expr, 		// constraint formula for this branch
		           	             ir_false_real_tbranch_addr // first instruction's VA in this branch
		      		           );			
		    }// end of if(func_local_ending_expr)
		}// end of if(func_precondition_expr)
#endif
	   }// end of if( )			    
	   

	}// end of if( )
	/* -------------------------------------------------------------------------------- */ 
	// SAT tests for the other possible path-expr

#ifdef H_SYMEXE_REP_OPTIMIZE
}// end of if(isREP)
#endif
    }// end of if(pred_expr)

    return ir_true_or_false;

}// end of branch_save_ir_false( )

