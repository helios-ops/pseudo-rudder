#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "hc_interface.h"
#include "stp_variables.h"

#include "H_test_config.h"

/* 
    ( x == a ) --> ( f(x) == y )

    x is taint-variable, y is result variable
 */





// static HExpr pred_expr;


/* update all related CPU states according to the STP SYM-machine's states regarding to each taint-unit

   Return : 1 --- OK
	    0 --- NOT ALL RIGHT
 */
/*
int update_SYMVM_with_stp_cons( HVC   hvc,
				HExpr path_expr
			      )
{
    int     x_count = 0;

    HExpr * x_exprs = obtaint_stp_vars_array(&x_count);
    if(x_exprs == NULL)
    {
	return 0;
    }// end of if( )


    if( predicate_form_build( hvc,
			      path_expr,
			      x_exprs,    // total unit-var-exprs			   
			      x_count
			    )
      )
    {
	for(int )	


	return 1;	
    }// end of if( )
    
    return 0;

}// end of update_SYMVM_with_stp_cons( )
*/


int predicate_form_build(  HVC	      hvc,
			   HExpr      path_expr,
			   HExpr    * x_exprs,    // total unit-var-exprs
			   // uint32_t * x_con_vals, // a group of con-values for taint-variables
			   int	      x_count,
			   HExpr *    pred_expr
			 )
{

    HExpr x_con_expr  = NULL;
    HExpr x_term_expr = NULL;

    HExpr    temp_expr  = NULL;

    uint32_t * x_temp_vals  = NULL;

    // HExpr    * x_temp_exprs = NULL;
    char * tmp_str1 = NULL;
    char * tmp_str2 = NULL;

    HWholeCounterExample wce = NULL;
    int qres  = 0;
    
    int count = 0;

    x_temp_vals = (uint32_t)malloc(sizeof(uint32_t) * x_count);
    if(x_temp_vals == NULL)
    {
	return 0;
    }// end of if( )


    /* ===================================================================================================== */
    vc_push(hvc);

    temp_expr = vc_notExpr( hvc,
			    path_expr
			  );

    qres = vc_query( hvc,
		     temp_expr				 
		   );

    term_printf( "vc_query_result is %d\n",
		 qres
	       );

    // 0 means the query is INVALID, which is what I really care about !
    if(qres != 0)
    {
	vc_pop(hvc);
	return 0;
    }// end of if( )


    wce = vc_getWholeCounterExample(hvc);

    int i = 0;
    
    for(i=0; i<x_count; i=i+1)
    {	
	x_con_expr = vc_getTermFromCounterExample( hvc,
						   x_exprs[i],
						   wce
					         );	

	// sym-expr
	tmp_str1 = exprString(x_exprs[i]);
	term_printf( "obtaint for variable %d ----- x_expr is %s ----- ",
		     i,
		     tmp_str1
		   );
	free(tmp_str1);

	// con-expr
	tmp_str2 = exprString(x_con_expr);
	term_printf( "value expr is %s, ",
		     tmp_str2
		   );
	free(tmp_str2);
		
	x_temp_vals[i] = getBVUnsigned(x_con_expr);

	term_printf( "value is %d\n",
		     x_temp_vals[i]
		   );

	/*
	term_printf( "obtaint for variable %d ----- expr is %s, value is %d\n",
		     i,
		     exprString(x_con_expr),
		     x_temp_vals[i]
		   );
	*/

	// vc_BVUnsigned(x_con_expr);

	// ( x == a )
   	/*
	x_term_expr = vc_eqExpr( hvc,
				 x_exprs[i],
				 x_con_expr
			       );

	pred_expr   = vc_andExpr( hvc,
				  pred_expr,
				  x_term_expr
			        );
	*/
    }// end of for{ }
    
    vc_pop(hvc);
    /* ===================================================================================================== */




    // Build the desired predicate under our previous STP-context !
    *pred_expr = vc_trueExpr(hvc);

    for(i=0; i<x_count; i=i+1)
    {	
	// currently the taint-unit is 1 byte long !
	x_con_expr  = vc_bvConstExprFromInt( hvc,
					     8,
					     x_temp_vals[i]
					   );
	/*
	term_printf( "vc_bvConstExprFromInt( ) --- for con-value 0x%x\n",
		     x_temp_vals[i]
		   );
	*/

	x_term_expr = vc_eqExpr( hvc,
				 x_exprs[i],
				 x_con_expr
			       );
	/*
	term_printf( "vc_bvEQ( )\n",
		     x_temp_vals[i]
		   );
	*/

	*pred_expr = vc_andExpr( hvc,
				 *pred_expr,
				 x_term_expr
			       );
	
    }// end of for{ }


    // vc_DeleteExpr(temp_expr);

    // vc_pop(hvc);
    /* ----------------------------------------------------------------------------------- */


    free(x_temp_vals);

    return 1;

}// end of predicate_form_build( )


static int y_id = 0;

uint32_t stp_formula_solve( HVC	  hvc,				
			    HExpr formula_expr,
			    HType form_type,
			    HExpr pred_expr
			  )
{
    int      qresult = 0;
    uint32_t q_c_res = 0;

    HExpr  expr    = NULL;
    HExpr  expr1   = NULL;
    HExpr  expr2   = NULL;

    /*
    term_printf( "stp_formula_solve( ) ----- dst_expr is %s, ", 
		 exprString(formula_expr)
	       );

    term_printf( "pred_expr is %s\n",
		 exprString(pred_expr)		 
	       );
    */

    /*
    HType  form_type = vc_getType( hvc,
				   formula_expr
				 );


    term_printf( "stp_formula_solve( ) ---- vc_getType( ) called !"
	       );
    */

    HWholeCounterExample wce = NULL;

    uint32_t y_value   = 0;

    y_id = y_id + 1;

    char     y_name[1000] ;
    int	     y_name_len = sprintf( y_name,
				   "y_%d\n",
				   y_id 
				 );
    y_name[y_name_len] = (char)0;

    HExpr    y_expr    = vc_varExpr( hvc,
				     y_name,
				     form_type
				   );

    /*
    term_printf( "introducing y_expr : %s",
		 exprString(y_expr)
	       );
    */

    // ( f(x) == y )
    HExpr post_expr = vc_eqExpr( hvc,
				 formula_expr,
				 y_expr
			       );

    /*
    term_printf( "introducing equal : %s",
		 exprString(post_expr)
	       );
    */
   

    /*
    expr  = vc_iffExpr( hvc,
			pred_expr,
			post_expr
		      );

    term_printf( "introducing iff : %s",
		 exprString(expr)
	       );

    expr1 = vc_notExpr( hvc,
			expr
		      );
    */

    expr = vc_notExpr( hvc,
		       post_expr
		     );

    /* -------------------------------------------------------------------------------------------- */
    vc_push(hvc);

    vc_assertFormula( hvc,
		      pred_expr
		    );
    
    
    qresult = vc_query( hvc,
	      		expr
	    	      );

    // Invalid query !
    if( qresult != 0 )
    {
	vc_pop(hvc);
	// term_printf( "HHui failed query !\n");

	return -1;
    }// end of if( )

    // term_printf("query finished !\n");

    wce = vc_getWholeCounterExample(hvc);

    expr2   = vc_getTermFromCounterExample( hvc,
				    	    y_expr,
					    wce
				  	  );	
    q_c_res = getBVInt(expr2);

    

    // vc_DeleteExpr(expr1);
    vc_DeleteExpr(expr2);

    vc_DeleteExpr(expr);   
    vc_DeleteExpr(y_expr);

    vc_pop(hvc);
    /* -------------------------------------------------------------------------------------------- */


    return q_c_res;

}// end of stp_formula_solve( )


uint32_t pred_stp_formula_solve( HVC   hvc,				
			    	 HExpr formula_expr,
				 HExpr pred_expr
			       )
{
    int      qresult = 0;
    uint32_t q_c_res = 0;

    HExpr  expr    = NULL;
    HExpr  expr1   = NULL;
    HExpr  expr2   = NULL;
    HExpr  expr3   = NULL;

    HType  exptype  = vc_getType( hvc,
				  formula_expr
				);

    char * str_type = typeString(exptype);
     
    HWholeCounterExample wce = NULL;
    uint8_t isBool = 0;


    uint32_t y_value   = 0;


    char     y_name[1000] ;
    int	     y_name_len = 0;

    HType    form_type = NULL;

    HExpr    y_expr    = NULL;

    /*
    term_printf( "pred_stp_formula_solve( ) ----- dst_expr is %s, type is %s", 
		 exprString(formula_expr),
		 typeString( vc_getType( hvc, 
					 formula_expr
				       ) 
			   )
	       );
    
    term_printf( "pred_expr is %s\n",
		 exprString(pred_expr)		 
	       );
    */

    if( strcmp(str_type, "BOOLEAN ") != 0)
    {
/*
	y_id = y_id + 1;
	y_name_len = sprintf( y_name,
			      "y_%d\n",
			      y_id 
			    );
        y_name[y_name_len] = (char)0;

	form_type = vc_bvType( hvc,
			       1
			     );
	y_expr    = vc_varExpr( hvc,
			        y_name,
				form_type
			      );


	formula_expr = vc_eqExpr( hvc,
				  formula_expr,
				  y_expr
				);

	formula_expr = vc_notExpr( hvc,
			  	   formula_expr
			         );

	vc_push(hvc);
        vc_assertFormula( hvc,
		          pred_expr
		        );

	qresult = vc_query( hvc,
			    formula_expr
			  );

	if(qresult == 0)
	{
	    wce   = vc_getWholeCounterExample(hvc);
	    expr3 = vc_getTermFromCounterExample( hvc,
				   	 	  y_expr, //formula_expr,
					   	  wce
				  	 	);	    
	    qresult = getBVInt(expr3);
	}// end of if( )

	term_printf("bbbb\n");
*/


/*
	else
	{
	    qresult = 0;
	}// end of if( )
 */	
        
    }
    else
    {
	vc_push(hvc);
        vc_assertFormula( hvc,
		          pred_expr
		        );

	qresult = vc_query( hvc,
			    formula_expr
			  );

	// term_printf("aaaa\n");

	if(qresult != 1)	
	{
	    qresult = 0;	    
	}// end of if( )

	vc_pop(hvc);
    }// end of if( )




    return qresult;


/*
    term_printf( "pred_stp_formula_solve( ) ----- dst_expr is %s, type is %s", 
		 exprString(formula_expr),
		 typeString( vc_getType( hvc, 
					 formula_expr
				       ) 
			   )
	       );

    term_printf( "pred_expr is %s\n",
		 exprString(pred_expr)		 
	       );

*/
    /* ------------------------------------------------------------------------------ */
/*
    uint32_t y_value   = 0;

    y_id = y_id + 1;

    char     y_name[1000] ;
    int	     y_name_len = sprintf( y_name,
				   "y_%d\n",
				   y_id 
				 );
    y_name[y_name_len] = (char)0;


    HType    form_type = vc_bvType( hvc,
				    1
				  );

    HExpr    y_expr    = vc_varExpr( hvc,
				     y_name,
				     form_type
				   );
*/
    /* ------------------------------------------------------------------------------ */




    /* -------------------------------------------------------------------------------------------- */

    
    


/*
    expr1 = vc_boolToBVExpr( hvc,
			     formula_expr
			   );

    expr2 = vc_eqExpr( hvc,
		       y_expr,
		       expr1
		     );

    expr  = vc_notExpr( hvc,
			expr2
		      );

    term_printf( "querying for expr : %s\n",
		 exprString(expr)
	       );

    qresult = vc_query( hvc,
	      		expr
	    	      );

    // Invalid query !
    if( qresult != 0 )
    {
	vc_pop(hvc);

	term_printf( "HHui failed query !\n");

	return;
    }// end of if( )

    term_printf("query finished !\n");

    wce = vc_getWholeCounterExample(hvc);

    expr3   = vc_getTermFromCounterExample( hvc,
				    	    y_expr, //formula_expr,
					    wce
				  	  );	

    q_c_res = getBVInt(expr3);

    

    // vc_DeleteExpr(expr1);
    vc_DeleteExpr(expr3);
    vc_DeleteExpr(expr2);
    vc_DeleteExpr(expr1);

    vc_DeleteExpr(expr);   
    vc_DeleteExpr(y_expr);

*/
/*
    if(strcmp(str_type, "BOOLEAN ") == 0)
    {
 */


/*
        expr = vc_notExpr( hvc,
			   formula_expr
		         );
*/
 	
/*
	term_printf( "simplified expr is %s\n",
		     exprString(expr)
		   );

        isBool = vc_isBool(expr);    
 
        if(isBool == 1)
        {
            // true expression !
	    q_c_res = 1;
        }
        else if(isBool == 0)
        {
        // false expression !
	    q_c_res = 0;
        }
        else
        {
	    q_c_res = -1;
  	    term_printf("unsolved bool expr !\n");
        }// end of if( )
 */  
        // vc_DeleteExpr(expr);
/*
    }// end of if( )
*/
    // vc_pop(hvc);
    /* -------------------------------------------------------------------------------------------- */


    // return q_c_res;

}// end of pred_stp_formula_solve( )


/*
	expr1 = vc_bvConstExprFromInt( hvc,
				       1,
				       0
				     );

	formula_expr = vc_bvAndExpr( hvc,
				     formula_expr,
				     formula_expr
				   );
	formula_expr = vc_eqExpr( hvc,
				  formula_expr,
				  expr1
				);
*/


/*
	formula_expr = vc_bvBoolExtract( hvc,
					 formula_expr,
					 0
				       );
 */
	
