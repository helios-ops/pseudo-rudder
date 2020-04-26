/*
Vine is Copyright (C) 2006-2009, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU GPL,
version 2 or later, but it is made available WITHOUT ANY WARRANTY.
See the top-level README file for more details.

For more information about Vine and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include "stmt.h"
#include "debug.h"
#include <iostream>
#include <fstream>
#include <assert.h>

// #include <ctypes.h>
#include <inttypes.h>

#include "H_taint_record.h"

#include "GetTemuData.h"

//#include "hc_interface.h"
#include "H_STP_stub.h"

#include "SymExe.h"

#include "sym_addr_resolve.h"
#include "record2file.h"

#include "H_vulscan_config.h"

#include "HH_IR_translate_config.h"
	  


// switches for several vulnerability scanning policies.
/* ======================================================================= */
extern int * H_vulscan_once_enough_err_found;
/* ======================================================================= */

extern uint32_t HHui_insn_addr;

using namespace std;

Stmt *
Stmt::clone(Stmt *s)
{
  return s->clone();
}

void Stmt::destroy( Stmt *s )
{
    Move    *move       = NULL;
    Jmp     *jmp        = NULL;
    CJmp    *cjmp       = NULL;
    ExpStmt *expstmt    = NULL;
    Call    *call       = NULL;
    Return  *ret        = NULL;
    Func    *fun        = NULL;
    
    switch ( s->stmt_type )
    {
    case MOVE:    
      move = (Move *)s;
      Exp::destroy(move->lhs);
      Exp::destroy(move->rhs);
      break;
    case JMP:
      jmp = (Jmp *)s;
      Exp::destroy(jmp->target);
      break;
    case CJMP:
      cjmp = (CJmp *)s;
      Exp::destroy(cjmp->cond);
      Exp::destroy(cjmp->t_target);
      Exp::destroy(cjmp->f_target);
      break;
    case EXPSTMT:
      expstmt = (ExpStmt *)s;
      Exp::destroy(expstmt->exp);
      break;
    case CALL:
      call = (Call*)s;
      if (call->lval_opt != NULL)
        Exp::destroy(call->lval_opt);
      for(vector<Exp*>::iterator
            i=call->params.begin(); i!=call->params.end(); i++)
        Exp::destroy(*i);
      break;
    case RETURN:
      ret = (Return*) s;
      if (ret->exp_opt != NULL)
        Exp::destroy(ret->exp_opt);
      break;
    case FUNCTION:
      fun = (Func*) s;
      for(vector<VarDecl*>::iterator
            i=fun->params.begin(); i!=fun->params.end(); i++)
        Stmt::destroy(*i);
      for(vector<Stmt*>::iterator
            i=fun->body.begin(); i!=fun->body.end(); i++)
        Stmt::destroy(*i);
      break;
    case COMMENT:
    case SPECIAL:
    case LABEL:
    case VARDECL:
      break;
    }    

    delete s;
}

VarDecl::VarDecl(string n, reg_t t, address_t asm_ad,
		address_t ir_ad) 
  : Stmt(VARDECL, asm_ad, ir_ad), name(n), typ(t)
{
	
}

VarDecl::VarDecl(const VarDecl &other) : 
  Stmt(VARDECL, other.asm_address, other.ir_address), 
  name(other.name), typ(other.typ)
{
	
}

VarDecl::VarDecl(Temp *t) : Stmt(VARDECL, 0x0, 0x0),
			    name(t->name),
			    typ(t->typ)
{
	
}



// HHui added for temp storage of concrete values of the i386-registers
/* --------------------------------------------------------------------------------------------------- */
VarDecl::VarDecl( string  myname, 
		  int     myvar_type,    /* 0 --- general reg; 1 --- EFLAG bit; 2 --- temp variable */
		  reg_t   mytype,
	  	  int	  myreg_idx,
	   	  int 	  myreg_offset,
		  int	  myreg_size
	 	) : Stmt(VARDECL, 0x0, 0x0), name(myname), typ(mytype)
{
    var_type   = myvar_type;

    reg_idx    = myreg_idx;
    reg_offset = myreg_offset;
    reg_size   = myreg_size;

}// end of VarDecl( )
/* --------------------------------------------------------------------------------------------------- */


void VarDecl::concrete_read( char * buf, 
			     int    size 
			   )
{
    if(var_type == 0)
    {
	
	// general registers
	
	
    }// end of if( )


}// end of concrete_read( )


void VarDecl::symbolic_write( HVC hvc, 
			      HExpr expr 
			    )
{
    
}// end of symbolic_write( )




string 
VarDecl::tostring()
{
  string ret = "var " + name + ":" + Exp::string_type(this->typ) + ";";
  return ret;
}

VarDecl *
VarDecl::clone() const
{
  return new VarDecl(*this);
}



// MOVE
/* ========================================================================= */
/*
	class Move : public Stmt 
	{
		 public:
		  Move(Exp *l, Exp *r, address_t asm_ad = 0x0, address_t ir_ad = 0x0);
		  Move(const Move &other);
		  virtual ~Move() { };
		  virtual void accept(IRVisitor *v) { v->visitMove(this); };
		  virtual string tostring();
		  virtual Move *clone() const;

		  Exp *lhs;
		  Exp *rhs;

			  ................
	};
  */
int Move::symexe( HVC   hvc,
		  HExpr path_expr
		)
{
	/*
		virtual void L_value_calculate( HVC    hvc, char *  value )= 0;
		virtual void R_value_calculate( HVC    hvc, char *  value) = 0;
     	  */
	  
	H_L_value    l_val;
	H_R_value    r_val;
	
	r_val.is_meta_sym_byte = 0;

	H_R_value * re_value;

	HExpr    symaddr_tmp_expr1 = NULL;
	HExpr    symaddr_tmp_expr2 = NULL;
	HExpr    symaddr_tmp_expr3 = NULL;
	uint32_t symaddr_tmp_concrete_value = 0;

        // HExpr    temp_expr = NULL;

	HExpr invalid_constraint_exprs[3] ;
        invalid_constraint_exprs[0] = NULL;
        invalid_constraint_exprs[1] = NULL;
	invalid_constraint_exprs[2] = NULL;

	/*
	HExpr illegal_constraint_exprs[2];
        illegal_constraint_exprs[0] = NULL;
        illegal_constraint_exprs[1] = NULL;
	*/

	HExpr	 * symaddr_correct_concrete_addrs_constraints = NULL;
	uint32_t * symaddr_correct_concrete_addrs_values      = NULL;
	int 	   symaddr_correct_concrete_addrs_count       = 0;

	int		  qresult      = 0;

        int		  index	       = 0;
	uint32_t	  taint_bitmap = 0;
	
	H_taint_record_t * records = NULL;
	int		 i_1 = 0;
	int		 i   = 0 ;

	int  low_bit   = 0;
	int  high_bit = 0;
		
        char * tmp_error_str = NULL;

	char * str_expr = NULL;

	HExpr  temp_expr = NULL;

	char * str_expr_type = NULL;
	HType  my_expr_type  = NULL;

	lhs->L_value_calculate( hvc, 
				(char *)&l_val
			      );
	
    	// Not interested !
	if(l_val.l_value_type == L_NONSENSE)
	{
		return -1;
	}// end of if( )
	/*
	else if(l_val.l_value_type == L_EFLAG_BIT)
	{			
		return -1;
	}
	*/
	

	rhs->R_value_calculate( hvc, 
				(char *)&r_val
			      );



// HHui Fixme : 暂时不考虑符号地址!


	if(r_val.r_value_type == R_CON_VALUE)
	{
	// 具体值的右值
		/*
		H_term_printf( "concrete r_value !, lval.l_val_type = ,"
			     );
		 */
		// 为左值计算相应的右值
		/* ============================================================ */
		switch(l_val.l_value_type)
		{
			case L_REG_INDEX:
			{
				/*
				H_term_printf( "%s\n", 
					       "register"
					     );
				 */

			//  通用寄存器
				index = l_val.l_value.reg_idx;
				// GetTEMUReg_AccessIDByIndex( int index )
				
				/*
				H_term_printf( "RegIndex %d as MOVE left value, right value is 0x%8x !\n", 
					       index,
					       ( r_val.r_value.value)
					     );

				 */

				// store into temp locations !
				SetConcreteRegData( index,
						    &( r_val.r_value.value)
						  );
				break;
			}
			case L_EFLAG_BIT:
			{
				/*
				H_term_printf( "%s\n", 
					       "EFLAG"
					     );
				 */
			// EFLAGS   寄存器标记位的索引
				index = l_val.l_value.eflag_bit_idx;

				// HHui decision : concrete values being right-value for EFLAGS would be ignored !
				
				SetConcreteEFLAGData( index,
						      ( r_val.r_value.value)
						    );
				
				break;
			}
			case L_MEM_ADDRESS:
			{
				/*
				H_term_printf( "%s\n", 
					       "MEMORY"
					     );
				 */

			// 内存地址操作数
				index = l_val.l_value.m_address;

				SetConcreteMemData( index, 
						    r_val.r_value_bits_size / 8,
						    &( r_val.r_value.value)
						  );
				break;
			}
/* -------------------------- SYMBOLIC ADDRESS HANDLING : HHui added at June 22nd, 2011 -------------------------- */
			case L_MEM_ADDRESS_SYM:
			{
				/*
				tmp_error_str = exprString(l_val.l_value.m_sym_address);
				str_expr      = exprString(*HHui_current_path_expr);
				H_term_printf( "symbolic mem-address ! --- %s, path expression --- %s \n",
					       tmp_error_str,
					       str_expr
					     );
				free(tmp_error_str);
				free(str_expr);
				*/
				qresult = hvc_symaddr_solve( hvc,    			     
							     HHui_current_path_expr,    // &path_expr
				      		             l_val.l_value.m_sym_address,
				       		             2, /* 1 -- read; 2 -- write; 4 -- execute */
				       			     invalid_constraint_exprs,  
							     // 2 elements' array holding ERRORs' constraints !
							     
						       	     &symaddr_correct_concrete_addrs_values,
							     &symaddr_correct_concrete_addrs_constraints,
						      	     &symaddr_correct_concrete_addrs_count
						     	   );

				if(qresult == 1)
				{
				    H_term_printf( "We've found an ERROR in the target program !\n");

				    // OUT-OF_RANGE expr !				
				    if(invalid_constraint_exprs[0] != NULL)
				    {
					/*
					tmp_error_str = exprString(invalid_constraint_exprs[0]);
					record_ERROR_2file( tmp_error_str,
							    0 // err_id
							  );
					free(tmp_error_str);
					 */
					temp_expr = vc_andExpr( hvc,
								*HHui_current_path_expr,
							 	invalid_constraint_exprs[0]
							      );
					record_ERROR_2file( temp_expr,
							    0 // err_id
							  );					
					vc_DeleteExpr(temp_expr);
				    }// end of if(invalid_constraint_exprs[0])

				    // INVALID-ACCESS expr !
				    if(invalid_constraint_exprs[1] != NULL)
				    {
					/*
					tmp_error_str = exprString(invalid_constraint_exprs[1]);
					record_ERROR_2file( tmp_error_str,
							    1 // err_id
							  );
					free(tmp_error_str);
					*/
					temp_expr = vc_andExpr( hvc,
								*HHui_current_path_expr,
							 	invalid_constraint_exprs[1]
							      );
					record_ERROR_2file( temp_expr,
							    1 // err_id
							  );					
					vc_DeleteExpr(temp_expr);
				    }// end of if(invalid_constraint_exprs[1])   

				    // stack-eip overwritten expr !
				    if(invalid_constraint_exprs[2] != NULL)
				    {
					/*
					tmp_error_str = exprString(invalid_constraint_exprs[2]);
					record_ERROR_2file( tmp_error_str,
							    2
							  );
					free(tmp_error_str);
					*/
					temp_expr = vc_andExpr( hvc,
								*HHui_current_path_expr,
							 	invalid_constraint_exprs[2]
							      );
					record_ERROR_2file( temp_expr,
							    2 // err_id
							  );					
					vc_DeleteExpr(temp_expr);
				    }// end of if(invalid_constraint_exprs[1])

				#ifdef H_VULSCAN_ONCE_ENOUGH
				    *H_vulscan_once_enough_err_found = 1;
				    return 0;				    
				#endif

				}// end of if(qresult == 1)

				    // concrete value to-be-written : this originally-destined R_value
				    symaddr_tmp_expr1 = vc_bvConstExprFromInt( hvc,
									       r_val.r_value_bits_size,
									       r_val.r_value.value
									     );

				    // WRITE : We would mark every possible m-addr unit as symbolic !
				    /* ----------------------------------------------------------------- */
				    if(symaddr_correct_concrete_addrs_count != 0)
				    {
					H_term_printf( "totally 0x%x possible concrete values for the SYM-ADDR --- ",
						       symaddr_correct_concrete_addrs_count
						     );

					for(i_1=0; i_1<symaddr_correct_concrete_addrs_count; i_1=i_1+1)
					{
					    // concrete value originally-existed
					    /*
					    GetConcreteMemData( symaddr_correct_concrete_addrs_values[i_1], 
								(r_val.r_value_bits_size / 8), 
								&symaddr_tmp_concrete_value
							      );
					    
					    H_term_printf( "Reading data[0x%x] at symbolic-address 0x%x\n",
							   symaddr_tmp_concrete_value,
							   symaddr_correct_concrete_addrs_values[i_1]
							 );					    
					    symaddr_tmp_expr2 = vc_bvConstExprFromInt( hvc,
										       r_val.r_value_bits_size,
										       symaddr_tmp_concrete_value
										     );
					    */
		    symaddr_tmp_expr2 = obtain_expr_from_TEMU_virtmem( symaddr_correct_concrete_addrs_values[i_1],
					     			       (r_val.r_value_bits_size / 8),
					     			       hvc
					   			     );

					    symaddr_tmp_expr3 = vc_iteExpr( hvc,
									    symaddr_correct_concrete_addrs_constraints[i_1],
									    symaddr_tmp_expr1, // then
									    symaddr_tmp_expr2  // else
									  );

					    records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t ) * 
									          r_val.r_value_bits_size / 8
					 			    		);	

					    for(i=0;  i<(r_val.r_value_bits_size / 8);  i=i+1)
					    {
						low_bit  = i * 8 ;
						high_bit = (i+1) * 8 - 1;
						
						( (H_taint_record_t *)( // (uint32_t)records + i * sizeof(H_taint_record_t) 
									records + i
							      	      ) 
						)->h_expr = vc_bvExtract( hvc,
									  symaddr_tmp_expr3,
								  	  high_bit,
								  	  low_bit
									); 					
					    }// end of for{i}
							
				  	    // bitmap : 1 bit per byte !
					    taint_bitmap = ( 1 << ( r_val.r_value_bits_size / 8 
							   	  ) 
					       		   ) - 1;

					    HH_Set_TemuMemByteTaintRecord( symaddr_correct_concrete_addrs_values[i_1],
								           (uint32_t)( (r_val.r_value_bits_size / 8) ), 
							       		   (uint64_t)taint_bitmap, 
							       		   records
							     		 );
					    /*
					    tmp_error_str = exprString(symaddr_tmp_expr3);
					    H_term_printf( "symbolic addressing WRITE finished --- addr[0x%x] --- size = %d, expr = %s!\n",
							   symaddr_correct_concrete_addrs_values[i_1],
							   (uint32_t)( (r_val.r_value_bits_size / 8) ),
							   tmp_error_str
							 );
					    free(tmp_error_str);
					    */

					}// end of for{i_1}

					if(symaddr_correct_concrete_addrs_values != NULL)
					{
					    free(symaddr_correct_concrete_addrs_values);
					}// end of if( )
					    
					if(symaddr_correct_concrete_addrs_constraints != NULL)
					{
					    free(symaddr_correct_concrete_addrs_constraints);
					}// end of if( )

 				    }// end of if(symaddr_correct_concrete_addrs_count != 0)
				    /* ----------------------------------------------------------------- */

				break;
			}
/* --------------------------------------------------------------------------------------------------------------  */

			case L_TEMP:
			{
				/*
				H_term_printf( "%s\n", 
					       "TEMP"
					     );
				 */
			// 临时变量
				index = l_val.l_value.tmp_idx;
			
				re_value = GetVarDecl_ValueByIndex(index);
				

				if( index == 0 ) // R_CC_OP
				{
				    // str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_OP = %x ---- ", 
						   // str_expr
						   r_val.r_value.value
						 );
				    // free(str_expr);
				}
				else if( index == 1 ) // R_CC_DEP1
				{
				    // str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_DEP1 = %x ---- ", 
						   r_val.r_value.value // str_expr
						 );
				    // free(str_expr);
				}
				else if( index == 2 ) // R_CC_DEP2
				{		
				    // str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_DEP2 = %x ---- ", 
						   r_val.r_value.value // str_expr
						 );
				    // free(str_expr);
				}
				else if( index == 3 ) // R_CC_NDEP
				{
				    // str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_DEP = %x ---- ", 
						   r_val.r_value.value // str_expr
						 );
				    // free(str_expr);
				}// end of if(index)


				/*
				H_term_printf( "TempIndex %d as MOVE left value, right value is 0x%8x !\n", 
					       index,
					       ( r_val.r_value.value)
					     );
				 */

				( re_value->r_value ).value  = r_val.r_value.value;
				re_value->r_value_bits_size  = r_val.r_value_bits_size;
				re_value->r_value_type	     = R_CON_VALUE;
				
				
				break;
			}			
		}// end of switch{ }
		/* ============================================================ */
		// 为左值计算相应的右值
		
	}
	else if(r_val.r_value_type == R_SYM_EXPRESSION)
	{
	// 符号值的右值
		/*
		H_term_printf( "symbolic r_value ! ---- ,"
			     );
		*/
		/* ============================================================ */
		switch(l_val.l_value_type)
		{
			case L_REG_INDEX:
			{								
				index    = l_val.l_value.reg_idx;

				records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t ) * 
								      (l_val.l_value_bits_size / 8 )
					 			    );

				taint_bitmap = ( (1 << (r_val.r_value_bits_size / 8)
						 ) 
					       ) - 1;
				
				// byte-wise tainting

				/* ================================================================================================ */
				/* =================== Tainting from a low-addr byte to high-addr byte ordering =================== */
				/* ================================================================================================ */
				/*	
				H_term_printf( "exprString( ) is 0x%x, records total size = %d * %d = %d \nleft_bits_num = %d, right_bits_num = %d\n",
						exprString,

					        sizeof(H_taint_record_t ),
						(l_val.l_value_bits_size / 8 ),
						sizeof(H_taint_record_t ) * (l_val.l_value_bits_size / 8 ),

						l_val.l_value_bits_size,
						r_val.r_value_bits_size

					     );
				
				
				*/

				/*
				H_term_printf( "original expression is %s\n",
					        exprString(r_val.r_value.expression)						
					     );
				*/

				for(i=0; i<(r_val.r_value_bits_size / 8); i=i+1)
				{
				// Expr vc_bvExtract(VC vc, Expr child, int high_bit_no, int low_bit_no); 
					low_bit  = i * 8 ;
					high_bit = (i + 1) * 8 - 1;
				
					/*
					H_term_printf( "records addr is 0x%x --- cur-structure's addr 0x%x for index %d\n",
						       records,
						       (uint32_t)records + i * sizeof(H_taint_record_t),
						       i
						     );
					*/

					( (H_taint_record_t *)( // (uint32_t)records + i * sizeof(H_taint_record_t)
								records + i 
							      ) 
					)->h_expr 
						 = vc_bvExtract( hvc, 					   								         r_val.r_value.expression,
								 high_bit,
								 low_bit
							       ); 


					/*
					H_term_printf( "indexing %d, expression is %s\n",
						       i,
						       exprString( ( (H_taint_record_t *)( (uint32_t)records + i * sizeof(H_taint_record_t) 
										         ) 
								   )->h_expr  
								 )
						     );
					
					*/
				}// end of for{ }

/*				
				H_term_printf("Register vc_bvConcatExpr( ) !\n");
H_term_printf( "original intergration is 0x%x(%s) --->(separate parts) sequential vitvectors' addresses are 0x%x(%s) -- [0], 0x%x(%s) -- [1], 0x%x(%s) -- [2], 0x%x(%s) -- [3]\n",
					       r_val.r_value.expression,
					       exprString(r_val.r_value.expression),

					       ( (H_taint_record_t *)records )->h_expr,
					       exprString( ( (H_taint_record_t *)records )->h_expr ),

					       ( (H_taint_record_t *)records + 1 )->h_expr,
					       exprString( ( (H_taint_record_t *)records + 1)->h_expr ),

					       ( (H_taint_record_t *)records + 2 )->h_expr,
					       exprString( ( (H_taint_record_t *)records + 2)->h_expr ),

					       ( (H_taint_record_t *)records + 3 )->h_expr,
					       exprString( ( (H_taint_record_t *)records + 3)->h_expr )
					     );				
*/				
				/*
				H_term_printf( "tainting reg --- R_count = %d , L_count = %d\n",
					       (r_val.r_value_bits_size / 8),
					       (l_val.l_value_bits_size / 8)	
					     );
				*/

				HH_symexe_taint_register( index,
							  (l_val.l_value_bits_size / 8),
						          records
						        );
				/*
				H_term_printf( "MOVE symbolic ! ---- register as left value with index = %d, offset = %d, size = %d, \nR_value size is %d\n",
					       (index / 4),
					       (index % 4),
					       (l_val.l_value_bits_size / 8),
					       (r_val.r_value_bits_size / 8)	
					     );
				 */

				/*
				HH_Set_TemuRegisterByteTaintRecord( index,	
								    taint_bitmap,	
								    records
				      				  );
				*/

				// Now taint the register !
				

				if(records != NULL)
				{
				    free(records);
				}// end of if( )
				
				
				break;
			}
			case L_EFLAG_BIT:
			{
				index    = l_val.l_value.eflag_bit_idx;

				records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t ) );

				taint_bitmap = ( 1 << r_val.r_value_bits_size ) - 1;
				
				my_expr_type  = vc_getType( hvc, 
							    r_val.r_value.expression
							  );
				str_expr_type = typeString(my_expr_type);
				
				if( strcmp( "BOOLEAN ", 
					    str_expr_type
					  ) 
				    != 0
				  )
				{
				    r_val.r_value.expression = vc_bvBoolExtract( hvc,
										 r_val.r_value.expression,
										 0
									       );
				    r_val.r_value.expression = vc_notExpr( hvc,
									   r_val.r_value.expression
									 );
				}// end of if( )

				/*
				vc_push(hvc);
				vc_query( hvc,
					  r_val.r_value.expression
					);
			        vc_pop(hvc);
				 */

				free(str_expr_type) ;

				( (H_taint_record_t *)records )->h_expr = r_val.r_value.expression;
				
				/*
				H_term_printf( "EFLAGS bit[%d] as left-value for SYM_EXPRESSION(addr : 0x%x )!\n",
						index,
						( (H_taint_record_t *)records )->h_expr
					     );
				 */

				// taint the corresponding EFLAGS bit with calculated symbolic-expression !
				HH_Set_TemuEFAGSTaintRecord( // GetEFLAGBitNameByIndex(index),
							     index,  // Now input the real index !
							     records
							   );
				free(records);
				
				break;
			}
			case L_MEM_ADDRESS:
			{
				index    = l_val.l_value.m_address;

/*
				H_term_printf( "left mem-val --- address = 0x%x, size = %d, sizeof(H_taint_record_t)=%d\n",
					 	index,
						(r_val.r_value_bits_size / 8),
						sizeof(H_taint_record_t)
					     );
*/

				records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t ) * 
								      r_val.r_value_bits_size / 8
					 			    );	

				for(i=0;  i<(r_val.r_value_bits_size / 8);  i=i+1)
				{
					low_bit  = i * 8 ;
					high_bit = (i+1) * 8 - 1;
						
					( (H_taint_record_t *)( // (uint32_t)records + i * sizeof(H_taint_record_t)
								records + i 
							      ) 
					)->h_expr = vc_bvExtract( hvc, 									  									  r_val.r_value.expression,
								  high_bit,
								  low_bit
								); 
					
				}// end of for{ }
							

				// bitmap : 1 bit per byte !
				taint_bitmap = ( 1 << ( r_val.r_value_bits_size / 8 
						      ) 
					       ) - 1;

				HH_Set_TemuMemByteTaintRecord( (uint32_t)index, 
							       (uint32_t)( (r_val.r_value_bits_size / 8) ), 
							       (uint64_t)taint_bitmap, 
							       records
							     );			

				/*
				H_term_printf("TemuMemByteTaintRecord( ) finished !\n")	;
				 */

				break;
			}
			case L_MEM_ADDRESS_SYM:
			{    
			// symbolic-memory-address WRITE
				/*
				tmp_error_str = exprString(l_val.l_value.m_sym_address);
				H_term_printf( "symbolic mem-address WRITE symbolic-expression : %s!\n",
					       tmp_error_str
					     );
				free(tmp_error_str);
				*/

				qresult = hvc_symaddr_solve( hvc,
				       			     HHui_current_path_expr,    // &path_expr,
				      		             l_val.l_value.m_sym_address,
				       		             2, /* 1 -- read; 2 -- write; 4 -- execute */
				       			     invalid_constraint_exprs,  // path-constraint AND illegal-constraint
							     // 2 elements' array holding ERRORs' constraints !
						       	     &symaddr_correct_concrete_addrs_values,
							     &symaddr_correct_concrete_addrs_constraints,
						      	     &symaddr_correct_concrete_addrs_count
						     	   );

				if(qresult == 1)
				{
				// We've found an ERROR !
				    H_term_printf( "We've found an ERROR in the target program !\n");

				    // OUT-OF_RANGE expr !
				    if(invalid_constraint_exprs[0] != NULL)
				    {
					/*
					tmp_error_str = exprString(invalid_constraint_exprs[0]);
					record_ERROR_2file( tmp_error_str,
							    0 // err_id
							  );
					free(tmp_error_str);
					*/
					temp_expr = vc_andExpr( hvc,
								*HHui_current_path_expr,
							 	invalid_constraint_exprs[0]
							      );
					record_ERROR_2file( temp_expr,
							    0 // err_id
							  );					
					vc_DeleteExpr(temp_expr);
				    }// end of if(invalid_constraint_exprs[0])

				    // INVALID-ACCESS expr !
				    if(invalid_constraint_exprs[1] != NULL)
				    {
					/*
					tmp_error_str = exprString(invalid_constraint_exprs[1]);
					record_ERROR_2file( tmp_error_str,
							    1 // err_id
							  );
					free(tmp_error_str);
					*/
					temp_expr = vc_andExpr( hvc,
								*HHui_current_path_expr,
							 	invalid_constraint_exprs[1]
							      );
					record_ERROR_2file( temp_expr,
							    1 // err_id
							  );					
					vc_DeleteExpr(temp_expr);
				    }// end of if(invalid_constraint_exprs[1])

				    // stack-eip overwritten expr !
				    if(invalid_constraint_exprs[2] != NULL)
				    {
					/*
					tmp_error_str = exprString(invalid_constraint_exprs[2]);
					record_ERROR_2file( tmp_error_str,
							    2 // err_id
							  );
					free(tmp_error_str);
					*/
					temp_expr = vc_andExpr( hvc,
								*HHui_current_path_expr,
							 	invalid_constraint_exprs[2]
							      );
					record_ERROR_2file( temp_expr,
							    2 // err_id
							  );					
					vc_DeleteExpr(temp_expr);
				    }// end of if(invalid_constraint_exprs[1])
		    
				#ifdef H_VULSCAN_ONCE_ENOUGH
				    *H_vulscan_once_enough_err_found = 1;
				    return 0;				    
				#endif
				}// end of if(qresult)

				    // symbolic expression to-be-written : this originally-destined R_value
				    symaddr_tmp_expr1 = r_val.r_value.expression;

				    // WRITE : We would mark every possible m-addr unit as symbolic !
				    /* ----------------------------------------------------------------- */
				    if(symaddr_correct_concrete_addrs_count != 0)
				    {
					H_term_printf( "totally 0x%x possible concrete values for the SYM-ADDR --- ",
						       symaddr_correct_concrete_addrs_count
						     );

					for(i_1=0; i_1<symaddr_correct_concrete_addrs_count; i_1=i_1+1)
					{
					    // concrete value originally-existed
					    /*
					    GetConcreteMemData( symaddr_correct_concrete_addrs_values[i_1], 
								(r_val.r_value_bits_size / 8), 
								&symaddr_tmp_concrete_value
							      );
					    
					    H_term_printf( "Reading data[0x%x] at symbolic-address 0x%x\n",
							   symaddr_tmp_concrete_value,
							   symaddr_correct_concrete_addrs_values[i_1]
							 );					    
					    symaddr_tmp_expr2 = vc_bvConstExprFromInt( hvc,
										       r_val.r_value_bits_size,
										       symaddr_tmp_concrete_value
										     );
					    */
					    symaddr_tmp_expr2 = obtain_expr_from_TEMU_virtmem( symaddr_correct_concrete_addrs_values[i_1],
								     			       (r_val.r_value_bits_size / 8),
					     						       hvc
					   						     );

					    symaddr_tmp_expr3 = vc_iteExpr( hvc,
									    symaddr_correct_concrete_addrs_constraints[i_1], // Constraint: sym_addr == con_addr
									    symaddr_tmp_expr1, // then
									    symaddr_tmp_expr2  // else
									  );

					    records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t ) * 
									          r_val.r_value_bits_size / 8
					 			    		);	

					    for(i=0;  i<(r_val.r_value_bits_size / 8);  i=i+1)
					    {
						low_bit  = i * 8 ;
						high_bit = (i+1) * 8 - 1;
						
						( (H_taint_record_t *)( // (uint32_t)records + i * sizeof(H_taint_record_t)
									records + i
							      	      ) 
						)->h_expr = vc_bvExtract( hvc,
									  symaddr_tmp_expr3,
								  	  high_bit,
								  	  low_bit
									); 					
					    }// end of for{i}
							
				  	    // bitmap : 1 bit per byte !
					    taint_bitmap = ( 1 << ( r_val.r_value_bits_size / 8 
							   	  ) 
					       		   ) - 1;

					    HH_Set_TemuMemByteTaintRecord( symaddr_correct_concrete_addrs_values[i_1],
								           (uint32_t)( (r_val.r_value_bits_size / 8) ), 
							       		   (uint64_t)taint_bitmap, 
							       		   records
							     		 );			
/*
				    H_term_printf( "symbolic addressing WRITE finished --- addr[0x%x] --- size = %d!\n",
						   symaddr_correct_concrete_addrs_values[i_1],
					           (uint32_t)( (r_val.r_value_bits_size / 8) )
						 );
 */

					}// end of for{i_1}

					if(symaddr_correct_concrete_addrs_values != NULL)
					{
					    free(symaddr_correct_concrete_addrs_values);
					}// end of if( )
					    
					if(symaddr_correct_concrete_addrs_constraints != NULL)
					{
					    free(symaddr_correct_concrete_addrs_constraints);
					}// end of if( )

 				    }// end of if(symaddr_correct_concrete_addrs_count != 0)
				    /* ----------------------------------------------------------------- */

			     break;
			}
			case L_TEMP:
			{
			// 对于临时变量的处理

				index = l_val.l_value.tmp_idx;

				// 临时变量的右值指针
				re_value = GetVarDecl_ValueByIndex(index);
			
				if( index == 0 ) // R_CC_OP
				{
				    str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_OP = %s ---- ", 
						   str_expr
						 );
				    free(str_expr);
				}
				else if( index == 1 ) // R_CC_DEP1
				{
				    str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_DEP1 = %s ---- ", 
						   str_expr
						 );
				    free(str_expr);
				}
				else if( index == 2 ) // R_CC_DEP2
				{		
				    str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_DEP2 = %s ---- ", 
						   str_expr
						 );
				    free(str_expr);
				}
				else if( index == 3 ) // R_CC_NDEP
				{
				    str_expr = exprString( r_val.r_value.expression );
				    H_term_printf( "R_CC_DEP = %s ---- ", 
						   str_expr
						 );
				    free(str_expr);
				}// end of if(index)

				/*				
				H_term_printf( "TempIndex %d as MOVE left value, right value is SYMBOLIC as %d !\n", 
					       index,
					       (r_val.r_value.expression)
					     );
				 */
				
			    #ifdef H_DELETE_OPRND_EXPR
				if(r_val.r_value_bits_size == 8)
				{
				    re_value->is_meta_sym_byte = r_val.is_meta_sym_byte; 
				}// end of if(r_val.r_value_bits_size)
			    #endif

				( re_value->r_value ).expression = r_val.r_value.expression;
				re_value->r_value_bits_size 	 = r_val.r_value_bits_size;
				re_value->r_value_type		 = R_SYM_EXPRESSION;

				// H_term_printf("Move Temp calculated \n");

				break;
			}
			
		}// end of switch{ }

		/* ============================================================ */
		
	}// end of if( )
	
	
	return 0 ;
	
}// end of Move::symexe( )
			        

string 
Move::tostring() 
{
    return lhs->tostring() + " = " + rhs->tostring() + ";";
}

Move::Move(const Move &other) 
  : Stmt(MOVE, other.asm_address, other.ir_address)
{
  this->lhs = other.lhs->clone();
  this->rhs = other.rhs->clone();
}

Move::Move(Exp *l, Exp *r, address_t asm_addr, address_t ir_addr) :  
  Stmt(MOVE, asm_addr, ir_addr), lhs(l), rhs(r)
{  
}


Move *
Move::clone() const
{
  return new Move(*this);
}
/* ========================================================================= */ // MOVE



// LABEL
/* ========================================================================= */ 
int Label::symexe( HVC   hvc,
		   HExpr path_expr
		 )
{
    
    return 0 ;
}// end of Move::symexe( )

void Label::pre_parse( int	* label_type, 
		       uint32_t * label_id		    
		     )
{
    const char * str_name = label.c_str( );

    uint32_t eip_addr = 0;
    int	     eip_len  = 0;
    int	     i	      = 0;

    if( (str_name[0] == 'p') &&	
	(str_name[1] == 'c')
      )
    {
	eip_len = strlen(str_name + 5);

	for(i=0; i<eip_len; i=i+1)	
	{
	    if( ( ( (uint32_t)str_name[5 + i] ) >=0x30) && ( ( (uint32_t)str_name[5 + i] ) <=0x39)
	      )
	    {
		eip_addr = eip_addr * 16 + ( ( (uint32_t)str_name[5 + i] ) - 0x30 );	
	    }
	    else
	    {
		eip_addr = eip_addr * 16 + ( ( (uint32_t)str_name[5 + i] ) - 'a' ) + 10 ;	
	    }// end of if( )
	}// end of for{ }
	
	// indicating virtual-addr!
	*label_type = 0;	
    }
    else
    {
	eip_len = strlen(str_name + 2);

	for(i=0; i<eip_len; i=i+1)	
	{
	    if( ( ( (uint32_t)str_name[2 + i] ) >=0x30) && ( ( (uint32_t)str_name[2 + i] ) <=0x39)
	      )
	    {
		eip_addr = eip_addr * 10 + ( ( (uint32_t)str_name[2 + i] ) - 0x30 );	
	    }
	    else
	    {
		eip_addr = eip_addr * 10 + ( ( (uint32_t)str_name[2 + i] ) - 'a' ) + 10 ;	
	    }// end of if( )
	}// end of for{ }

	// indicating label-id !
	*label_type = 1;
    }// end of if( )

    *label_id = eip_addr;

}// end of label::pre_parse( )



Label::Label(const Label &other) 
  : Stmt(LABEL, other.asm_address, other.ir_address)
{
  this->label = string(other.label);
}

Label::Label(string l, address_t asm_addr, address_t ir_addr)  
  : Stmt(LABEL,asm_addr, ir_addr)
{ label = l; }


Label *
Label::clone() const
{
  return new Label(*this);
}

string
Label::tostring()
{
  //  return "label L_" + label + ":";
  return "label " + label + ":";
}
/* ========================================================================= */  // LABEL



// JMP
/* ========================================================================= */
int Jmp::symexe( HVC   hvc,
		 HExpr path_expr
	       )
{
    H_term_printf( "jmp ignored !\n"
		 );
    return 0 ;
}// end of Jmp::symexe( )


Jmp::Jmp(Exp *e, address_t asm_addr, address_t ir_addr) : 
  Stmt(JMP, asm_addr, ir_addr), target(e)
{  }

Jmp::Jmp(const Jmp &other) 
  : Stmt(JMP, other.asm_address, other.ir_address)
{
  target = other.target->clone();
}

Jmp *
Jmp::clone() const
{
  return new Jmp(*this);
}


string Jmp::tostring() {
  string ret = "jmp(" + target->tostring() + ");";
  return ret;
}
/* ========================================================================= */ // JMP



// CJMP
/* ========================================================================= */

uint32_t CJmp::symexe_pathvc( HVC 	  hvc, 
			      HExpr *     global_path_expr,
			      HExpr *     predicate_expr,
		      
			      int	  H_predicate,
		    	      uint32_t    tbranch,
		       	      uint32_t    fbranch,
		       	      BRANCH_SAVE mybranch_save,

			      int   *	  label_type,

			      int	  isREP	// denote whether this CJMP belong to a REP-insn or not.
		      	    )
{
    H_R_value    cond_r_val;

    uint32_t 	 tbranch_stmt_id;
    uint32_t 	 fbranch_stmt_id;

    H_R_value    tbranch_r_val;
    H_R_value    fbranch_r_val;    
 
    char *	 str_expr;
    char * 	 str_type = NULL;

    uint32_t     ir_true_real_fbranch_eip  = 0;
    uint32_t     ir_false_real_tbranch_eip = 0;

    int 	 ir_true_or_false = -1;

    HType	 pred_expr_type = NULL;

    char * 	 dbg_ptr = NULL;
    

    cond->R_value_calculate( hvc,
			     (char *)(&cond_r_val)
			   );


    /* Just suppose the dst-eip would not be tainted ! */
    /* ------------------------------------------------------------------------------------------------- */
    t_target->R_value_calculate( hvc,
				 (char *)(&tbranch_r_val)
			       );

    f_target->R_value_calculate( hvc,
				 (char *)(&fbranch_r_val)
			       );

    // *real_fbranch_eip = 0;

    // CJmp's true branch is in-fact real-app's false branch !
    if(tbranch_r_val.r_value_type == R_PC_ADDRESS)
    {	
	ir_true_real_fbranch_eip  = tbranch_r_val.r_value.pc_address;
    }
    else if(fbranch_r_val.r_value_type == R_PC_ADDRESS)
    {
	ir_false_real_tbranch_eip = fbranch_r_val.r_value.pc_address;
    }// end of if( )

    /*
    if(tbranch_r_val.r_value_type == R_LABEL)
    {	
	ir_true_real_fbranch_eip  = tbranch_r_val.r_value.pc_address;
    }
    */

    H_term_printf( "ir_true branch is 0x%x , ir_false branch is 0x%x\n",
		   ir_true_real_fbranch_eip,
		   ir_false_real_tbranch_eip
		 );

    /* ------------------------------------------------------------------------------------------------- */

    // only cares about SYM-EXPR related branching predicate !
    if(cond_r_val.r_value_type == R_SYM_EXPRESSION)
    {
	pred_expr_type = vc_getType( hvc,
				     (cond_r_val.r_value).expression
				   );
	str_type = typeString(pred_expr_type);

	if( strcmp( str_type, 
		    "BOOLEAN "
		  ) != 0
	  )
	{
	    *predicate_expr = vc_notExpr( hvc,
				          vc_bvBoolExtract( hvc,					     
							    (cond_r_val.r_value).expression,
					    		    0
					  	          )
				        );    
	}
	else
	{
	    *predicate_expr = (cond_r_val.r_value).expression;
	    
	}// end of if(strcmp( ))

	free(str_type);

	// HHui-Fixme --- TODO: a more elegant solution ...
	// I suppose here, that this case should never be for JCC-like instructions !
	/* I suppose here that this predicate not as important as those for JCCs, choosing the label 
	   with a lower ID would mean that more IR-stmts be executed.
	 */
	if( (tbranch_r_val.r_value_type == R_LABEL) && 
	    (fbranch_r_val.r_value_type == R_LABEL)  
	  )
	{
	    *label_type = 1;

	    if( (uint32_t)(tbranch_r_val.r_value.label_id) < (uint32_t)(fbranch_r_val.r_value.label_id) )
	    {
	        return tbranch_r_val.r_value.label_id;		
	    }
	    else
	    {
	        return fbranch_r_val.r_value.label_id;		
	    }// end of if(tbranch_r_val.r_value.label_id)
	}// end of if(tbranch_r_val)


	// accumulate the predicate into global-path-expr.
	ir_true_or_false = mybranch_save( hvc,
				          global_path_expr,       // IN-OUT
				          *predicate_expr,
				          H_predicate,
				          tbranch,
				          fbranch,	   
				       
				          ir_true_real_fbranch_eip,
				          ir_false_real_tbranch_eip
				        );

	// mandatory control of the IR-stmt SYMEXE-flow for REP-like instructions.
	if(isREP)
	{	   
	    if( (tbranch_r_val.r_value_type == R_PC_ADDRESS) &&
		(tbranch_r_val.r_value.pc_address == HHui_insn_addr)
	      )
	    {
		ir_true_or_false = 0;
	    }
	    else if( (fbranch_r_val.r_value_type == R_PC_ADDRESS) &&
		     (fbranch_r_val.r_value.pc_address == HHui_insn_addr)
		   )
	    {
		ir_true_or_false = 1;
	    }
	    else
	    {
		// signalling error by triggering an exception 
		dbg_ptr  = NULL;
		*dbg_ptr = 1;
	    }// end of if()

	    // end of if(tbranch_r_val.r_value_type)
	    /*
	    // tbranch calculation
	    switch(tbranch_r_val.r_value_type)
	    {
		case R_LABEL:
		{
    	            tbranch_stmt_id = tbranch_r_val.r_value.label_id;
		    break;
		}				   
	    	case R_PC_ADDRESS: 
		{
		    tbranch_stmt_id = fetch_stmtid_by_content( 0,
							       tbranch_r_val.r_value.pc_address
							     );
		    break;
		}
		default:
		    // this should never happen !
		    break;
	    }// end of switch{tbranch_r_val.r_value_type}


	    // tbranch calculation
	    switch(fbranch_r_val.r_value_type)
	    {
		case R_LABEL:
		{
    	            fbranch_stmt_id = fbranch_r_val.r_value.label_id;
		    break;
		}				   
	    	case R_PC_ADDRESS: 
		{
		    fbranch_stmt_id = fetch_stmtid_by_content( 0,
							       fbranch_r_val.r_value.pc_address
							     );
		    break;
		}
		default:
		    // this should never happen !
		    break;
	    }// end of switch{fbranch_r_val.r_value_type}
	    */
	    


	}// end of if(isREP)
    }
    else
    {
	if(cond_r_val.r_value.value == 0)
	{
	    ir_true_or_false = 0;
	}
	else
	{
	    ir_true_or_false = 1;
	}// end of if(cond_r_val.r_value.value)
	
    }// end of if(cond_r_val.r_value_type == R_SYM_EXPRESSION)
 

    if(ir_true_or_false == 1)
    {
	// IR true branch is taken !
	if(tbranch_r_val.r_value_type == R_LABEL)
	{
	    // ir_true_real_fbranch_eip  = tbranch_r_val.r_value.pc_address;	    
	    *label_type = 1;
	    return tbranch_r_val.r_value.label_id;
	}
	else
	{
	    *label_type = 0;
	    return tbranch_r_val.r_value.pc_address;
	}// end of if( )
    }
    else
    {
	// IR false branch is taken !
	if(fbranch_r_val.r_value_type == R_LABEL)
	{
	    *label_type = 1;
	    return fbranch_r_val.r_value.label_id;
	}
	else
	{
	    *label_type = 0;
	    return fbranch_r_val.r_value.pc_address;
	}// end of if( )	
    }// end of if(ir_true_or_false)


}// end of symexe_pathvc( )


int CJmp::symexe( HVC   hvc,
		  HExpr path_expr
		)
{
    
    return 0 ;
}// end of Jmp::symexe( )



CJmp::CJmp(Exp *c, Exp *t, Exp *f, address_t asm_addr, address_t ir_addr) 
  : Stmt(CJMP, asm_addr, ir_addr), cond(c), t_target(t), f_target(f)
{  }


CJmp::CJmp(const CJmp &other) 
  : Stmt(CJMP, other.asm_address, other.ir_address)
{
  cond = other.cond->clone();
  f_target = other.f_target->clone();
  t_target = other.t_target->clone();
}

CJmp *
CJmp::clone() const
{
  return new CJmp(*this);
}

string 
CJmp::tostring() 
{
	string ret = "cjmp(" + cond->tostring() + "," + 
	
	t_target->tostring() + "," + f_target->tostring() + ");";
	
    return ret;
}
/* ========================================================================= */ // CJMP




// SPECIAL
/* ========================================================================= */ 
int Special::symexe( HVC   hvc,
		     HExpr path_expr
		   )
{
    
    return 0 ;
}// end of Special::symexe( )



Special::Special(string s, address_t asm_addr, address_t ir_addr) 
  : Stmt(SPECIAL, asm_addr, ir_addr), special(s)
{  }

Special::Special(const Special &other) 
  : Stmt(SPECIAL, other.asm_address, other.ir_address)
{
  special = other.special;
}

Special *
Special::clone() const
{
  return new Special(*this);
}

string Special::tostring() {
  string ret = "special(\"" + special + "\");";
  return ret;
}
/* ========================================================================= */ // SPECIAL




// COMMENT
/* ========================================================================= */
int Comment::symexe( HVC   hvc,
		     HExpr path_expr
		   )
{
    
    return 0 ;
}// end of Comment::symexe( )



Comment::Comment(string s, address_t asm_addr, address_t ir_addr) 
  : Stmt(COMMENT, asm_addr, ir_addr)
{ comment = s; }

Comment::Comment(const Comment &other) 
  : Stmt(COMMENT, other.asm_address, other.ir_address)
{
  comment = other.comment;
}


Comment *
Comment::clone() const
{
  return new Comment(*this);
}

string Comment::tostring() {
  string s = "//" + string(comment);
  return s;
}
/* ========================================================================= */ // COMMENT




// EXPSTMT
/* ========================================================================= */
int ExpStmt::symexe( HVC   hvc,
		     HExpr path_expr
		   )
{
/*
    switch(exp.exp_type)
    {
	case 
    }// end of switch{ }
 */   
    return 0 ;
}// end of ExpStmt::symexe( )



ExpStmt::ExpStmt(Exp *e, address_t asm_addr, address_t ir_addr) 
  : Stmt(EXPSTMT, asm_addr, ir_addr)
{
  exp =e ;
}

ExpStmt::ExpStmt(const ExpStmt &other) 
  : Stmt(EXPSTMT, other.asm_address, other.ir_address)
{
  exp = other.exp->clone();
}

ExpStmt *
ExpStmt::clone() const
{
  return new ExpStmt(*this);
}

string
ExpStmt::tostring(){
  string s = exp->tostring() + ";";
  return s;
}
/* ========================================================================= */ // EXPSTMT



//CALL
/* ========================================================================= */
int Call::symexe( HVC   hvc,
		  HExpr path_expr
		)
{    
    return 0 ;
}// end of Call::symexe( )



Call::Call(Exp *lval_opt, string fnname, vector<Exp*> params,
       address_t asm_ad, address_t ir_ad)
  : Stmt(CALL, asm_ad, ir_ad)
{
  this->lval_opt = lval_opt;
  this->callee = new Name(fnname);
  this->params = params;
}

Call::Call(Exp *lval_opt, Exp *callee, vector<Exp *> params,
	   address_t asm_ad, address_t ir_ad)
  : Stmt(CALL,asm_ad, ir_ad)
{
  this->lval_opt = lval_opt;
  this->callee = callee;
  this->params = params;
}

Call::Call(const Call &other)
  : Stmt(CALL, other.asm_address, other.ir_address)
{
  this->lval_opt = (other.lval_opt == NULL) ? NULL : other.lval_opt->clone();
  assert(other.callee);
  this->callee = other.callee->clone();
  this->params.clear();

  for(vector<Exp*>::const_iterator 
        i = other.params.begin(); i != other.params.end(); i++) {
    this->params.push_back((*i)->clone());
  }
}

string Call::tostring()
{
  ostringstream ostr;
  Name *name;
  if(this->lval_opt != NULL)
    ostr << this->lval_opt->tostring() << " = ";
  
  if(this->callee->exp_type == NAME){
    name = (Name *) this->callee;
    ostr << name->name;
  } else {
    ostr << "call " << this->callee->tostring();
  }
  ostr << "(";
  for(vector<Exp*>::iterator
        i=this->params.begin(); i != this->params.end(); i++) {
    ostr << (*i)->tostring();
    if ((i+1) != this->params.end())
      ostr << ", ";
  }
  ostr << ");";
  string str = ostr.str();
  return str;
}

Call* Call::clone() const
{
  return new Call(*this);
}
/* ========================================================================= */ // CALL



// RETURN
/* ========================================================================= */
int Return::symexe( HVC   hvc,
		    HExpr path_expr
		  )
{    
    return 0 ;
}// end of Call::symexe( )




Return::Return(Exp *exp_opt,
               address_t asm_ad, address_t ir_ad)
  : Stmt(RETURN, asm_ad, ir_ad)
{
  this->exp_opt = exp_opt;
}

Return::Return(const Return &other)
  : Stmt(RETURN, other.asm_address, other.ir_address)
{
  this->exp_opt = (other.exp_opt == NULL) ? NULL : other.exp_opt->clone();
}

string Return::tostring()
{
  ostringstream ostr;

  ostr << "return";

  if(this->exp_opt != NULL)
    ostr << " " << this->exp_opt->tostring();

  ostr << ";";

  return ostr.str();
}

Return* Return::clone() const
{
  return new Return(*this);
}
/* ========================================================================= */ // RETURN




// FUNC
/* ========================================================================= */
int Func::symexe( HVC   hvc,
		  HExpr path_expr
		)
{    
    return 0 ;
}// end of Call::symexe( )




Func::Func(string fnname, bool has_rv, reg_t rt, 
                   vector<VarDecl*> params, 
                   bool external, vector<Stmt*> body,
                   address_t asm_ad, address_t ir_ad)
  : Stmt(FUNCTION, asm_ad, ir_ad)
{
  this->fnname = fnname;
  this->has_rv = has_rv;
  this->rt = rt;
  this->params = params;
  this->external = external;
  this->body = body;
}

Func::Func(const Func &other)
  : Stmt(FUNCTION, other.asm_address, other.ir_address)
{
  this->fnname = other.fnname;
  this->has_rv = other.has_rv;
  this->rt = other.rt;
  this->params.clear();
  for(vector<VarDecl*>::const_iterator
        i=other.params.begin(); i!=other.params.end(); i++)
    this->params.push_back((*i)->clone());
  this->external = other.external;
  this->body.clear();
  for(vector<Stmt*>::const_iterator
        i=other.body.begin(); i!=other.body.end(); i++)
    this->body.push_back((*i)->clone());
}

string Func::tostring()
{
  ostringstream ostr;
  if (external)
    ostr << "extern ";

  if (has_rv) 
    ostr << Exp::string_type(rt) << " ";
  else
    ostr << "void ";
  
  //ostr << fnname;

  ostr << this->fnname << "(";
  for(vector<VarDecl*>::iterator
        i=this->params.begin(); i != this->params.end(); i++) {
    ostr << (*i)->tostring();
    if ((i+1) != this->params.end())
      ostr << ", ";
  }
  ostr << ")";

  if (this->body.empty()) {
    ostr << ";";
  } else {
    ostr << "\n";
    ostr << "{\n";
    for(vector<Stmt*>::iterator
          i=this->body.begin(); i != this->body.end(); i++) {
      ostr << "\t" << (*i)->tostring() << endl;
    }
    ostr << "}";
  }

  return ostr.str();
}

Func* Func::clone() const
{
  return new Func(*this);
}
/* ========================================================================= */ // end of FUNC



// ASSERT
/* ========================================================================= */
int Assert::symexe( HVC   hvc,
		    HExpr path_expr
		  )
{    
    return 0 ;
}// end of Call::symexe( )




Assert::Assert(Exp *cond, address_t asm_ad, address_t ir_ad)
  : Stmt(ASSERT, asm_ad, ir_ad), cond(cond)
{ }

Assert::Assert(const Assert &other)
  : Stmt(ASSERT, other.asm_address, other.ir_address) 
{
  cond = other.cond->clone();
}

string Assert::tostring()
{
  return "assert(" + cond->tostring() + ");";
}
 /* ========================================================================= */ // ASSERT

 



//----------------------------------------------------------------------
// Convert int to std::string in decimal form
//----------------------------------------------------------------------
string int_to_str( int i )
{
    ostringstream stream;
    stream << i << flush;
    return (stream.str());
}

//----------------------------------------------------------------------
// Convert int to std::string in hex form
//----------------------------------------------------------------------
string int_to_hex( int i )
{
    ostringstream stream;
    stream << hex << i << flush;
    return (stream.str());
}

//----------------------------------------------------------------------
// Generate a unique label, this is done using a static counter
// internal to the function.
//----------------------------------------------------------------------
Label *mk_label()
{
    static int label_counter = 0;
    return new Label("L_" + int_to_str(label_counter++) );
}


