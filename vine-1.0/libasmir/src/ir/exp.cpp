/*
Vine is Copyright (C) 2006-2009, BitBlaze Team.

You can redistribute and modify it under the terms of the GNU GPL,
version 2 or later, but it is made available WITHOUT ANY WARRANTY.
See the top-level README file for more details.

For more information about Vine and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include "exp.h"
#include "stmt.h"
#include <iostream>
#include <map>
#include <cassert>


#include <stdlib.h>
#include <malloc.h>

#include "i386_reg_init.h"

#include "GetTemuData.h"

#include "H_vulscan_config.h"

#include "HH_IR_translate_config.h"

// HHui's funcs for TEMU concrete values' reading !
// #include "GetTemuData.h"

// HHui's STP declarations !
//#include "hc_interface.h"

// TEMU record related !
#include "H_taint_record.h"

#include "H_STP_stub.h"


#include "SymExe.h"

#include "sym_addr_resolve.h"

#include "record2file.h"

using namespace std;


// switches for several vulnerability scanning policies.
/* ======================================================================= */
extern int * H_vulscan_once_enough_err_found;
/* ======================================================================= */


// Do NOT change this. It is used in producing XML output.
static string binopnames[] = {
  "PLUS",
  "MINUS",
  "TIMES",
  "DIVIDE",
  "MOD",
  "LSHIFT",
  "RSHIFT",
  "ARSHIFT",
  "LROTATE",
  "RROTATE",
  "LOGICAND",
  "LOGICOR",
  "BITAND",
  "BITOR",
  "XOR",
  "EQ",
  "NEQ",
  "GT",
  "LT",
  "GE",
  "LE",
  "SDIVIDE"
};
static string strs[] = {
  "+",
  "-",
  "*",
  "/",
  "%",
  "<<",
  ">>",
  "@>>",
  "<<",
  ">>",
  "&&",
  "||",
  "&",
  "|",
  "^",
  "==",
  "<>",
  ">",
  "<",
  ">=",
  "<=",
  "/$" 
};

uint64_t
Exp::cast_value(reg_t t, uint64_t v)
{
  // Makes debugging easier actually assigning to correct type.
  uint64_t u64;
  uint32_t u32;
  uint16_t u16;
  uint8_t u8;
  switch(t){
  case REG_1: if(v == 0) return 0; else return 1; break;
  case REG_8: u8 = (uint8_t) v; return u8; break;
  case REG_16: u16 = (uint16_t) v; return u16; break;
  case REG_32: u32 = (uint32_t) v; return u32; break;
  case REG_64: u64 = (uint64_t) v; return u64; break;
  }
  assert(0); // eliminates warnings.
}

uint32_t 
Exp::reg_to_bits(const reg_t &reg)
{
  switch(reg)
    {
    case REG_1: return 1; break;
    case REG_8: return 8; break;
    case REG_16: return 16; break;
    case REG_32: return 32; break;
    case REG_64: return 64; break;
    }
  assert(0); // eliminates warnings.
}


Exp*
Exp::clone(Exp* copy)
{
  return copy->clone();
}


void Exp::destroy( Exp *expr )
{
    switch ( expr->exp_type )
    {
    case BINOP:     BinOp::destroy((BinOp *)expr);          break;
    case UNOP:      UnOp::destroy((UnOp *)expr);            break;
    case CONSTANT:  Constant::destroy((Constant *)expr);    break;
    case MEM:       Mem::destroy((Mem *)expr);              break;
    case TEMP:      Temp::destroy((Temp *)expr);            break;
    case PHI:       Phi::destroy((Phi *)expr);              break;
    case UNKNOWN:   Unknown::destroy((Unknown *)expr);      break;
    case CAST:      Cast::destroy((Cast *)expr);            break;
    case NAME:      Name::destroy((Name *)expr);            break;
    case LET:       Let::destroy((Let *)expr);              break; 
    case EXTENSION:   
      // Fixme: need to make a destroy virtual function that all
      // exp have. 
      print_debug("warning", "Memory lost on unhandled destroy"); break;
    }

}
string
Exp::string_type(const reg_t &typ)
{
  //  return string_type(typ.kind, typ.width);
  string s;
  switch(typ)
    {
    case REG_1: s= "reg1_t"; break;
    case REG_8: s = "reg8_t"; break;
    case REG_16: s = "reg16_t"; break;
    case REG_32: s = "reg32_t"; break;
    case REG_64: s = "reg64_t"; break;
    }
  return s;
}


// BinOP
/* ===================================================================== */
/*
    class BinOp : public Exp 
    {
	 public:
	  BinOp(binop_type_t t, Exp *l, Exp *r);
	  virtual void accept(IRVisitor *v) { v->visitBinOp(this); }
	  virtual ~BinOp() {};
	  BinOp(const BinOp& copy);
	  virtual string tostring() const;
	  virtual BinOp *clone() const;

	  /// Utility to convert binop to the string representation, e.g.
	  /// PLUS -> "+"
	  static string optype_to_string(const binop_type_t t);
	  // PLUS -> "PLUS"
	  static string optype_to_name(const binop_type_t t);
	  /// Reverse mapping from string to binop_type_t
	  static binop_type_t string_to_optype(const string s);
	  static void destroy( BinOp *expr );

	  Exp *lhs;
	  Exp *rhs;
	  binop_type_t binop_type;

	 virtual void * abstract_value_evaluate( ) ;	 
	};
  */
  
// BinOP  只能出现在vine IR  的右边操作数中!
void BinOp::L_value_calculate( HVC    hvc, 
			       char * value // would be returned as H_R_value ! 
			     )
{
   //  vine IR  的左值一般比较简单
    H_R_value l_value ;
    H_R_value r_value ;
   
    l_value.is_meta_sym_byte = 0;
    r_value.is_meta_sym_byte = 0;

    lhs->R_value_calculate( hvc,
			    (char *)( &l_value )
			  );

#ifdef H_VULSCAN_ONCE_ENOUGH
    if(*H_vulscan_once_enough_err_found == 1)
    {
	return;
    }// end of if(*H_vulscan_once_enough_err_found)
#endif

    rhs->R_value_calculate( hvc,
			    (char *)( &r_value )
			  );

#ifdef H_VULSCAN_ONCE_ENOUGH
    if(*H_vulscan_once_enough_err_found == 1)
    {
	return;
    }// end of if(*H_vulscan_once_enough_err_found)
#endif

    char * left_str  = NULL;
    char * right_str = NULL;

    int    left_typ  = 0;
    int    right_typ = 0;


    int    both_con  = 0;
    int    left_con  = 0;

    HExpr  tmp_expr  = NULL;
    HExpr  tmp_expr1 = NULL;
    HExpr  tmp_expr2 = NULL;
    HExpr  tmp_expr3 = NULL;
    HExpr  tmp_expr4 = NULL;

    int	   bits_num  = 0;
    int	   bits_num1 = 0;
	

    int    bitno_low  = 0;
    int	   bitno_high = 0;

    uint8_t * temp_debug_ptr = NULL;
    uint32_t  temp_debug_len = 0;

    int    qresult = 0;
    /*
	//  Exp  作为右值的计算属性

	typedef enum R_EXP_VALUE
	{
	    R_SYM_EXPRESSION = 0,
	    R_CON_VALUE
	}R_exp_value_t;

	// 右值具体形式
	typedef union R_VALUE
	{
	    HExpr expression;
	    int 	value;
	}R_value_t;


	typedef struct H_R_VALUE
	{
	    R_value_t  		r_value;
	    R_exp_value_t	r_value_type;
	    uint32_t		r_value_bits_size;
	}H_R_value;
      */
/*
    H_term_printf( "left type is %d, right type is %d\n",
		   l_value.r_value_type,
		   r_value.r_value_type
		 );

    H_term_printf( "left OP right --- op = %d, left is %s, right is %s \n",
		   binop_type,
		   ( (l_value.r_value_type == R_SYM_EXPRESSION) ? "symbolic" : ( (l_value.r_value_type == R_CON_VALUE) ? "concrete" : "NULL"
									       ) 
		   ),
		   ( (r_value.r_value_type == R_SYM_EXPRESSION) ? "symbolic" : ( (r_value.r_value_type == R_CON_VALUE) ? "concrete" : "NULL"
									       ) 
		   )
		 );
*/
    switch(binop_type)
    {
        case PLUS:
	 {
	 	if( (  l_value.r_value_type == R_CON_VALUE ) &&
		     ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   /*
		   H_term_printf( "concrete addition ---- 0x%x(left value) + 0x%x(right value) = 0x%8x \n",
				  (l_value.r_value).value,
				  (r_value.r_value).value,
				  (l_value.r_value).value + (r_value.r_value).value
				);
		    */

		   ( ( (H_R_value  *)value)->r_value ).value   = (l_value.r_value).value + (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type       = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;
			
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    // Right is symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( r_value.r_value ).expression
					     );
		    /*
		    H_term_printf( "sym-right bits_num = %d\n",
				   bits_num
				 );
		     */
		    tmp_expr = vc_bvConstExprFromInt( hvc,
					  	      bits_num,
						      l_value.r_value.value
						    );
		    // Expr vc_bvPlusExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvPlusExpr( hvc, 
		    								    bits_num,
		    								    (r_value.r_value).expression, 
		    								    tmp_expr
		    								  ); 
		    vc_DeleteExpr(tmp_expr);
		
		#ifdef H_DELETE_OPRND_EXPR
		    if((r_value.is_meta_sym_byte) == 0)
		    {
		        vc_DeleteExpr( (r_value.r_value).expression );
		    }// end of if(r_value->is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		    
/*		    
		    H_term_printf( "CON + SYM ===> vc_bvPlusExpr( )!  --- bit-num=%d, sym_length == con_length\n",
				   bits_num,
				   ( (r_value.r_value_bits_size == l_value.r_value_bits_size) ? 1:0 )
				 );
 */		     		    
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		    // Left is symbolic !

		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );
		    /*
		    H_term_printf( "sym-left bits_num = %d\n",
				   bits_num
				 );
		     */
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      r_value.r_value.value
						    );
		    /*
		    H_term_printf( "SYM + CON ===> vc_bvPlusExpr( )!  --- bit-num=%d, (sym_length == con_length) = %d\n",
				   bits_num,
				   ( (r_value.r_value_bits_size == l_value.r_value_bits_size) ? 1:0 )
				 );
		     */
		    // Expr vc_bvPlusExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvPlusExpr( hvc, 
		    								    bits_num,
		    								    (l_value.r_value).expression, 
		    								    tmp_expr
		    								  );		    		
		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if((l_value.is_meta_sym_byte) == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;

		}
		else
		{
		    // both are symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );
		    bits_num1 = vc_getBVLength( hvc, 
			 	 	        ( r_value.r_value ).expression
					      );

		    if(bits_num != bits_num1)
		    {
			// H_term_printf("invalid PLUS ---- left-bits_num != right-bits_num !\n");

			uint8_t * bits_ptr = NULL;
		 	bits_ptr[0] = 0;
		    }// end of if( )

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvPlusExpr( hvc,
										    bits_num,
		    							            (l_value.r_value).expression,
										    (r_value.r_value).expression
										  ); 	
		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}// end of if( )	 			 	

	 	break;
        }
	case MINUS:
	{
	 	if( (  l_value.r_value_type == R_CON_VALUE ) &&
		     ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   ( ( (H_R_value  *)value)->r_value ).value   = (l_value.r_value).value - (r_value.r_value).value;
		   
		   ( (H_R_value  *)value)->r_value_type        = R_CON_VALUE;
		   ( (H_R_value  *)value)->r_value_bits_size   = l_value.r_value_bits_size;
		    /*
		    H_term_printf( "concrete subtraction ---- 0x%x(left value) - 0x%x(right value) = 0x%8x \n",
				   (l_value.r_value).value,
				   (r_value.r_value).value,
				   (l_value.r_value).value - (r_value.r_value).value
				 );
		     */
			
		}
		else if( l_value.r_value_type == R_CON_VALUE )
		{
		    // Right is symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( r_value.r_value ).expression
					     );
			
		    if( l_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = l_value.r_value_bits_size;
		    }// end of if( )

		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      l_value.r_value.value
						    );

		    // Expr vc_bvPlusExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvMinusExpr( hvc, 
		    								     bits_num,
		    								     tmp_expr,
		    								     (r_value.r_value).expression    											   ); 
		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;		
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		    // Left is symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );
			
		    if( r_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = r_value.r_value_bits_size;
		    }// end of if( )

		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      r_value.r_value.value
						     );

		    // Expr vc_bvPlusExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvMinusExpr( hvc, 
		    								     bits_num,
		    								     (l_value.r_value).expression, 
		    								     tmp_expr
		    								   ); 
		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}
		else
		{
		    // both are symbolic !
		    bits_num = vc_getBVLength( hvc, 
			 		       ( l_value.r_value ).expression
					     );


		    bits_num1 = vc_getBVLength( hvc, 
					 	( r_value.r_value ).expression
					      );

		    bits_num = (bits_num >= bits_num1) ? bits_num1 : bits_num; 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvMinusExpr( hvc,
									             bits_num,
		    								     (l_value.r_value).expression, 
		    								     (r_value.r_value).expression
										   ); 

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
	 	    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}// end of if( )		

		break;
	}
	case TIMES:
	{
	 	if( (  l_value.r_value_type == R_CON_VALUE ) &&
		     ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   ( ( (H_R_value  *)value)->r_value ).value	= (l_value.r_value).value * (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type 	= R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size   = l_value.r_value_bits_size;
			
		}
		else if( l_value.r_value_type == R_CON_VALUE )
		{
		    // Right is symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( r_value.r_value ).expression
					     );
			
		    if( l_value.r_value_bits_size < bits_num )
		    {
		        bits_num = l_value.r_value_bits_size;
		    }// end of if( )

		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      l_value.r_value.value
						    );

		    // Expr vc_bvMultExpr(VC vc, int n_bits, Expr left, Expr right) 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvMultExpr( hvc, 
		    								    bits_num,
		    								    tmp_expr,
		    								    (r_value.r_value).expression
		    								  ); 
		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
			
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		    // vc_getBVLength(VC vc, Expr e); 
		    bits_num = vc_getBVLength( hvc, 
		 			       ( l_value.r_value ).expression
					     );
			
		    if( r_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = r_value.r_value_bits_size;
		    }// end of if( )

		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      r_value.r_value.value
						    );

		    // Expr vc_bvPlusExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvMultExpr( hvc, 
		    								    bits_num,
		    								    (l_value.r_value).expression, 
		    								    tmp_expr
		    								  ); 
		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}
		else
		{
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );


		    bits_num1 = vc_getBVLength( hvc, 
					 	( r_value.r_value ).expression
					      );

		    bits_num = (bits_num >= bits_num1) ? bits_num1 : bits_num; 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvMultExpr( hvc,
										    bits_num,
		    								    (l_value.r_value).expression, 
		    								    (r_value.r_value).expression 
		    								  ); 
		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
   		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}// end of if( )		
		
		break;
	}
	case DIVIDE:
	{
	 	if( (  l_value.r_value_type == R_CON_VALUE ) &&
		     ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   ( ( (H_R_value  *)value)->r_value ).value  = (l_value.r_value).value / (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
			
		}
		else if( l_value.r_value_type == R_CON_VALUE )
		{
		    // vc_getBVLength(VC vc, Expr e); 
		    bits_num = vc_getBVLength( hvc, 
					       ( r_value.r_value ).expression
					     );
			
		    if( l_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = l_value.r_value_bits_size;
		    }// end of if( )

		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      l_value.r_value.value
						    );

		    // Expr vc_bvDivExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvDivExpr( hvc, 
		    								   bits_num,
		    								   tmp_expr,
		    								   (r_value.r_value).expression
									         ); 

		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;


		    // right-value is symbolic, so checks for DIV-BY-0
		    /* ------------------------------------------------------------ */
		    tmp_expr1 = vc_bvConstExprFromInt( hvc,
						       bits_num,
						       0
						     );
		    tmp_expr2 = vc_eqExpr( hvc,
					   tmp_expr1,
					   ( r_value.r_value ).expression
					 );
		    tmp_expr3 = vc_andExpr( hvc,
					    *HHui_current_path_expr,
					    tmp_expr2					    
					  );
		    tmp_expr4 = vc_notExpr( hvc,
					    tmp_expr3
					  );
		    vc_push(hvc);
		    
		    qresult = vc_query( hvc,
					tmp_expr4
				      );
		    if(qresult == 0)
		    {
			record_ERROR_2file( tmp_expr3,
					    5 // err_id
					  );

		    #ifdef H_VULSCAN_ONCE_ENOUGH
		        *H_vulscan_once_enough_err_found = 1;
		    #endif
		    }// end of if(qresult)

		    vc_DeleteExpr(tmp_expr4);
		    vc_DeleteExpr(tmp_expr3);
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    vc_pop(hvc);
		    /* ------------------------------------------------------------ */
		    
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		    // vc_getBVLength(VC vc, Expr e); 
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );
			
		    if( r_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = r_value.r_value_bits_size;
		    }// end of if( )

		    /*
		    H_term_printf( "L_shift r_value length = %d",
				   r_value.r_value_bits_size
				 );
		    */
		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      r_value.r_value.value
						     );

		    // Expr vc_bvPlusExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvDivExpr( hvc, 
		    								   bits_num,
		    								   (l_value.r_value).expression, 
		    								   tmp_expr
		    								 ); 

		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
 		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}
		else
		{
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );


		    bits_num1 = vc_getBVLength( hvc, 
					 	( r_value.r_value ).expression
					      );

		    bits_num = (bits_num >= bits_num1) ? bits_num1 : bits_num; 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvDivExpr( hvc,
										   bits_num,
		    								   (l_value.r_value).expression, 
		    								   (r_value.r_value).expression
		    								 ); 
		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;

		    // right-value is symbolic, so checks for DIV-BY-0
		    /* ------------------------------------------------------------ */
		    tmp_expr1 = vc_bvConstExprFromInt( hvc,
						       bits_num,
						       0
						     );
		    tmp_expr2 = vc_eqExpr( hvc,
					   tmp_expr1,
					   ( r_value.r_value ).expression
					 );
		    tmp_expr3 = vc_andExpr( hvc,
					    *HHui_current_path_expr,
					    tmp_expr2					    
					  );
		    tmp_expr4 = vc_notExpr( hvc,
					    tmp_expr3
					  );
		    vc_push(hvc);
		    
		    qresult = vc_query( hvc,
					tmp_expr4
				      );
		    if(qresult == 0)
		    {
			record_ERROR_2file( tmp_expr3,
					    5 // err_id
					  );			
		    #ifdef H_VULSCAN_ONCE_ENOUGH
		        *H_vulscan_once_enough_err_found = 1;
		    #endif
		    }// end of if(qresult)

		    vc_DeleteExpr(tmp_expr4);
		    vc_DeleteExpr(tmp_expr3);
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    vc_pop(hvc);
		    /* ------------------------------------------------------------ */

		}// end of if( )		
	

		// H_term_printf("DIVIDE finished !\n");	

		break;		
	}
	case MOD:
	{
	 	if( (  l_value.r_value_type == R_CON_VALUE ) &&
		     ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   ( ( (H_R_value  *)value)->r_value ).value  = (l_value.r_value).value % (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
			
		}
		else if( l_value.r_value_type == R_CON_VALUE )
		{
		    // Right is symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( r_value.r_value ).expression
					     );
			
		    if( l_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = l_value.r_value_bits_size;
		    }// end of if( )

		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      l_value.r_value.value
						    );

		    // Expr vc_bvModExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvModExpr( hvc, 
		    								   bits_num,
		    								   tmp_expr,
		    								   (r_value.r_value).expression	  
		    								 ); 
		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
    		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		    // Left is symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );
			
		    if( r_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = r_value.r_value_bits_size;
		    }// end of if( )

		
		    tmp_expr = vc_bvConstExprFromInt( hvc,
						      bits_num,
						      r_value.r_value.value
						    );

		    // Expr vc_bvPlusExpr(VC vc, int n_bits, Expr left, Expr right); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvModExpr( hvc, 
		    							           bits_num,
		    								   (l_value.r_value).expression, 
		    								   tmp_expr
		    								 ); 
		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}
		else
		{
		    // both are symbolic !
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );

		    bits_num1 = vc_getBVLength( hvc, 
					 	( r_value.r_value ).expression
					      );

		    bits_num = (bits_num >= bits_num1) ? bits_num1 : bits_num; 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvModExpr( hvc,
										   bits_num,
		    								   (l_value.r_value).expression, 
		    								   (r_value.r_value).expression
										 ); 
		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
		}// end of if( )		
		
		break;
	}
	case LSHIFT:
	{
	 	if( (  l_value.r_value_type == R_CON_VALUE ) &&
		     ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   ( ( (H_R_value  *)value)->r_value ).value  = (l_value.r_value).value << (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
			
		}
		else if( l_value.r_value_type == R_CON_VALUE )
		{  
// HHui Fixme : 左操作数(  被移动数)   为常数，右操作数为 Expr( number to shift left ! )   的情况----  扩展为32  bit 
		    /*
		    bits_num = vc_getBVLength( hvc, 
					       ( r_value.r_value ).expression
					     );
			
		    if( r_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = r_value.r_value_bits_size;
		    }// end of if( )
		    */		
		    tmp_expr2 = vc_bvConstExprFromInt( hvc,
						       // l_value.r_value_bits_size,
						       32,
						       l_value.r_value.value
						     );

 	 	    // Expr vc_bvVar32LeftShiftExpr(VC vc, Expr sh_amt, Expr child); 		    
		    
		    if( 32 != r_value.r_value_bits_size )
		    {
		        tmp_expr1 = vc_bvSignExtend( hvc,
						     (r_value.r_value).expression,
						     32
						   ); 
		    }
		    else
		    {
			tmp_expr1 = (r_value.r_value).expression;
		    }// end of if( )

		    /*
		    temp_debug_ptr = (uint8_t *)exprString((r_value.r_value).expression);
		    H_term_printf( "right-expr is %s\n",
				   (char *)temp_debug_ptr
				 );
		    free(temp_debug_ptr);
		    */

		    tmp_expr = vc_bvVar32LeftShiftExpr( hvc, 
						        tmp_expr1, // (r_value.r_value).expression,
						        tmp_expr2
						      );
		    vc_DeleteExpr(tmp_expr1);
		    vc_DeleteExpr(tmp_expr2);

		    bitno_low  = 0;
		    bitno_high = l_value.r_value_bits_size - 1;
		
		    if( 32 != l_value.r_value_bits_size )
		    {
		        ( ( (H_R_value  *)value)->r_value ).expression = vc_bvExtract( hvc,
										       tmp_expr,
							   			       bitno_high,
	    									       bitno_low
										     );

			vc_DeleteExpr(tmp_expr);
		    }
		    else
		    {
			( ( (H_R_value  *)value)->r_value ).expression = tmp_expr;
		    }// end of if( )

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
    		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;		    

		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "LSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		    */

		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )



		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    /* ----------------------------------------------------------------------------------------------------- */ // just for debugging !
			
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		    tmp_expr = vc_bvLeftShiftExpr( hvc,
						   (r_value.r_value).value, 
		   				   (l_value.r_value).expression
						 );
		    /*
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvLeftShiftExpr( hvc,
											 (r_value.r_value).value, 
		   									 (l_value.r_value).expression
										       );
		    */
		    bitno_low  = 0;
		    bitno_high = l_value.r_value_bits_size - 1;
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvExtract( hvc,
									   //( ( (H_R_value  *)value)->r_value ).expression,
										   tmp_expr,
							   			   bitno_high,
	    									   bitno_low
										 );
		  							       
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;		    
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;

		    // H_term_printf("left shifting finished !\n");

		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "LSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		    */
		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )

		    vc_DeleteExpr(tmp_expr);

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    /* ----------------------------------------------------------------------------------------------------- */ // just for debugging !

		}
		else
		{
		// 两者皆为符号操作数的情况，扩展为32 bit	

		    if( 32 != r_value.r_value_bits_size )	
		    {
			tmp_expr1 = vc_bvSignExtend( hvc,
						     (r_value.r_value).expression,
						     32
						   );
		    }
		    else
		    {
			tmp_expr1 = (r_value.r_value).expression;
		    }// end of if( )

		    if( 32 != l_value.r_value_bits_size )	
		    {
			tmp_expr2 = vc_bvSignExtend( hvc,
						     (l_value.r_value).expression,
						     32
						   );
		    }
		    else
		    {
			tmp_expr2 = (l_value.r_value).expression;
		    }// end of if( )

		    tmp_expr = vc_bvVar32LeftShiftExpr( hvc,				  		          								tmp_expr1,
							tmp_expr2
						      ); 

		    if((r_value.r_value).expression != tmp_expr1)
		    {
		        vc_DeleteExpr(tmp_expr1);
		    }// end of if(r_value)

		    if((l_value.r_value).expression != tmp_expr2)
		    {
		        vc_DeleteExpr(tmp_expr2);
		    }// end of if(l_value

		    bitno_low  = 0;
		    bitno_high = l_value.r_value_bits_size - 1;
		
		    if( 32 != l_value.r_value_bits_size )
		    {
		        ( ( (H_R_value  *)value)->r_value ).expression = vc_bvExtract( hvc,
										       tmp_expr,
							   			       bitno_high,
										       bitno_low
										     );
			vc_DeleteExpr(tmp_expr);
		    }
		    else
		    {
			( ( (H_R_value  *)value)->r_value ).expression = tmp_expr;
		    }// end of if( )

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;


		    
		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );

		    /*
		    H_term_printf( "LSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		    */

		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )
		    /* ----------------------------------------------------------------------------------------------------- */ // just for debugging !

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    /*
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvLeftShiftExpr( hvc,
											 (r_value.r_value).expression, // 左移的位数
		   									 (l_value.r_value).expression
		    								       );

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size; // 32;
		    */		
		}// end of if( )
		break;
	}
	case RSHIFT:
	{
		// H_term_printf("-------------- RIGHT SHIFT ------------------ ");

	 	if( (  l_value.r_value_type == R_CON_VALUE ) &&
		     ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   ( ( (H_R_value  *)value)->r_value ).value   = (l_value.r_value).value >> (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type       = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;
			
		}
		else if( l_value.r_value_type == R_CON_VALUE )
		{  
// HHui Fixme : 左操作数(  被移动数)   为常数，右操作数为Expr( number to shift right ! )   的情况----  扩展为32  bit 
		    /*
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );	
		    if( r_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = r_value.r_value_bits_size;
		    }// end of if( )
		    */
		    tmp_expr1 = vc_bvConstExprFromInt( hvc,
						      32,
						      l_value.r_value.value
						    );

 	 	    // Expr vc_bvVar32LeftShiftExpr(VC vc, Expr sh_amt, Expr child); 
		    if( 32 != r_value.r_value_bits_size )
		    {
			tmp_expr2 = vc_bvSignExtend( hvc,
						     (r_value.r_value).expression,
						     32
						   );
		        tmp_expr = vc_bvVar32RightShiftExpr( hvc, 
							     tmp_expr2,
						             tmp_expr1
	    			  		           ); 
			vc_DeleteExpr(tmp_expr2);
		    }
		    else
		    {
			tmp_expr = vc_bvVar32RightShiftExpr( hvc,
							     (r_value.r_value).expression,
							     tmp_expr1
							   );
		    }// end of if( )
		    
		    vc_DeleteExpr(tmp_expr1);

		    if( 32 != l_value.r_value_bits_size )
		    {
		       ( ( (H_R_value  *)value)->r_value ).expression = vc_bvExtract( hvc,
										      tmp_expr,
										      (l_value.r_value_bits_size - 1),
										      0
										    );
			vc_DeleteExpr(tmp_expr);
		    }
		    else
		    {
			( ( (H_R_value  *)value)->r_value ).expression = tmp_expr;
		    }// end of if( )

		    
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "RSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		     */

		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )

		    ( (H_R_value  *)value)->r_value_type       = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;


		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		// 右移位数为具体值的情况
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvRightShiftExpr( hvc,
											 (r_value.r_value).value, // right 移的位数
		   									 (l_value.r_value).expression
		    									);
		    ( (H_R_value  *)value)->r_value_type       = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;

		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "RSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		     */

		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		    /* ----------------------------------------------------------------------------------------------------- */ // just for debugging !
		}
		else
		{
		// 两者皆为符号操作数的情况，扩展为32 bit

		    if( 32 != l_value.r_value_bits_size )
		    {
			tmp_expr1 = vc_bvSignExtend( hvc,
						     (l_value.r_value).expression,
						     32
						   );
		    }
		    else
		    {
			tmp_expr1 = (l_value.r_value).expression;
		    }// end of if( )

		    if( 32 != r_value.r_value_bits_size )
		    {
			tmp_expr2 = vc_bvSignExtend( hvc,
						     (r_value.r_value).expression,
						     32
						   );
		    }
		    else
		    {
			tmp_expr2 = (r_value.r_value).expression;
		    }// end of if( )

		    tmp_expr = vc_bvVar32RightShiftExpr( hvc,
							 tmp_expr2,
							 tmp_expr1
						       ); 

		    if(tmp_expr1 != (l_value.r_value).expression)
		    {
			vc_DeleteExpr(tmp_expr1);
		    }// end of if(tmp_expr1)

		    if(tmp_expr2 != (r_value.r_value).expression)
		    {
		        vc_DeleteExpr(tmp_expr2);
		    }// end of if(tmp_expr2)

		    bitno_low  = 0;
		    bitno_high = l_value.r_value_bits_size - 1;

		    if(32 != l_value.r_value_bits_size)
		    {
		        ( ( (H_R_value  *)value)->r_value ).expression = vc_bvExtract( hvc,
										       tmp_expr,
							   			       bitno_high, 
										       bitno_low
										     );
		        vc_DeleteExpr(tmp_expr);
	            }
		    else
		    {
			( ( (H_R_value  *)value)->r_value ).expression = tmp_expr;
		    }// end of if( )
		    ( (H_R_value  *)value )->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;

		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "RSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		    */

		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )


		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    /* ----------------------------------------------------------------------------------------------------- */ // just for debugging !

		   /*
		   ( ( (H_R_value  *)value)->r_value ).expression = vc_bvRightShiftExpr( hvc,
											 (r_value.r_value).expression, // 左移的位数
		   									 (l_value.r_value).expression
		    								       );

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
		    */

		}// end of if( )		
		
		// H_term_printf("- RIGHT SHIFT ! - ");

		break;
	}
	case ARSHIFT: /* @>> : arithmetic shift right */
	{		
		// H_term_printf("--- ARSHIFT --- \n");
				
		if( ( l_value.r_value_type == R_CON_VALUE ) &&
		    ( r_value.r_value_type == R_CON_VALUE )
		  )	
		{
		   ( ( (H_R_value  *)value)->r_value ).value  = (l_value.r_value).value >> (r_value.r_value).value;
		   
		   ( (H_R_value  *)value)->r_value_type       = R_CON_VALUE;
		   ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;
		}
		else if( l_value.r_value_type == R_CON_VALUE )
		{  
// HHui Fixme : 左操作数(  被移动数)   为常数，右操作数为Expr( number to shift right ! )   的情况----  扩展为32  bit 
		    /*
		    bits_num = vc_getBVLength( hvc, 
					       ( l_value.r_value ).expression
					     );
			
		    if( r_value.r_value_bits_size <= bits_num )
		    {
		        bits_num = r_value.r_value_bits_size;
		    }// end of if( )
 		    */		
		    tmp_expr1 = vc_bvConstExprFromInt( hvc,
						       // l_value.r_value_bits_size,
						       32,
						       l_value.r_value.value
						     );

		    if( 32 != r_value.r_value_bits_size )
		    {
		        tmp_expr2 = vc_bvVar32RightShiftExpr( hvc, 
						              vc_bvSignExtend( hvc,
									       (r_value.r_value).expression,
									       32
									     ),
							      tmp_expr1
	    			  		            ); 
		    }
		    else
		    {
			tmp_expr2 = vc_bvVar32RightShiftExpr( hvc,
							      (r_value.r_value).expression,
							      tmp_expr1
							    );
		    }// end of if( )

		    vc_DeleteExpr(tmp_expr1);

		    bitno_low  = 0;
		    bitno_high = l_value.r_value_bits_size - 1;

		    if( 32 != l_value.r_value_bits_size )
		    {
		        ( ( (H_R_value  *)value)->r_value ).expression = vc_bvExtract( hvc,
										       tmp_expr2,
										       bitno_high,
										       bitno_low
										     );
			vc_DeleteExpr(tmp_expr2);
		    }
		    else
		    {
			( ( (H_R_value  *)value)->r_value ).expression = tmp_expr2;
		    }// end of if( )

		    ( (H_R_value  *)value)->r_value_type       = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;

		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "RSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		     */
		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )


		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    /*
 ----------------------------------------------------------------------------------------------------- */ // just for debugging !
		}
		else if( r_value.r_value_type == R_CON_VALUE )
		{
		// 右移位数为具体值的情况
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvRightShiftExpr( hvc,
											 (r_value.r_value).value, // right 移的位数
		   									 (l_value.r_value).expression
		    									);
		    ( (H_R_value  *)value)->r_value_type       = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;

		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "RSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		     */

		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )


		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		    /* ----------------------------------------------------------------------------------------------------- */ // just for debugging !

		}
		else
		{
		// 两者皆为符号操作数的情况，扩展为32 bit
		    if( 32 != r_value.r_value_bits_size )
		    {
		        tmp_expr1 = vc_bvSignExtend( hvc,
						     (r_value.r_value).expression,
						     32
						   );
		    }
		    else
		    {
			tmp_expr1 = (r_value.r_value).expression;
		    }// end of if( )

		    if( 32 != l_value.r_value_bits_size )
		    {
		        tmp_expr2 = vc_bvSignExtend( hvc,
						     (l_value.r_value).expression,
						     32
						   );
		    }
		    else
		    {
			tmp_expr2 = (l_value.r_value).expression;
		    }// end of if( )

		    tmp_expr = vc_bvVar32RightShiftExpr( hvc,
						         tmp_expr1,
							 tmp_expr2
						       ); 

		    if(tmp_expr1 != (r_value.r_value).expression)
		    {
		        vc_DeleteExpr(tmp_expr1);
		    }// end of if(tmp_expr1)

		    if(tmp_expr2 != (l_value.r_value).expression)
		    {
		        vc_DeleteExpr(tmp_expr2);
		    }// end of if(tmp_expr2)

		    bitno_low  = 0;
		    bitno_high = l_value.r_value_bits_size - 1;

		    if( 32 != l_value.r_value_bits_size )
		    {
		        ( ( (H_R_value  *)value)->r_value ).expression = vc_bvExtract( hvc,
										       tmp_expr,
										       bitno_high,
										       bitno_low
										     );
		        vc_DeleteExpr(tmp_expr);
		    }
		    else
		    {
			( ( (H_R_value  *)value)->r_value ).expression = tmp_expr;
		    }// end of if( )

		    ( (H_R_value  *)value )->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;

		    // just for debugging !
		    /* ----------------------------------------------------------------------------------------------------- */
		    temp_debug_len = vc_getBVLength( hvc,
						     ( ( (H_R_value  *)value)->r_value ).expression
						   );
		    /*
		    H_term_printf( "RSHIFT_final_length = %d\n",
				   temp_debug_len
				 );
		     */

		    if(temp_debug_len != l_value.r_value_bits_size)
		    {
			temp_debug_ptr = NULL;    
			temp_debug_ptr[0] = 1;
		    }// end of if( )

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    /* ----------------------------------------------------------------------------------------------------- */ // just for debugging !

		}// end of if( )		

		// H_term_printf("- ARITHMETIC RIGHT SHIFT ! - ");
		
		break;
	}
	case LROTATE:
	{
		// H_term_printf("- LEFT_ROTATE - ");
		break;
	}
	case RROTATE:
	{
		// H_term_printf("- RIGHT_ROTATE - ");
		break;
	}
	case LOGICAND:
	{
	/*
		Expr vc_trueExpr(VC vc); 
	 	Expr vc_falseExpr(VC vc); 
	 	Expr vc_notExpr(VC vc, Expr child); 
	 	Expr vc_andExpr(VC vc, Expr left, Expr right); 
	 	Expr vc_andExprN(VC vc, Expr* children, int numOfChildNodes); 
	 	Expr vc_orExprN(VC vc, Expr* children, int numOfChildNodes); 
	 	Expr vc_impliesExpr(VC vc, Expr hyp, Expr conc); 
	 	Expr vc_iffExpr(VC vc, Expr left, Expr right); 
	  */
	  	if( ( l_value.r_value_type == R_CON_VALUE ) &&
	            ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = (l_value.r_value).value  &&  (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (l_value.r_value).value
						     );
		    		    			    
		    tmp_expr2 = vc_andExpr( hvc,
					    tmp_expr1,
					    (r_value.r_value).expression
					  );
		    vc_DeleteExpr(tmp_expr1);

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
									       	    ); 
		    vc_DeleteExpr(tmp_expr2);

		    ( (H_R_value  *)value)->r_value_type  = R_SYM_EXPRESSION;

		    ( (H_R_value  *)value)->r_value_bits_size = 1;	

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );
		    		    			    
		    tmp_expr2 = vc_andExpr( hvc,
				            (l_value.r_value).expression,
    					    tmp_expr1
					  );
		    vc_DeleteExpr(tmp_expr1);

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    ); 
		    vc_DeleteExpr(tmp_expr2);

		    ( (H_R_value  *)value)->r_value_type  = R_SYM_EXPRESSION;

		    ( (H_R_value  *)value)->r_value_bits_size = 1;	

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    tmp_expr = vc_andExpr( hvc,
					   (l_value.r_value).expression,
					   (r_value.r_value).expression
					 );

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr
										     );
		    vc_DeleteExpr(tmp_expr); 

		    ( (H_R_value  *)value)->r_value_type  = R_SYM_EXPRESSION;

		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		
		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 

		break;
	}
	case LOGICOR:
	{
		// Expr vc_orExpr(VC vc, Expr left, Expr right); 
	  	if( ( l_value.r_value_type == R_CON_VALUE ) &&
	            ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value	= (l_value.r_value).value  || (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type 	= R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size   = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (l_value.r_value).value
						     );
		    tmp_expr2 = vc_orExpr( hvc,
					   tmp_expr1, 
					   (r_value.r_value).expression
					 );		    			   
		    vc_DeleteExpr(tmp_expr1);
 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    ); 
		    vc_DeleteExpr(tmp_expr2);

		    ( (H_R_value  *)value)->r_value_type  = R_SYM_EXPRESSION;

		    ( (H_R_value  *)value)->r_value_bits_size   = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif			
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );
		    tmp_expr2 = vc_orExpr( hvc,
					   (l_value.r_value).expression,	 	
					   tmp_expr1
					 );
		    vc_DeleteExpr(tmp_expr1);

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
					 				      	    ); 
		    vc_DeleteExpr(tmp_expr2);

		    ( (H_R_value  *)value)->r_value_type  = R_SYM_EXPRESSION;					

		    ( (H_R_value  *)value)->r_value_bits_size   = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    tmp_expr = vc_orExpr( hvc,
					  (l_value.r_value).expression,
					  (r_value.r_value).expression
			 		);

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr
										    ); 
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;			

		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		
		}// end of if( ) 
		
		break;
	}
	case BITAND:  // & , not '&&'
	{
	// 按位AND
		/*
 	 Expr vc_bvAndExpr(VC vc, Expr left, Expr right); 
 	 Expr vc_bvNotExpr(VC vc, Expr child); 
	 	  */

	  	if( ( l_value.r_value_type == R_CON_VALUE ) &&
	            ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value	= (l_value.r_value).value  & (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type 	= R_CON_VALUE;

		    ( (H_R_value  *)value)->r_value_bits_size   = l_value.r_value_bits_size;
		    // ( (H_R_value  *)value)->r_value_bits_size   = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (l_value.r_value).value
						    );
		    	    		    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvAndExpr( hvc,
										   tmp_expr, 
										   (r_value.r_value).expression
										 ); 

		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    /*
		    H_term_printf( "left bits_num = %d, right value = %d\n",
				   bits_num,
				   (r_value.r_value).value
				 );
		     */

		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (r_value.r_value).value
						    );
		    		    			    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvAndExpr( hvc, 										   (l_value.r_value).expression,
										   tmp_expr
										 );
		    vc_DeleteExpr(tmp_expr);
 
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;		
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    char * t_ptr = NULL;
		    /*

		    t_ptr = typeString( vc_getType( hvc,
						    (l_value.r_value).expression
						  )
				      );
		    H_term_printf( "left type is %s --- ",
				   (char *)t_ptr
				 );
		    free(t_ptr);
		     */

		    /*
		    t_ptr = typeString( vc_getType( hvc,
						    (r_value.r_value).expression
						  )
				      );
		    
		    H_term_printf( "right type is %s --- ",
				   (char *)t_ptr
				 );
		    free(t_ptr);
		    */
		    if( vc_getBVLength( hvc, 
				 	(l_value.r_value).expression
				      ) != 
			vc_getBVLength( hvc, 
				 	(r_value.r_value).expression
				      )
		      )
		    {
			H_term_printf("fckk !\n");
			
			t_ptr    = NULL;
			t_ptr[0] = 0;
		    }// end of if( )
		    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvAndExpr( hvc,
										   (l_value.r_value).expression,
										   (r_value.r_value).expression
			 							 ); 
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;			
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 
	
		// H_term_printf("calculated !\n");

		break;
	}
	case BITOR: // '|' , not "||" !
	{
		// Expr vc_bvOrExpr(VC vc, Expr left, Expr right); 

	  	if( ( l_value.r_value_type == R_CON_VALUE ) &&
	            ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    // H_term_printf("CON or CON \n");

		    ( ( (H_R_value  *)value)->r_value ).value = (l_value.r_value).value  | (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    // H_term_printf("CON or SYM \n");

		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (l_value.r_value).value
						    );		    		    	
		    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvOrExpr( hvc,
										  tmp_expr, 
										  (r_value.r_value).expression
										); 
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
			
		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    // H_term_printf("SYM or CON \n");

		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (r_value.r_value).value
						    );		    		    			    

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvOrExpr(  hvc,
										   (l_value.r_value).expression,
										   tmp_expr
										); 
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    // H_term_printf("SYM or SYM \n");

		    // left 
		    /* ------------------------------------------------------------------------------------------ */
		    left_str = typeString( vc_getType( hvc,
						       l_value.r_value.expression
						     )
					 );		
		    /*
		    H_term_printf( "left is of type : %s\n",
				   left_str
			         );
		    */

		    if(strcmp(left_str, "BOOLEAN ") == 0)
		    {
			// left_typ = 1;
			tmp_expr1 = vc_boolToBVExpr( hvc,
						     (l_value.r_value).expression		
						   );
		    }
		    else
		    {
			tmp_expr1 = (l_value.r_value).expression;
		    }// end of if( )

		    free(left_str);
		    /* ------------------------------------------------------------------------------------------ */


		    // right 
		    /* ------------------------------------------------------------------------------------------ */
		    right_str = typeString( vc_getType( hvc,
						        r_value.r_value.expression
						     )
					 );		

		    /*
		    H_term_printf( "right is of type : %s\n",
				   right_str
			         );
		     */

		    if(strcmp(right_str, "BOOLEAN ") == 0)
		    {
			// left_typ = 1;
			 tmp_expr2 = vc_boolToBVExpr( hvc,
						      (r_value.r_value).expression
						    );
		    }
		    else
		    {
			tmp_expr2 = (r_value.r_value).expression;
		    }// end of if( )

		    free(right_str);
		    /* ------------------------------------------------------------------------------------------ */
		    

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvOrExpr( hvc,
										  tmp_expr1,
										  tmp_expr2
										); 
		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
			vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif

		    if(tmp_expr1 != (l_value.r_value).expression)
		    {
		        vc_DeleteExpr(tmp_expr1);
		    }// end of if(tmp_expr1)


		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0) 			
		    {
			vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(tmp_expr1)
		#endif

		    if(tmp_expr2 != (r_value.r_value).expression)
		    {
		        vc_DeleteExpr(tmp_expr2);
		    }// end of if(tmp_expr2)

		    /*
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvOrExpr( hvc,
										  (l_value.r_value).expression,
										  (r_value.r_value).expression
										); 
		    */
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    // ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
		
		}// end of if( ) 

		
		break;
	}
	case XOR:
	{
		// H_term_printf("XOR!\n");

		// Expr vc_bvXorExpr(VC vc, Expr left, Expr right); 

	  	if(  ( l_value.r_value_type == R_CON_VALUE ) &&
	             ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = (l_value.r_value).value  ^ (r_value.r_value).value;
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (l_value.r_value).value
						    );
		    			    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvXorExpr( hvc,
										   tmp_expr, 
										   (r_value.r_value).expression
										 ); 
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;
			
		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0) 
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (r_value.r_value).value
						    );
		    
		    ( (H_R_value  *)value)->r_value_bits_size	   = bits_num;		    	
		    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvXorExpr(  hvc,
										    (l_value.r_value).expression,
										    tmp_expr
										 ); 
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type  = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else
		{
/*
		    H_term_printf( "bitxor --- left(sym)[bits=%d][%s] --- right(sym)[bits=%d][%s]\n",
				   l_value.r_value_bits_size,
   				   exprString(l_value.r_value.expression),
				   r_value.r_value_bits_size,
   				   exprString(r_value.r_value.expression)
				 );
*/


/*
		    type_str = typeString( vc_getType( hvc,
								           sub_rval.r_value.expression
								   	 ) 
							     );
					// src-opnd sym-expression is of Type BOOLEAN , type length = 8


					if(strcmp(type_str, "BOOLEAN ") == 0)
					{
					    expr_is_bool = 1;
					}
					else
					{
					    expr_is_bool = 0;
					}// end of if( )

 */

		    // left 
		    /* ------------------------------------------------------------------------------------------ */
		    left_str = typeString( vc_getType( hvc,
						       l_value.r_value.expression
						     )
					 );	
/*	
		    H_term_printf( "left is of type : %s\n",
				   left_str
			         );
*/

		    if(strcmp(left_str, "BOOLEAN ") == 0)
		    {
			// left_typ = 1;
			tmp_expr1 = vc_boolToBVExpr( hvc,
						     (l_value.r_value).expression		
						   );
		    }
		    else
		    {
			tmp_expr1 = (l_value.r_value).expression;
		    }// end of if( )

		    free(left_str);
		    /* ------------------------------------------------------------------------------------------ */


		    
		    // right
		    /* ------------------------------------------------------------------------------------------ */
		    right_str = typeString( vc_getType( hvc,
						        r_value.r_value.expression
						      )
					  );
/*		
		    H_term_printf( "right is of type : %s\n",
				   right_str
			         );
*/

		    if(strcmp(right_str, "BOOLEAN ") == 0)
		    {
			// left_typ = 1;
			tmp_expr2 = vc_boolToBVExpr( hvc,
						     (r_value.r_value).expression		
						   );

		    }
		    else
		    {
			tmp_expr2 = (r_value.r_value).expression;
		    }// end of if( )

		    free(right_str);
		    /* ------------------------------------------------------------------------------------------ */

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvXorExpr( hvc,
										   tmp_expr1,
										   tmp_expr2
			 							 ); 		   
		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)		      
		    {
			vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.r_value)
		#endif

		    if( tmp_expr1 != (l_value.r_value).expression )
		    {
		        vc_DeleteExpr(tmp_expr1);
		    }// end of if(tmp_expr1)

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
			vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(tmp_expr1)
		#endif

		    if( tmp_expr2 != (r_value.r_value).expression )
		    {
		        vc_DeleteExpr(tmp_expr2);
		    }// end of if(tmp_expr2)

		    /*
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvXorExpr( hvc,
										   (l_value.r_value).expression,
										   (r_value.r_value).expression
			 							 ); 
		     */
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
		
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;



		}// end of if( ) 
		
		// H_term_printf("BVXOR_finished !\n");

		break;
	}
	case EQ:
	{
		// H_term_printf(" -- EQ -- \n");

		// Expr vc_eqExpr(VC vc, Expr child0, Expr child1); 
		// H_term_printf("Begin visiting EQUAL ! ---- ");

		// temply using vc_bvLtExpr(VC vc, Expr left, Expr right)
		/* ================================================================================================================================ */
		/*    Expr vc_bvLtExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvLtExpr(VC vc, Expr left, Expr right); 
		  */
				// Expr vc_bvXorExpr(VC vc, Expr left, Expr right); 

	  	if(  ( l_value.r_value_type == R_CON_VALUE ) &&
	             ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = ( (l_value.r_value).value )  ==
								( (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (l_value.r_value).value
						    );
		    		    			    
		    tmp_expr2 = vc_eqExpr( hvc,
					   tmp_expr1, 
					   (r_value.r_value).expression
					 ); 

		    vc_DeleteExpr(tmp_expr1);

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
			
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );
		    		    
		    tmp_expr2 = vc_eqExpr( hvc,
					   (l_value.r_value).expression,
					   tmp_expr1
					 );
 
		    vc_DeleteExpr(tmp_expr1);

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    if( vc_getBVLength( hvc,
					(l_value.r_value).expression 
				      ) != 
			vc_getBVLength( hvc,
					(r_value.r_value).expression 
				      )
		      )
		    {
			H_term_printf("fucking EQUAL !\n");			
			uint8_t * ptr = NULL;
			ptr[0] = 1;
			ptr[0] = ptr[0] / 0;
		    }// end of if( )

		    tmp_expr1 = vc_eqExpr( hvc,
					   (l_value.r_value).expression,
					   (r_value.r_value).expression
			 		 ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr1
										    );
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 

		// H_term_printf("Finish visit to EQUAL!\n");
		/* ================================================================================================================================ */
		
		// H_term_printf(" -- EQ ! -- \n");
		
		break;
	}
	case NEQ:
	{
		// Expr vc_eqExpr(VC vc, Expr child0, Expr child1); 		
		// Expr vc_notExpr(VC vc, Expr child); 

		// H_term_printf("Begin visiting NOT_EQ ! --- \n");

		// temply using vc_bvLtExpr(VC vc, Expr left, Expr right)
		/* ================================================================================================================================ */
		/*    Expr vc_bvLtExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvLtExpr(VC vc, Expr left, Expr right); 
		  */
				// Expr vc_bvXorExpr(VC vc, Expr left, Expr right); 

	  	if(  ( l_value.r_value_type == R_CON_VALUE ) &&
	             ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = ( (l_value.r_value).value )  !=
								( (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    /*
		    H_term_printf( " CON(--0x%x--) < > SYM(--0x%x--) \n",
				   l_value.r_value_bits_size,
				   r_value.r_value_bits_size
				 );
		     */

		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 

		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (l_value.r_value).value
						     );
		    		    			    
		    tmp_expr2 = vc_eqExpr( hvc,
					   tmp_expr1, 
					   (r_value.r_value).expression
					 );
	 	    
		    tmp_expr3 = vc_notExpr( hvc,
					    tmp_expr2
					  );
		  
		    // [0] == 0
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr3
										    );		
		    vc_DeleteExpr(tmp_expr3);
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);
							
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
			
		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    /*
		    H_term_printf( " SYM(--0x%x--) < > CON(--0x%x--) \n",
				   l_value.r_value_bits_size,
				   r_value.r_value_bits_size
				 );
		     */

		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );		    		    
		    tmp_expr2 = vc_eqExpr( hvc,
					   (l_value.r_value).expression,
					   tmp_expr1
					 );
		    
		    tmp_expr3 = vc_notExpr( hvc,
					    tmp_expr2
					  ); 
		     
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr3
										    );
		    vc_DeleteExpr(tmp_expr3);
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type       = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    /*
		    H_term_printf( " SYM(--0x%x--) < > SYM(--0x%x--) \n",
				   l_value.r_value_bits_size,
				   r_value.r_value_bits_size
				 );
		    */

		    if( vc_getBVLength( hvc,
					(l_value.r_value).expression
				      ) != 
			vc_getBVLength( hvc,
					(r_value.r_value).expression
				      )
		      )
		    {
			uint8_t * h_ptr = NULL;
			H_term_printf("fucking NEQ !\n");
			h_ptr[0] = 1;
		    }// end of if( )		    

		    tmp_expr1 = vc_eqExpr( hvc,
					   (l_value.r_value).expression,
					   (r_value.r_value).expression
				         );
		    tmp_expr2 = vc_notExpr( hvc,
					    tmp_expr1
			 		  ); 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 

		// H_term_printf("Finish visit to NOT_EQ!\n");
		/* ================================================================================================================================ */

		break;
	}
	case GT:
	{
		/*
		 	 Expr vc_bvGtExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvGtExpr(VC vc, Expr left, Expr right); 

		 */
/* HHui Fixme : temply not considering  ( unsigned GREAT_THAN ) VS ( signed GREAT_THAN) 
 */
		// H_term_printf("Begin visiting GREAT_THAN ! --- ");

		// temply using vc_bvLtExpr(VC vc, Expr left, Expr right)
		/* ================================================================================================================================ */
		/*    Expr vc_bvLtExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvLtExpr(VC vc, Expr left, Expr right); 
		  */
				// Expr vc_bvXorExpr(VC vc, Expr left, Expr right); 

	  	if(  ( l_value.r_value_type == R_CON_VALUE ) &&
	             ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = ( (l_value.r_value).value )  >
								( (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (l_value.r_value).value
						     );
		    		    			    
		    tmp_expr2 = vc_bvGtExpr( hvc,
					     tmp_expr1, 
					     (r_value.r_value).expression
					   ); 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
			
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );
		    		    
		    tmp_expr2 = vc_bvGtExpr(  hvc,
					      (l_value.r_value).expression,
					      tmp_expr1
					   );
 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    tmp_expr1 = vc_bvGtExpr( hvc,
					     (l_value.r_value).expression,
					     (r_value.r_value).expression
			 		   ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr1
										    );
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 

		// H_term_printf("Finish visit to GREAT_THAN!\n");
		/* ================================================================================================================================ */

	 	
		break;
	}
	case LT:
	{
/* HHui Fixme : temply not considering  ( unsigned LESS_THAN ) VS ( signed LESS_THAN) 
 */
		// H_term_printf("Begin visiting LESS_THAN ! --- ");

		// temply using vc_bvLtExpr(VC vc, Expr left, Expr right)
		/* ================================================================================================================================ */
		/*    Expr vc_bvLtExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvLtExpr(VC vc, Expr left, Expr right); 
		  */
				// Expr vc_bvXorExpr(VC vc, Expr left, Expr right); 

	  	if(  ( l_value.r_value_type == R_CON_VALUE ) &&
	             ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = ( (l_value.r_value).value )  <
								( (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (l_value.r_value).value
						     );
		    		    			    
		    tmp_expr2 = vc_bvLtExpr( hvc,
					     tmp_expr1, 
					     (r_value.r_value).expression
					   ); 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif			
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );		    		    
		    tmp_expr2 = vc_bvLtExpr( hvc,
					     (l_value.r_value).expression,
					     tmp_expr1
					   ); 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );

		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    tmp_expr1 = vc_bvLtExpr( hvc,
					     (l_value.r_value).expression,
					     (r_value.r_value).expression
			 		   ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr1
										    );
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 

		// H_term_printf("Finish visit to LESS_THAN!\n");
		/* ================================================================================================================================ */

		break;
	}
	case GE:
	{
		/*	 Expr vc_bvGeExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvGeExpr(VC vc, Expr left, Expr right); 		
		  */
/* HHui Fixme : temply not considering  ( unsigned GREAT_EQUAL ) VS ( signed GREAT_EQUAL ) 
 */
		// H_term_printf("Begin visiting GREAT_EQUAL ! --- ");

		// temply using vc_bvLtExpr(VC vc, Expr left, Expr right)
		/* ================================================================================================================================ */
		/*    Expr vc_bvLtExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvLtExpr(VC vc, Expr left, Expr right); 
		  */
				// Expr vc_bvXorExpr(VC vc, Expr left, Expr right); 

	  	if(  ( l_value.r_value_type == R_CON_VALUE ) &&
	             ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = ( (l_value.r_value).value )  >=
								( (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (l_value.r_value).value
						     );		    		    			    
		    tmp_expr2 = vc_bvGeExpr( hvc,
					     tmp_expr1, 
					     (r_value.r_value).expression
					   ); 

		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif			
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );
		    		    
		    tmp_expr2 = vc_bvGeExpr( hvc,
					     (l_value.r_value).expression,
					     tmp_expr1
					   ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );

		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    tmp_expr1 = vc_bvGeExpr( hvc,
					     (l_value.r_value).expression,
					     (r_value.r_value).expression
			 		   ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr1
										    );

		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 

		// H_term_printf("Finish visit to GREAT_EQUAL\n");
		/* ================================================================================================================================ */


		break;
	}
	case LE:
	{
		/*
		 	 Expr vc_bvLeExpr(VC vc, Expr left, Expr right); 		
		 	 Expr vc_sbvLeExpr(VC vc, Expr left, Expr right);		 	 
		  */
/* HHui Fixme : temply not considering  ( unsigned LESS_EQUAL ) VS ( signed LESS_EQUAL ) 
 */
		// H_term_printf("Begin visiting LESS_EQUAL ! --- ");

		// temply using vc_bvLtExpr(VC vc, Expr left, Expr right)
		/* ================================================================================================================================ */
		/*    Expr vc_bvLtExpr(VC vc, Expr left, Expr right); 
		 	 Expr vc_sbvLtExpr(VC vc, Expr left, Expr right); 
		  */
				// Expr vc_bvXorExpr(VC vc, Expr left, Expr right); 

	  	if(  ( l_value.r_value_type == R_CON_VALUE ) &&
	             ( r_value.r_value_type == R_CON_VALUE )
	         )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value = ( (l_value.r_value).value )  <=
								( (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type      = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    			 	       bits_num, 
						       (l_value.r_value).value
						     );
		    		    			    
		    tmp_expr2 = vc_bvLtExpr( hvc,
					     tmp_expr1, 
					     (r_value.r_value).expression
					   ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif			
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr1 = vc_bvConstExprFromInt( hvc, 
		    				       bits_num, 
						       (r_value.r_value).value
						     );
		    		    
		    tmp_expr2 = vc_bvLtExpr( hvc,
					     (l_value.r_value).expression,
					     tmp_expr1
					   ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr2
										    );
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    tmp_expr = vc_bvLtExpr( hvc,
					    (l_value.r_value).expression,
					    (r_value.r_value).expression
			 		  ); 
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
										      tmp_expr
										    );
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;	
		    ( (H_R_value  *)value)->r_value_bits_size = 1;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}// end of if( ) 

		// H_term_printf("Finish visit to LESS_EQUAL\n");
		/* ================================================================================================================================ */

		break;
	}
  	case SDIVIDE:
	{
		/* signed left divided by right i.e. left/right 
		
		 	Expr vc_sbvDivExpr(VC vc, int n_bits, Expr left, Expr right);  	  	 
		  */
		/* ================================================================================================================================ */
	  	if( ( l_value.r_value_type == R_CON_VALUE ) &&
	            ( r_value.r_value_type == R_CON_VALUE )
	          )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value  = (signed long)( (l_value.r_value).value  / (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type       = R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size  = l_value.r_value_bits_size;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (l_value.r_value).value
						    );
		    		    			    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_sbvDivExpr( hvc,
										    bits_num,
										    tmp_expr, 
										    (r_value.r_value).expression
										  );
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num; // r_value.r_value_bits_size;

		    // right-value is symbolic, so checks for DIV-BY-0
		    /* ------------------------------------------------------------ */
		    tmp_expr1 = vc_bvConstExprFromInt( hvc,
						       bits_num,
						       0
						     );
		    tmp_expr2 = vc_eqExpr( hvc,
					   tmp_expr1,
					   ( r_value.r_value ).expression
					 );
		    tmp_expr3 = vc_andExpr( hvc,
					    *HHui_current_path_expr,
					    tmp_expr2					    
					  );
		    tmp_expr4 = vc_notExpr( hvc,
					    tmp_expr3
					  );
		    vc_push(hvc);
		    
		    qresult = vc_query( hvc,
					tmp_expr4
				      );
		    if(qresult == 0)
		    {
			record_ERROR_2file( tmp_expr3,
					    5 // err_id
					  );			
		    #ifdef H_VULSCAN_ONCE_ENOUGH
		        *H_vulscan_once_enough_err_found = 1;
		    #endif

		    vc_pop(hvc);

		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		    }// end of if(qresult)
		
		    vc_DeleteExpr(tmp_expr4);
		    vc_DeleteExpr(tmp_expr3);
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);

		    /* ------------------------------------------------------------ */

		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (r_value.r_value).value
						    );
		    		    			    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_sbvDivExpr( hvc,
										    bits_num,
										    (l_value.r_value).expression,
										    tmp_expr
										  );
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num; // l_value.r_value_bits_size;

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_sbvDivExpr( hvc,
										    l_value.r_value_bits_size,
										    (l_value.r_value).expression,
										    (r_value.r_value).expression
			 							  ); 
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;

		    // right-value is symbolic, so checks for DIV-BY-0
		    /* ------------------------------------------------------------ */
		    tmp_expr1 = vc_bvConstExprFromInt( hvc,
						       r_value.r_value_bits_size,
						       0
						     );
		    tmp_expr2 = vc_eqExpr( hvc,
					   tmp_expr1,
					   ( r_value.r_value ).expression
					 );
		    tmp_expr3 = vc_andExpr( hvc,
					    *HHui_current_path_expr,
					    tmp_expr2					    
					  );
		    tmp_expr4 = vc_notExpr( hvc,
					    tmp_expr3
					  );
		    vc_push(hvc);
		    
		    qresult = vc_query( hvc,
					tmp_expr4
				      );
		    if(qresult == 0)
		    {
			record_ERROR_2file( tmp_expr3,
					    5 // err_id
					  );			
		    #ifdef H_VULSCAN_ONCE_ENOUGH
			*H_vulscan_once_enough_err_found = 1;
		    #endif
		    }// end of if(qresult)

		    vc_pop(hvc);


		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		    vc_DeleteExpr(tmp_expr4);
		    vc_DeleteExpr(tmp_expr3);
		    vc_DeleteExpr(tmp_expr2);
		    vc_DeleteExpr(tmp_expr1);
		    /* ------------------------------------------------------------ */		
		}// end of if( ) 		
		/* ================================================================================================================================ */

		break;
  	}
  	case SMOD:
	{
		/*  	signed left modulo right i.e. left%right 

		 	 Expr vc_sbvModExpr(VC vc, int n_bits, Expr left, Expr right); 
		  */
		/* ================================================================================================================================ */
	  	if( ( l_value.r_value_type == R_CON_VALUE ) &&
	            ( r_value.r_value_type == R_CON_VALUE )
	          )	
		{
		    ( ( (H_R_value  *)value)->r_value ).value	= (signed long)( (l_value.r_value).value  % (r_value.r_value).value );
		   
		    ( (H_R_value  *)value)->r_value_type 	= R_CON_VALUE;
		    ( (H_R_value  *)value)->r_value_bits_size   = l_value.r_value_bits_size;
		}
		else if( l_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (r_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (l_value.r_value).value
						    );
		    		    			    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_sbvModExpr( hvc,
									    	    bits_num,
										    tmp_expr, 
										    (r_value.r_value).expression
										  );
		    vc_DeleteExpr(tmp_expr);
 
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num; // r_value.r_value_bits_size;
			
		#ifdef H_DELETE_OPRND_EXPR
		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif
		}
		else if( r_value.r_value_type == R_CON_VALUE ) 
		{
		    bits_num = vc_getBVLength( hvc, 
					       (l_value.r_value).expression
					     ); 
		    // Expr vc_bvConstExprFromInt(VC vc, int n_bits, unsigned int value); 
		    tmp_expr = vc_bvConstExprFromInt( hvc, 
		    				      bits_num, 
						      (r_value.r_value).value
						    );
		    		    			    
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_sbvModExpr( hvc,
										       bits_num,
										       (l_value.r_value).expression,
										       tmp_expr
										     ); 
		    vc_DeleteExpr(tmp_expr);

		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;		
		    ( (H_R_value  *)value)->r_value_bits_size = bits_num; // l_value.r_value_bits_size;			

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)
		#endif
		}
		else
		{
		    ( ( (H_R_value  *)value)->r_value ).expression = vc_sbvModExpr( hvc,
										    l_value.r_value_bits_size,
										    (l_value.r_value).expression,
										    (r_value.r_value).expression
			 							  ); 
		    ( (H_R_value  *)value)->r_value_type      = R_SYM_EXPRESSION;			
		    ( (H_R_value  *)value)->r_value_bits_size = l_value.r_value_bits_size;		

		#ifdef H_DELETE_OPRND_EXPR
		    if(l_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((l_value.r_value).expression);
		    }// end of if(l_value.is_meta_sym_byte)

		    if(r_value.is_meta_sym_byte == 0)
		    {
		        vc_DeleteExpr((r_value.r_value).expression);
		    }// end of if(r_value.is_meta_sym_byte)
		#endif

		}// end of if( ) 		
		 /* ================================================================================================================================ */

		break;
  	}
    }// end of switch{ }
	
    ( (H_R_value  *)value)->is_meta_sym_byte = 0;
}// end of BinOp::abstract_value_evaluate( )



void BinOp:: R_value_calculate( HVC    hvc, char *  value )
{
	BinOp:: L_value_calculate( hvc, value );
}// end of BinOp:: R_value_calculate( HVC    hvc, char *  value )

	


BinOp::BinOp(binop_type_t t, Exp *l, Exp *r) 
  : Exp(BINOP), lhs(l), rhs(r), binop_type(t)
{ 

}

BinOp::BinOp(const BinOp& copy)
  : Exp(BINOP), binop_type(copy.binop_type)
{
  lhs = copy.lhs->clone();
  rhs = copy.rhs->clone();
}

BinOp *
BinOp::clone() const
{
  return new BinOp(*this);
}

string
BinOp::tostring() const
{
  string ret;

  /*
  H_term_printf( "BinOP type : %s\n",
		 strs[binop_type].c_str( )
	       );
  */
  ret =  lhs->tostring() + strs[binop_type] + rhs->tostring();

  /*
  H_term_printf( "left is : %s\n",
		 lhs->tostring( ).c_str( )
	       );

  H_term_printf( "right is : %s\n",
		 lhs->tostring( ).c_str( )
	       );
  */
  ret = "(" + ret + ")";
  return ret;
}

string
BinOp::optype_to_string(const binop_type_t binop_type)
{
  return strs[binop_type];
}

string
BinOp::optype_to_name(const binop_type_t binop_type)
{
  return binopnames[binop_type];
}

binop_type_t
BinOp::string_to_optype(const string s)
{
  for(unsigned i = 0; i < sizeof(strs); i++){
    if(strs[i] == s)
      return (binop_type_t) i;
  }
  assert(1 == 0);
  return (binop_type_t) 0;
}

void BinOp::destroy( BinOp *expr )
{
    assert(expr);

    Exp::destroy(expr->lhs);
    Exp::destroy(expr->rhs);

    delete expr;
}
/* ===================================================================== */ // BinOP




 // UNOP
/* ===================================================================== */
void  UnOp:: L_value_calculate( HVC    hvc, char *  value )
{
	/*
		typedef struct H_R_VALUE
		{
		    R_value_t  		r_value;
		    R_exp_value_t	r_value_type;
		    uint32_t		r_value_bits_size;	
		}H_R_value;
	  */
	H_R_value  r_value;
	r_value.is_meta_sym_byte = 0;

        HExpr tmp_expr1 = NULL;
	HExpr tmp_expr2 = NULL;
	HExpr tmp_expr3 = NULL;
	
	exp->R_value_calculate( hvc,
				(char *)( &r_value )
			      );

	HType  temp_type   = NULL;
	char * str_temp_tp = NULL;

	switch(unop_type)
	{
		case NEG:
		{
		// 取负
			if( r_value.r_value_type == R_CON_VALUE )
			{
			    ( ( (H_R_value  *)value)->r_value ).value	= -((r_value.r_value).value) ;
			   
			    ( (H_R_value  *)value)->r_value_type 	= R_CON_VALUE;
			    ( (H_R_value  *)value)->r_value_bits_size   = r_value.r_value_bits_size;
			}
			else
			{
			    // 符号值!
			    /*   Expr vc_bvUMinusExpr(VC vc, Expr child);   */
			    ( ( (H_R_value  *)value)->r_value ).expression = vc_bvUMinusExpr( hvc, 
											     (r_value.r_value).expression
											    );
			    ( (H_R_value  *)value)->r_value_type 	= R_SYM_EXPRESSION;
			    ( (H_R_value  *)value)->r_value_bits_size   = r_value.r_value_bits_size;
			}// end of if( )
			
			break;
		}
		case NOT:
		{
		// 取反		
			if( r_value.r_value_type == R_CON_VALUE )
			{
			    ( ( (H_R_value  *)value)->r_value ).value	= -((r_value.r_value).value) ;
			   
			    ( (H_R_value  *)value)->r_value_type 	= R_CON_VALUE;
			    ( (H_R_value  *)value)->r_value_bits_size   = r_value.r_value_bits_size;
			    // ( (H_R_value  *)value)->r_value_bits_size   = 1;	
			}
			else
			{
			    // 符号值!
			    /*  Expr vc_notExpr(VC vc, Expr child);   */

			    temp_type  = vc_getType( hvc,
						     (r_value.r_value).expression
						   );

			    str_temp_tp = typeString(temp_type);

			    if( strcmp( "BOOLEAN ", 
					str_temp_tp
				      ) == 0
			      )
			    {
				( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
											      	  vc_notExpr( hvc, 		    														      (r_value.r_value).expression
													    )
			    							       	        );
				( (H_R_value  *)value)->r_value_bits_size = 1;
			    }
			    else
			    {
				( ( (H_R_value  *)value)->r_value ).expression = vc_bvNotExpr( hvc,
											       (r_value.r_value).expression
											     );
				( (H_R_value  *)value)->r_value_bits_size   = r_value.r_value_bits_size;
			    }// end of if( )

			    free(str_temp_tp);
/*	
			    ( ( (H_R_value  *)value)->r_value ).expression = vc_boolToBVExpr( hvc,
											      vc_notExpr( hvc, 		    														  (r_value.r_value).expression
													)
			    							       	    );
 */
			    ( (H_R_value  *)value)->r_value_type 	= R_SYM_EXPRESSION;
			}// end of if( )
			
			break;
		}
	}// end of switch{ }

    #ifdef H_DELETE_OPRND_EXPR
	if(r_value.r_value_type == R_SYM_EXPRESSION)
	{
	    if(r_value.is_meta_sym_byte == 0)
	    {
	        vc_DeleteExpr((r_value.r_value).expression);
	    }// end of if(r_value.is_meta_sym_byte)
	}// end of if(r_value.r_value_type)
    #endif

   ( (H_R_value  *)value)->is_meta_sym_byte = 0;

}// end of UnOp:: L_value_calculate( )


void UnOp:: R_value_calculate( HVC    hvc, char *  value)
{
	L_value_calculate( hvc, value );	
	
}// end of UnOp:: R_value_calculate( )




UnOp::UnOp(const UnOp& copy)
  : Exp(UNOP), unop_type(copy.unop_type)
{
  exp = copy.exp->clone();
}

UnOp::UnOp(unop_type_t typ, Exp *e)  
  : Exp(UNOP), unop_type(typ), exp(e)
{ 
}

UnOp *
UnOp::clone() const
{
  return new UnOp(*this);
}


string
UnOp::tostring() const
{
   string ret;
   switch(unop_type){
   case NEG:
     ret = "-" + exp->tostring();
    break;
   case NOT:
     ret = "!" + exp->tostring();
     break;
   }
   ret = "(" + ret + ")";
   return ret;
}

string
UnOp::optype_to_string(const unop_type_t op)
{
  // Do NOT change this. It is used in producing XML output.
  string ret;
  switch(op){
  case NEG:
    ret = "NEG"; break;
  case NOT:
    ret = "NOT"; break;
  }
  return ret;
}

unop_type_t
UnOp::string_to_optype(const string s)
{
  if(s == "NEG") return NEG;
  if(s == "NOT") return NOT;
  assert(1 == 0);
  return NEG;
}

void UnOp::destroy( UnOp *expr )
{
    assert(expr);

    Exp::destroy(expr->exp);

    delete expr;
}
/* ===================================================================== */ // UnOP




/*
Mem::Mem(Exp *a)
  : Exp(MEM), addr(a)
{
  typ = REG_ADDRESS_T;
}
*/

// MEM   作为左值的计算
/* ===================================================================== */
void  Mem:: L_value_calculate( HVC    hvc, char *  value)
{
	/*   Exp *addr;
	      reg_t typ;
	  */
	// H_L_value  addr_l_value ;
	H_R_value  addr_r_value ;

	// addr's R_value would be the L_Value of Mem !
	addr->R_value_calculate( hvc, 
				 (char *)&addr_r_value
			       ); 

	int mem_size = 0 ;

	/* enum reg_t { REG_1, REG_8, REG_16, REG_32, REG_64 }; */
	switch(typ)
	{
		case REG_1:
		{
			break;
		}
		case REG_8:
		{
			mem_size = 1;
			break;
		}
		case REG_16:
		{
			mem_size = 2;
			break;
		}
		case REG_32:
		{
			mem_size = 4;
			break;
		}
		case REG_64:
		{
			mem_size = 8;
			break;
		}
	}// end of switch{ }

	// final L_Value type for 'Mem' !	
	/* ----------------------------------------------------------------------------------------- */
	if( addr_r_value.r_value_type == R_CON_VALUE )
	{
	// concrete address !
		( (H_L_value *)value )->l_value_type  	      = L_MEM_ADDRESS;
		( (H_L_value *)value )->l_value_bits_size     = mem_size * 8;
		( ( (H_L_value *)value )->l_value ).m_address = addr_r_value.r_value.value;
	}
	else
	{
	// symbolic address !
		// final L_Value type for 'Mem' !
		H_term_printf("symbolic address !\n");
		
		( (H_L_value *)value )->l_value_type  	          = L_MEM_ADDRESS_SYM;
		( (H_L_value *)value )->l_value_bits_size         = addr_r_value.r_value_bits_size;
		( ( (H_L_value *)value )->l_value ).m_sym_address = addr_r_value.r_value.expression;
	}// end of if( )
	/* ----------------------------------------------------------------------------------------- */

}// end of Mem:: L_value_calculate( )



// MEM   作为右值的计算
void Mem:: R_value_calculate( HVC    hvc, char *  value)
{
	
	H_R_value  addr_r_value ;
	char * 	   name = NULL;
		
	// addr   作为地址值的左值计算
	addr->R_value_calculate( hvc, 
				 (char *)&addr_r_value
			       );
	
	( (H_R_value *)value )->is_meta_sym_byte = 0; 

	string 	opname       	  = "";
	uint64_t   taint_bitmap  = 0;


	H_taint_record_t * records = NULL;
	
	
	int size = 0 ;


	uint32_t  addr_value  = 0 ;

	HExpr     oprnd_expr  = NULL;
	HExpr 	  temp_expr   = NULL;

	char *  tmp_error_str = NULL;

	uint32_t  oprnd_value = 0;
	int i = 0 ;

	int reg_index = -1;


	int qresult = 0;
	HExpr invalid_constraint_exprs[3];
	invalid_constraint_exprs[0] = NULL;
	invalid_constraint_exprs[1] = NULL;
	invalid_constraint_exprs[2] = NULL;

	int	   correct_concrete_addrs_count	 = 0;
	uint32_t * correct_concrete_addrs_values = NULL;
        HExpr *    symaddr_correct_concrete_addrs_constraints = NULL;

	HExpr	   tmp_expr1 = NULL;
	HExpr	   tmp_expr2 = NULL;
	HExpr	   tmp_expr3 = NULL;
	HExpr	   tmp_expr4 = NULL;

/*	
int hvc_symaddr_solve( HVC         hvc,
		       HExpr *     path_expr,
		       HExpr       symaddr_expr,
		       int         access_mode,      	 // 1 -- read; 2 -- write; 4 -- execute 
		       HExpr *     invalid_constraint_exprs, // 2 elements' array holding ERRORs' constraints !
		       uint32_t ** correct_concrete_addrs_values,
		       HExpr **    symaddr_correct_concrete_addrs_constraints,
		       int	*  correct_concrete_addrs_count
		     )
*/
	
	switch(typ)
        {
	    case REG_8:
	    {
		size = 1;
		break;
	    }
	    case REG_16:
	    {
		size = 2;
		break;
	    }
	    case REG_32:
	    {
		size = 4;
		break;
	    }
	    case REG_64:
	    {
		size = 8;
		break;
	    }
	}// end of switch{ }

        /*
        H_term_printf( "malloc( ) for taint-records : size = %d\n",
		       sizeof(H_taint_record_t ) * size
		     );
	 */

	records = (H_taint_record_t *)malloc( sizeof(H_taint_record_t ) * size
								      // (addr_l_value.l_value_bits_size / 8)
					    );

	H_R_VALUE * temp_r_value;

	switch(addr_r_value.r_value_type)
	{
		case R_CON_VALUE:
		{	
			// H_term_printf("concrete address !\n");

		// concrete memory addressing !
			addr_value = addr_r_value.r_value.value;			
			break;
		}
		case R_SYM_EXPRESSION:
		{
			// H_term_printf("symbolic address !\n");

		// symbolic memory-addressing-READing !
		/* --------------------------------------------------------------------------------- */
		       qresult = hvc_symaddr_solve( hvc,
						    HHui_current_path_expr,
						    addr_r_value.r_value.expression,
						    1,      	      	      // 1 -- read; 2 -- write; 4 -- execute 
						    invalid_constraint_exprs, // 3 elements' array holding ERRORs' constraints !
						    &correct_concrete_addrs_values,
		       				    &symaddr_correct_concrete_addrs_constraints,
						    &correct_concrete_addrs_count
		       				  );

		       if(qresult == 1)
		       {
			   H_term_printf( "We've found an ERROR !\n");
			
/* ----------------------------------------------------------------------------------------------------------------------------------------------------------- */
			   // OUT-OF_RANGE expr !
			   if(invalid_constraint_exprs[0] != NULL)
			   {
			       temp_expr = vc_andExpr( hvc,
						       *HHui_current_path_expr,
						       invalid_constraint_exprs[0]
						     );			       
			       record_ERROR_2file( temp_expr,
						   3 // err_id
						 );
			       vc_DeleteExpr(temp_expr);

			    /*
			       temp_expr = vc_notExpr( hvc,
				                       invalid_constraint_exprs[0]
						     );								       
			    #ifdef H_DEBUG_TEST
			       if(H_predicate_change != NULL)
			       {
				   H_predicate_change( hvc,
						       temp_expr,
						       *HHui_current_path_expr,
						       vc_andExpr( hvc,
								   *HHui_current_path_expr,
								   temp_expr
								 )						       
						     );
			       }// end of if(H_predicate_change)
			    #endif
			       *HHui_current_path_expr = vc_andExpr( hvc,
								     *HHui_current_path_expr,
								     temp_expr
								   );
				vc_DeleteExpr(temp_expr);
			    */
			    }// end of if( )

			    // INVALID-ACCESS expr !
			    if(invalid_constraint_exprs[1] != NULL)
			    {				
			       temp_expr = vc_andExpr( hvc,
						       *HHui_current_path_expr,
						       invalid_constraint_exprs[1]
						     );			      
				
			       record_ERROR_2file( temp_expr,
						   4 // err_id
						 );
			       vc_DeleteExpr(temp_expr);

			    /*
			       temp_expr = vc_notExpr( hvc,
						       invalid_constraint_exprs[1]
						     );								    
			    #ifdef H_DEBUG_TEST
			       if(H_predicate_change != NULL)
			       {
				   H_predicate_change( hvc,
						       temp_expr,
						       *HHui_current_path_expr,
						       vc_andExpr( hvc,
								   *HHui_current_path_expr,
								   temp_expr
								 )						       
						     );
			       }// end of if(H_predicate_change)
			    #endif
				*HHui_current_path_expr = vc_andExpr( hvc,
								      *HHui_current_path_expr,
								      temp_expr
								    );
				vc_DeleteExpr(temp_expr);
			    */
			    }// end of if( )   
				
			#ifdef H_VULSCAN_ONCE_ENOUGH
			    *H_vulscan_once_enough_err_found = 1;
			    return;				    
			#endif

			for(i = 0; i < 3; i = i + 1)
			{
			    if(invalid_constraint_exprs[i] != NULL)
			    {
				vc_DeleteExpr(invalid_constraint_exprs[i]);
			    }// end of if(invalid_constraint_exprs[i])
			}// end of for{i}
/* ----------------------------------------------------------------------------------------------------------------------------------------------------------- */
		       }
		       else
		       {
			   H_term_printf( "1111111111111111111111111 ----- correct_concrete_addrs_count = %d!\n",
					  correct_concrete_addrs_count
					);

/*
HExpr symaddr_reading_expr_formulate( HVC        hvc,
				      uint32_t * symaddr_corect_concrete_addrs_values, 
				      HExpr *    symaddr_correct_concrete_addrs_constraints,
				      int        correct_concrete_addrs_count,
				      int        data_length,
				      char *     records
				    )
 */
			   ( ( (H_R_value *)value )->r_value).expression = 
						symaddr_reading_expr_formulate( hvc,
										correct_concrete_addrs_values,
								                symaddr_correct_concrete_addrs_constraints, 
									 	correct_concrete_addrs_count,
										size,
										(char *)records
							  		      );
			   ( (H_R_value *)value )->r_value_type          = R_SYM_EXPRESSION;
		   	   ( (H_R_value *)value )->r_value_bits_size     = size * 8 ;

			   /*			   
			   H_term_printf( "constructed SYM-ADDR-Reading expr is %s\n",
					  exprString( ( ( (H_R_value *)value )->r_value).expression )
					);   
			   */

			   if(records != NULL)
			   {
				free(records);
			   }// end of if( )

			   return;
		       }// end of if( )	
		/* --------------------------------------------------------------------------------- */
		// symbolic memory-addressing-READing !

			break;
		}
	
	}// end of switch{ }

	taint_bitmap = HH_Query_TemuMemTaintStatus( addr_value,
						    size,
				      		    records				    		  
						  );
		
	/*
	H_term_printf( "accessing memory --- vaddr is 0x%8x --, size is %d\n ",
		       addr_value,
		       size
		     );
	*/
	GetConcreteMemData( addr_value,
			    size,
			    &oprnd_value
			  );
  
	if(taint_bitmap == 0) // NOT tainted !
	{
		/*
		H_term_printf( "not tainted with value being 0x%8x ---- ",
			       oprnd_value
			     );	
		 */
		( ( (H_R_value *)value )->r_value).value   = oprnd_value;
		( (H_R_value *)value )->r_value_type       = R_CON_VALUE;				
		( (H_R_value *)value )->r_value_bits_size  = size * 8 ;
	}
	else
	{
		tmp_expr1 = NULL;

		for( i=0; i<size; i=i+1)
		{
		    if( taint_bitmap & (1 << i) )
		    {			
		        // this byte is tainted !
		  	/* ---------------------------------------------------------------------------------------- */
			
			if(i == 0)
			{
			    oprnd_expr = ( (H_taint_record_t *)records )->h_expr ;
			}
			else
			{
			    temp_expr  = ( (H_taint_record_t *)( // (uint32_t)records + sizeof(H_taint_record_t) * i
								 records + i  
							       )
					 )->h_expr;

			    oprnd_expr = vc_bvConcatExpr( hvc,
							  temp_expr,
							  oprnd_expr
							);
			    if(tmp_expr1 != NULL)
			    {
				vc_DeleteExpr(tmp_expr1);
			    }// end of if(tmp_expr1)

			    tmp_expr1 = oprnd_expr;
			}// end of if( )			
		  	/* ------------------------------------------------------------------------------------------ */

		    }
		    else
		    {
		        // this byte is concrete !
		  	/* ------------------------------------------------------------------------------------------ */
		        GetConcreteMemData( addr_value,
				    	    size,
			 	    	    &oprnd_value
			 	  	  );

			if(i == 0)
			{
			    oprnd_expr = vc_bvConstExprFromInt( hvc,
								8,
								// 0
								*( ( (uint8_t *)&oprnd_value 
								   ) + i
					  			 ) 
			     				      );
			}
			else
			{
			    temp_expr = vc_bvConstExprFromInt( hvc,				       			
							       8,
							       // 0
							       *( ( (uint8_t *)&oprnd_value 
							 	  ) + i
					  			) 
			     				     );
			    
   			    oprnd_expr = vc_bvConcatExpr( hvc,
							  temp_expr,
							  oprnd_expr
							);

			    if(tmp_expr1 != NULL)
			    {
				vc_DeleteExpr(tmp_expr1);
			    }// end of if(tmp_expr1)

			    tmp_expr1 = oprnd_expr;

			}// end of if( )

			/* ------------------------------------------------------------------------------------------ */

		    }// end of if( )

		    /*
		    	H_term_printf( "expression[%d] = %s --- "
				       i,
				       ( (H_taint_record_t *)( (uint32_t)records + sizeof(H_taint_record_t) * i 
							     )
				       ) ->h_expr
			 	     );

			oprnd_expr = vc_bvConcatExpr( hvc,
						      ( (H_taint_record_t *)(records + i) )->h_expr, // left expr
						      oprnd_expr
						    );
		    */


		}// end of for{ }

		
		// H_term_printf("concat finished !\n");

		/*		
		H_term_printf("with symbolic-expression as ");		
		
		vc_printExprFile( hvc, 
				  oprnd_expr,
				  stp_fd
				);

		H_term_printf("SYM_EXE\n ");		
		*/
		
	    #ifdef H_DELETE_OPRND_EXPR
		if(size == 1)
		{
		    ( (H_R_value *)value )->is_meta_sym_byte = 1;
		}// end of if(size)
	    #endif

		( ( (H_R_value *)value )->r_value).expression  = oprnd_expr;
		( (H_R_value *)value )->r_value_type           = R_SYM_EXPRESSION;
		( (H_R_value *)value )->r_value_bits_size      = size * 8 ;

/*		
		H_term_printf( "Mem SYM-EXPR = %s\n",
			       exprString( oprnd_expr )
			     );
		
 */
		/*
	        HExpr hh_expr1 = vc_bvSignExtend( hvc, 
		 	    			  oprnd_expr,
		     				  32
		   	        	        );
		 */

	}// end of if( )

	

	
	if(records != NULL)
	{
		free(records);
	}// end of if( )
	
	
	/*
	uint64_t HH_Query_TemuMemTaintStatus( uint32_t 		 	 m_address,
										        int			 	 m_length,
				      							 H_taint_record_t * h_taint_recoird
				    						      )
				    						      
	*/

	
	
	
}// end of Mem:: R_value_calculate( )




Mem::Mem(Exp *a, reg_t t)
  : Exp(MEM), addr(a), typ(t)
{
}


Mem::Mem(const Mem& copy)
  : Exp(MEM)
{
  addr = copy.addr->clone();
  typ = copy.typ;
}

Mem *
Mem::clone() const
{
  return new Mem(*this);
}

string
Mem::tostring() const
{
  return "mem[" + addr->tostring() + "]";
// + Exp::string_type(typ);
  //os << "mem[" << addr->tostring() << "]";
}

void Mem::destroy( Mem *expr )
{
    assert(expr);

    Exp::destroy(expr->addr);

    delete expr;    
}
/* ===================================================================== */ // MEM



// Constant
/* ===================================================================== */
void  Constant:: L_value_calculate( HVC    hvc, char *  value)
{

/*
//  Exp  作为左值的计算属性
typedef enum L_EXP_VALUE
{
    L_REG_INDEX = 0,
    L_EFLAG_BIT,
    L_TEMP,
    L_MEM_ADDRESS
}L_exp_value_t;


// 左值具体形式
typedef union L_VALUE
{
    
    uint32_t   reg_idx;
    uint32_t   eflag_bit_idx;
    uint32_t   tmp_idx; 		  // index in the storage for temp variables    
    uint32_t   m_address;
    
}L_value_t;

typedef struct H_L_VALUE
{
    L_value_t  		l_value;
    L_exp_value_t   l_value_type;
    uint32_t		l_value_bits_size;
}H_L_value;
  */
	(( (H_L_value *)value )->l_value).m_address = (uint32_t)val;
	( (H_L_value *)value )->l_value_type	    = L_MEM_ADDRESS;
	( (H_L_value *)value )->l_value_bits_size   = 32;

	printf("Constant L_VALUE !\n");
	
}// end of Constant:: L_value_calculate( )


void Constant:: R_value_calculate( HVC    hvc, char *  value)
{
	( (H_R_value *)value )->is_meta_sym_byte   = 0; 

	( ( (H_R_value *)value )->r_value ).value  = (uint32_t)val;
	( (H_R_value *)value )->r_value_type	   = R_CON_VALUE;
	
	int size = 0 ;
		
	switch(typ)
	{
		case REG_1:
		{
			size = 1;
			break;			
		}
		case REG_8:
		{
			size = 8;
			break;			
		}
		case REG_16:
		{
			size = 16;
			break;			
		}
		case REG_32:
		{
			size = 32;
			break;			
		}
		case REG_64:
		{
			size = 64;
			break;
		}
	}// end of switch{ }
		

	( (H_R_value *)value )->r_value_bits_size = size;
	
}// end of Constant:: R_value_calculate( )



Constant::Constant(reg_t t, const_val_t v)
  : Exp(CONSTANT), typ(t), val(v)
{
}

Constant::Constant(const Constant& other)
  : Exp(CONSTANT),typ(other.typ), val(other.val)
{
}


Constant *
Constant::clone() const
{
  return new Constant(*this);
}

string
Constant::tostring() const
{
  ostringstream os;
  uint8_t u8;
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  
  switch(typ){
  case REG_1: if(val == 0) os << "0"; else os << "1"; break;
  case REG_8: u8 = (uint8_t) val; os << dec << (int) u8; break;
  case REG_16: u16 = (uint16_t) val; os << u16; break;
  case REG_32: u32 = (uint32_t) val; os << u32; break;
  case REG_64: u64 = (uint64_t) val; os << u64; break;
  }
  os << ":" << Exp::string_type(typ);
  return os.str();
}

void Constant::destroy( Constant *expr )
{
    assert(expr);

    delete expr;
}

Constant Constant::t = Constant(REG_1,
				(const_val_t)1);
Constant Constant::f = Constant(REG_1,
				(const_val_t)0);


/* ===================================================================== */ // CONTANT




// PHI
/* ===================================================================== */
void  Phi:: L_value_calculate( HVC    hvc, char *  value)
{
	
}// end of Phi:: L_value_calculate( )


void  Phi:: R_value_calculate( HVC    hvc, char *  value)
{
	
}// end of Phi:: R_value_calculate( )


// ------------------------------------------------------------
// Class Phi
//         Phi functions
// ------------------------------------------------------------
Phi::Phi(const Phi& copy)
  : Exp(PHI)
{
  for(vector<Temp *>::const_iterator it = copy.vars.begin();
      it != copy.vars.end(); it++){
    Temp *t = *it;
    this->vars.push_back(t->clone());
  }
  phi_name = copy.phi_name;
}

Phi::Phi(string orig_name, vector<Temp*> v)
  : Exp(PHI), vars(v), phi_name(orig_name)
{ 
}

Phi *
Phi::clone() const
{
  return new Phi(*this);
}

string
Phi::tostring() const
{ 
  string ret = "PHI(";
  string comma = " ";
  for (vector<Temp *>::const_iterator it = vars.begin();
       it != vars.end(); it++) {
    ret += comma;
    ret += (*it)->tostring();
    comma = ",";
  }
  ret += " )";
  return ret;
}

void Phi::destroy( Phi *expr )
{
    assert(expr);

    unsigned int i;

    for ( i = 0; i < expr->vars.size(); i++ )
    {
        Exp::destroy(expr->vars.at(i));
    }

    delete expr;
}
/* ===================================================================== */ // PHI




// TEMP
/* ===================================================================== */
// 左值:   作为地址操作数的情况----- 【应该仅仅限定于内存地址】
void  Temp:: L_value_calculate( HVC    hvc, char *  value)
{
	uint32_t    size  = 0;
	reg_t  	    type ;

	// checks for temporary variables !
	int 	    index    = Find_VarDecl(name);

	H_R_value * r_value  = NULL;

	VarDecl *   var_decl = NULL;
	
	if(index == -1)
	{
		// checks for general-purpose registers !
		var_decl = Obtain_i386_regvar_byname(name);
		if(var_decl != NULL)
		{
		    /*
		    H_term_printf( "register as Temp's left variable ----- idx = %d, offset = %d, size = %d\n",
				   var_decl->reg_idx, 
				   var_decl->reg_offset,
				   var_decl->reg_size
				 );
		     */
		    ( (H_L_value *)value )->l_value_type       = L_REG_INDEX;
		    ( (H_L_value *)value )->l_value_bits_size  = (var_decl->reg_size) * 8 ;
		
		    ( ( (H_L_value *)value )->l_value).reg_idx = (var_decl->reg_idx) * 4 + var_decl->reg_offset;
		}
		else
		{
		// checks for EFLAGS bits
			// index= GetEFLAG_Bit_Index(name);
			
			var_decl = Obtain_i386_EFLAGS_bit_var_byname(name);
			// reg_idx;
			// if(index != -1)
			if(var_decl != NULL)
			{
				( (H_L_value *)value )->l_value_type	         = L_EFLAG_BIT;
				( (H_L_value *)value )->l_value_bits_size	 = 1;
				// ( ( (H_L_value *)value )->l_value).eflag_bit_idx = index;
			
				// the bit's index in the real i386-EFLAGS register !
				( ( (H_L_value *)value )->l_value).eflag_bit_idx = var_decl->reg_idx;
			}
			else
			{
				( (H_L_value *)value )->l_value_type = L_NONSENSE ;
			}// end of if( )


		}// end of if( )		
		
	}
	else
	{
	// 临时声明的变量
		type  = GetVarDecl_TypeByIndex(index);

	 	switch(type)
		{
			case REG_1:
			{
				size = 1;
				break;
			}
			case REG_8:
			{
				size = 8;
				break;
			}
			case REG_16:
			{
				size = 16;
				break;
			}
			case REG_32:
			{
				size = 32;
				break;
			}
			case REG_64:
			{
				size = 64;
				break;
			}
		}// end of switch{ }
	
		 r_value = GetVarDecl_ValueByIndex(index);		 
		
		( (H_L_value *)value )->l_value_type	   = L_TEMP;
		( (H_L_value *)value )->l_value_bits_size  = size;
		( ( (H_L_value *)value )->l_value).tmp_idx = index;


		 
	}// end of if( )
			
}// end of Phi:: L_value_calculate( )



void Temp:: R_value_calculate( HVC    hvc, char *  value)
{
	uint32_t	size	= 0;

	
	int 		index 	= -1 ;
	reg_t  	oprnd_type;	
	
	H_R_value * r_value 	= NULL;

	uint32_t  data_value 	= 0;

	H_taint_record_t * records = NULL;
	
	uint64_t  taint_bitmap = 0 ;	

	HExpr	 tmp_expr1 = NULL;
	HExpr	 tmp_expr2 = NULL;
	HExpr	 tmp_expr3 = NULL;
	HExpr	 tmp_expr4 = NULL;

	HExpr    expr 	   = NULL;
	HExpr    temp_expr = NULL;
	HExpr    t_expr	   = NULL;


	HType    temp_type     = NULL;
	char *   str_temp_type = NULL;

	uint32_t temp_val  = 0;
	uint32_t byte_val  = 0;

	( (H_R_value *)value )->is_meta_sym_byte = 0; 

	// 通用寄存器
	/* ================================================================= */
	index= GetReg_Index(name) ;
	VarDecl * var_decl = NULL;

	

	// 为通用寄存器操作数
	if(index != -1)
	{
		var_decl = Obtain_i386_regvar_byname(name);

		// size = GetReg_SizeByIndex(index) ;
		// total bytes count !
		size = var_decl->reg_size;

		records = (H_taint_record_t *)malloc(sizeof(H_taint_record_t) * size) ;
				
		taint_bitmap = HH_Query_TemuRegisterTaintStatus( name,
					     			 records
					     		       );

		// concrete value of this TEMU register
		temp_val = GetConcreteRegData(index);

		if(taint_bitmap)
		{
		// Symbolic right-value !
			/*
			H_term_printf( "register %s is tainted being the right-value, de-facto concrete value being 0x%x !\n",
				       name.c_str( ),
				       temp_val
				     );
			*/

			// 为符号值
			// expr = ( (H_taint_record_t *)records )->h_expr;			


			// concatenate !
			/* ============================================================================================ */
			/* ======= Retrieve taint-record from a low-addr byte to high-addr byte ordering concat ======= */
			/* ============================================================================================ */
			/* -------------------------------------------------------------------------------------------------------------------------- */
			tmp_expr1 = NULL;

			for(int i=0; i<size;i=i+1 )
			{		
			    	    
			    if( taint_bitmap & (1 << i) )
			    {
			    // tainted byte!
				if(i == 0)
				{				    
    				    expr = ( (H_taint_record_t *) ( // (uint32_t)records + sizeof(H_taint_record_t) * i
								    records + i  
								  )
					   )->h_expr;
/*
				    H_term_printf( "expr[%d] : %s\n",
						   0,
						   exprString(expr)
						 );
*/
				}
				else
				{
				    temp_expr = ( (H_taint_record_t *)( // (uint32_t)records + sizeof(H_taint_record_t) * i
									records + i  
								      )
					        )->h_expr;

/*				    				
				    H_term_printf( "expr[%d] : %s\n",
						   i,
						   exprString(temp_expr)
						 );
*/

				    t_expr = vc_bvConcatExpr( hvc, 
							      temp_expr, // high-bits would resides on the left
							      expr	 // low-bits would resides on the right
							    );	
				
				    if(tmp_expr1 != NULL)
				    {
					vc_DeleteExpr(tmp_expr1);
				    }// end of if(tmp_expr1)

				    expr      = t_expr;
				    tmp_expr1 = expr;

				}// end of if( )				
			    }
			    else
			    {
				/*
				byte_val = *( (uint8_t *)( ((uint32_t)&temp_val) + i 
				   		         ) 				    	      
					    );
				 */
				byte_val = *( ((uint8_t *)&temp_val) + i 
					    );

			        // concrete byte!
				if(i == 0)
				{				    
				    expr = vc_bvConstExprFromInt( hvc,
								  8,
								  byte_val
								 );
				}
				else
				{
				    temp_expr = vc_bvConstExprFromInt( hvc,
								       8,
								       byte_val
								       // 0
								     );

				    expr      = vc_bvConcatExpr( hvc, 
								 temp_expr, // left
								 expr	    // right
						      	       );	

				    if(tmp_expr1 != NULL)
				    {
					vc_DeleteExpr(tmp_expr1);
				    }// end of if(tmp_expr1)

				    tmp_expr1 = expr;
				}// end of if( )

			    }// end of if( )			    				

			}// end of for{ }
			/* -------------------------------------------------------------------------------------------------------------------------- */

/*
			H_term_printf( "total expr is %s\n",
					exprString(expr)
				     );
*/

		    #ifdef H_DELETE_OPRND_EXPR
			/* HHui added at Feb 13th, 2012 when encountering single-byte memory or register object 
			   so as to warn the optimization not to vc_DeleteExpr( ) the corresponding 8-bit sym-record.
     			 */
			if(size == 1)
			{			    
			    ( (H_R_value *)value )->is_meta_sym_byte = 1;
			}// end of if(size)
		    #endif

			( (H_R_value *)value )->r_value_type 	       = R_SYM_EXPRESSION;
			( ( (H_R_value *)value )->r_value ).expression = expr;
			( (H_R_value *)value )->r_value_bits_size      = size * 8;
			
		}
		else
		{
			// 为具体值 --- this index is the index in the i386-general-register-stack !
			data_value = GetConcreteRegData(index);
		
			( (H_R_value *)value )->r_value_type 	  = R_CON_VALUE;
			( (H_R_value *)value )->r_value_bits_size = size * 8;
			( ( (H_R_value *)value )->r_value ).value = data_value;
			
		}// end of if( )
		

		if(records != NULL)
		{
		    free(records);
		}// end of if( )
		
		
		/*
		H_term_printf( "finished calculating the right value of %s",
			       name.c_str( )	
			     );
		 */

		return ;
	}// end of if( )
	/* ================================================================= */
	// 通用寄存器



/* HHui Notice : EFLAGS temply would not take into account when calculating the right-value, as they should not appear in the position in my tailored-calculation ! */
	// EFLAGS   标记位
	/* ================================================================= */
	// 为EFLAGS   标记位
	index= GetEFLAG_Bit_Index(name);
	if(index != -1)
	{
	/*
	 uint32_t HH_Query_TemuEFLAGSTaintStatus( string  	     eflag_name,
					 H_taint_record_t *  eflag_bit_expr_record
				       )
	*/
		records	     = (H_taint_record_t *)malloc(sizeof(H_taint_record_t)) ;
		
		taint_bitmap = HH_Query_TemuEFLAGSTaintStatus( name,
							       records
							     );
		/*
		H_term_printf( "EFLAG bit name is %s\n",
			       name.c_str( )
			     );
		*/
		if(taint_bitmap != 0)
		{
			// 符号值
			expr = ( (H_taint_record_t *)records )->h_expr;
			
			( (H_R_value *)value )->r_value_type = R_SYM_EXPRESSION;

			temp_type     = vc_getType( hvc,
						    expr
						  );

			str_temp_type = typeString(temp_type);

			/*
			H_term_printf( "EFLAG expr type is %s\n",
				       str_temp_type
				     );
			*/

			if( strcmp( "BOOLEAN ", 
				    str_temp_type
				  ) == 0
			  )
			{
/*
			    vc_push(hvc);
			    vc_query( hvc,
				      expr
				    );
			    vc_pop(hvc);
			    H_term_printf("queried !\n");			    
 */
			    expr = vc_boolToBVExpr( hvc,
						    expr
						  );
			}// end of if( )

			free(str_temp_type);
			
			( ( (H_R_value *)value )->r_value ).expression = expr;

		    #ifdef H_DELETE_OPRND_EXPR
			/* HHui added at Feb 13th, 2012 when encountering single-byte memory or register object 
			   so as to warn the optimization not to vc_DeleteExpr( ) the corresponding 8-bit sym-record.
     			 */			    
			( (H_R_value *)value )->is_meta_sym_byte = 1;
		    #endif

			
			( (H_R_value *)value )->r_value_bits_size      = 1;						
		}
		else
		{
			( (H_R_value *)value )->r_value_type 	  = R_CON_VALUE;
			( ( (H_R_value *)value )->r_value).value  = GetConcreteEFLAGData(name);
			( (H_R_value *)value )->r_value_bits_size = 1;						
			/*			
			// 具体值			
			
						
			( (H_R_value *)value )->r_value_type 	  = R_CON_VALUE;
			( (H_R_value *)value )->r_value_bits_size = 1;
			( ( (H_R_value *)value )->r_value).value  = data_value;		
			*/
		
		}// end of if( )

		if(records != NULL)
		{
		    free(records);
		}// end of if( )
		

		return;
	}// end of if( )
	
	/* ================================================================= */
	// EFLAGS   标记位



	// 临时变量
	/* ================================================================= */
	index = Find_VarDecl(name);
	// 为临时变量操作数
	if(index != -1)
	{
		// H_term_printf("---- Fetching temp varible value ---- ");

		// Obtain the right-value structure 
		r_value = GetVarDecl_ValueByIndex( index );	

		switch(typ)
		{
			case REG_1:
			{
				size = 1;
				break;
			}
			case REG_8:
			{
				size = 8;
				break;
			}
			case REG_16:
			{
				size = 16;
				break;
			}
			case REG_32:
			{
				size = 32;
				break;
			}
			case REG_64:
			{
				size = 64;
				break;
			}
		}// end of switch{ }

		( (H_R_value *)value )->r_value_type	  = r_value->r_value_type;
		( (H_R_value *)value )->r_value_bits_size = size;

		switch(r_value->r_value_type)
		{
			case R_CON_VALUE:
			{
				// H_term_printf("concrete temp varible value ! --- ");	
				( ( (H_R_value *)value )->r_value ).value =(r_value->r_value).value;
				break;
			}
			case R_SYM_EXPRESSION:
			{				

	  	        #ifdef H_DELETE_OPRND_EXPR
			    /* HHui added at Feb 13th, 2012 when encountering single-byte memory or register object 
			       so as to warn the optimization not to vc_DeleteExpr( ) the corresponding 8-bit sym-record.
     			     */
			    if(size == 1)
		   	    {			    
			        ( (H_R_value *)value )->is_meta_sym_byte = r_value->is_meta_sym_byte;
			    }// end of if(size)
		        #endif

				// H_term_printf("symbolic temp varible value ! --- ");	
				( ( (H_R_value *)value )->r_value ).expression =(r_value->r_value).expression;

				HType  sub_r_type = vc_getType( hvc,
								( ( (H_R_value *)value )->r_value ).expression 
							      );
				char * sub_r_str  = typeString(sub_r_type);
				/*
				H_term_printf( "type is %s\n", 
					       sub_r_str
					     );
				 */
				free(sub_r_str);
				break;
			}
		}// end of switch{ }	

		// H_term_printf("temp varible value obtained !\n");
		return ;
	}// end of if( )
	/* ================================================================= */
	// 临时变量	


	( (H_R_value *)value )->r_value_type = R_NONSENSE;		
	
	
}// end of Temp:: R_value_calculate( )


Temp::Temp(reg_t t, string n) 
  : Exp(TEMP), typ(t), name(n)
{ }


Temp::Temp(const Temp &other)
  : Exp(TEMP), typ(other.typ), name(other.name)
{
}


Temp *
Temp::clone() const
{
  return new Temp(*this);
}

string 
Temp::tostring() const
{
  // Argh! Stop removing useful error checking and debugging information.
  // It doesn't hurt anyone.
  return name + ":" + Exp::string_type(typ);
  //return name;
}


void Temp::destroy( Temp *expr )
{
    assert(expr);

    delete expr;
}
/* ===================================================================== */ // TEMP




// UNKNOWN
/* ===================================================================== */
void  Unknown:: L_value_calculate( HVC    hvc, char *  value)
{

}// end of Unknown:: L_value_calculate( )


void Unknown:: R_value_calculate( HVC    hvc, char *  value)
{

}// end of Unknown:: R_value_calculate( )



Unknown::Unknown(string s) : Exp(UNKNOWN), str(s)
{ }

Unknown::Unknown(const Unknown &other) : Exp(UNKNOWN), str(other.str)
{ }

Unknown *
Unknown::clone() const
{
  return new Unknown(*this);
}

void Unknown::destroy( Unknown *expr )
{
    assert(expr);

    delete expr;
}
/* ===================================================================== */ // UNKNOWN



// NAME
/* ===================================================================== */
void Name:: L_value_calculate( HVC    hvc, char *  value)
{

}// end of Name:: L_value_calculate( )


void Name:: R_value_calculate( HVC    hvc, char *  value)
{
    // cjmp(T_1t0:reg1_t,name(pc_0x4010cf),name(L_3)); 
    const char * str_name = name.c_str( );

    uint32_t eip_addr = 0;
    int	     eip_len  = 0;
    int      i	      = 0 ;

    
    if( (str_name[0] == 'p') &&
	(str_name[1] == 'c')
      )
    {	
        // pc !
	( (H_R_value *)value )->r_value_type = R_PC_ADDRESS;

        // ( ( (H_R_value *)value )->r_value ).pc_address = (uint32_t)( atoi(str_name + 2) );
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

/*
	H_term_printf( "real fbranch eip is 0x%x, eip_len = %d\n",
		       eip_addr,
		       eip_len
		     );
 */

	( ( (H_R_value *)value )->r_value ).pc_address = (uint32_t)eip_addr;
    }
    else if( (str_name[0] == 'L')
	   )
    {
        // label --- (in fact, it's just the next instruction's address !)
	( (H_R_value *)value )->r_value_type = R_LABEL;
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
	
	( ( (H_R_value *)value )->r_value ).label_id = (uint32_t)eip_addr;

    }// end of if( )
    
}// end of Name:: R_value_calculate( )



Name::Name( string s ) : Exp(NAME), name(s)
{ 
  //typ = REG_ADDRESS_T;
}

Name::Name( const Name &other ) : Exp(NAME), name(other.name)
{ 
  //typ = REG_ADDRESS_T;
}

Name *
Name::clone() const
{
  return new Name(*this);
}

string Name::tostring() const
{
  //  return "name(L_" + name + ")";
  return "name(" + name + ")";
}

void Name::destroy( Name *expr )
{
    assert(expr);

    delete expr;
}
/* ===================================================================== */ // NAME




// Cast :  得到一个"  计算意义上"   临时的操作数
/* ===================================================================== */

/*   成员变量:

	  Exp *exp;
	  reg_t typ;	  
	  cast_t cast_type;
  */

// 作为左值，表征地址操作数
void Cast::L_value_calculate( HVC    hvc, char *  value)
{
	// possibly this won't appear to be the lval !@	
		
}// end of Cast:: L_value_calculate( )



// 作为右值，表征具体的操作数值
void Cast:: R_value_calculate( HVC    hvc, char *  value)
{
	H_R_value  sub_rval ;

	uint32_t 	   mask     = 0 ;

	int		   bit_low  = 0;
	int		   bit_num = 0 ;

	HExpr	   expr       = NULL;
	HExpr	   expr1      = NULL;
	HExpr	   expr2      = NULL;

	char *	   type_str   = NULL;
	char * 	   expr_str   = NULL;

	int	   expr_is_bool = -1;


	// 求解被cast   的对象的右值
	exp->R_value_calculate( hvc, 
				(char *)( &sub_rval )
			      );


	( (H_R_value *)value )->r_value_type = sub_rval.r_value_type;
	/*
	 	 Expr vc_bvExtract(VC vc, Expr child, int high_bit_no, int low_bit_no); 
	  */


	/* ---------------------------------------------------------------------------- */
	// 转换的目标类型	
	switch(typ)
	{
		case REG_1:
		{
			( (H_R_value *)value )->r_value_bits_size = 1 ;
			break;			
		}
		case REG_8:
		{
			( (H_R_value *)value )->r_value_bits_size = 8 ;
			break;			
		}
		case REG_16:
		{
			( (H_R_value *)value )->r_value_bits_size = 16 ;
			break;			
		}
		case REG_32:
		{
			( (H_R_value *)value )->r_value_bits_size = 32 ;
			break;			
		}
		case REG_64:
		{
			( (H_R_value *)value )->r_value_bits_size = 64 ;
			break;
		}
	}// end of switch{ }
	/* ---------------------------------------------------------------------------- */
	mask = ( 1 << ( (H_R_value *)value )->r_value_bits_size ) - 1;
		
       ( (H_R_value *)value )->r_value_type = sub_rval.r_value_type;
/*	
	H_term_printf( "src operand to be extended is %s\n",
			( (sub_rval.r_value_type == R_CON_VALUE) ? "concrete": "symbolic" )
		     );
*/		
			
	
	//  值的类型
	/* ---------------------------------------------------------------------------- */
	switch(sub_rval.r_value_type)
	{
		case R_CON_VALUE:
		{
			// 具体值
			// 位向量的扩展		
		  	switch(cast_type)
			{
				case CAST_UNSIGNED:
				{
					( ( (H_R_value *)value )->r_value ).value  = (sub_rval.r_value).value & mask;
					break;
				}
				case CAST_SIGNED:
				{
					( ( (H_R_value *)value )->r_value ).value  = (sub_rval.r_value).value & mask;					
					break;
				}		
				case CAST_HIGH:
				{
					/*
					( ( (H_R_value *)value )->r_value ).value  = ( ( sub_rval.r_value ).value >> 
															( ( (H_R_value *)value )->r_value_bits_size / 2 )
														    ) & mask;
					  */
					mask =  (  1 << ( sub_rval.r_value_bits_size ) ) - 
						(  1 << ( sub_rval.r_value_bits_size -
						     	  ( (H_R_value *)value )->r_value_bits_size 
							) 						  
						);
					( ( (H_R_value *)value )->r_value ).value  =  ( ( sub_rval.r_value ).value & mask ) >>
													 ( sub_rval.r_value_bits_size -
						     		    					   ( (H_R_value *)value )->r_value_bits_size 
						     		  					 ); 
						
					break;
				}
				case CAST_LOW:
				{
					
					mask = ( 1 << ( (H_R_value *)value )->r_value_bits_size ) - 1;					
					( ( (H_R_value *)value )->r_value ).value  = (sub_rval.r_value).value & mask;
					// ( (H_R_value *)value )->r_value_bits_size

					// H_term_printf("casting low finished !\n");

					break;
				}
				case CAST_FLOAT:
				{
					break;
				}
				case CAST_INTEGER:
				{
					( ( (H_R_value *)value )->r_value ).value  = (sub_rval.r_value).value & mask;					
					break;
				}
				case CAST_RFLOAT:
				{
					break;
				}
				case CAST_RINTEGER:
				{
					break;
				}				
			}// end of switch{ }								

			break;
		}
		case R_SYM_EXPRESSION:
		{
		// 符号值
				
			// 符号表达式的变换
			/* ---------------------------------------------------------------------------- */	
			switch(cast_type)
			{
				case CAST_UNSIGNED:
				{
					// ( ( (H_R_value *)value )->r_value ).value  = (sub_rval.r_value).value & mask;
					bit_num = ( (H_R_value *)value )->r_value_bits_size  - 
						  sub_rval.r_value_bits_size;
					
					expr1    = vc_bvConstExprFromInt( hvc, 
									  bit_num, 
									  0
									); 
					/*
					H_term_printf( "unsigned casting expr is %s, vc_isBool( ) is at address 0x%x \n",
						       exprString( sub_rval.r_value.expression ),
						       vc_isBool
						     );
					H_term_printf( "type is %s, vc_getType( ) is at address 0x%x \n",
						       typeString( vc_getType( hvc,
									       sub_rval.r_value.expression
									     )
								 )
						     );
					*/


// ================== HHui Fixme : checks if the expr is a Boolean ========================================================= //
					type_str = typeString( vc_getType( hvc,
								           sub_rval.r_value.expression
								   	 ) 
							     );
					// src-opnd sym-expression is of Type BOOLEAN , type length = 8

					/*
					H_term_printf( "src-opnd sym-expression is of Type %s, type length = %d\n",
						       type_str,
						       strlen(type_str)	
						     );
					*/
					/*
					expr_is_bool = ( strcmp( typeString( vc_getType( hvc,
											 sub_rval.r_value.expression
										       ) 
									   ),
								 "BOOLEAN"

							       ) == 0 
						       ) ? 1 : 0;
					 */

					if(strcmp(type_str, "BOOLEAN ") == 0)
					{
					    expr_is_bool = 1;
					}
					else
					{
					    expr_is_bool = 0;
					}// end of if( )

					free(type_str);

// ================== HHui Fixme : checks if the expr is a Boolean ========================================================= //
					/*
					expr = vc_bvConcatExpr( hvc, 
								expr1, 
								vc_bvExtract( hvc, 
									      sub_rval.r_value.expression, 
									      sub_rval.r_value_bits_size - 1, 
									      0
									    )
							      ); 
					*/					
				  	
					

					// Just true or false judgement !
					// expr_is_bool = vc_isBool(sub_rval.r_value.expression);
					if(expr_is_bool == 1)
					{
					    // H_term_printf();

					    expr2 = vc_boolToBVExpr( hvc,
							             sub_rval.r_value.expression
								   );

					    /*
					    H_term_printf( "src-opnd sym-expression is of Type %s\n",
						      	   typeString( vc_getType( hvc,
									       	   expr2
								   	     	 ) 
								     )
						         );
					    */

					    // A Bool expr !
					    expr = vc_bvConcatExpr( hvc, 
								    expr1, 
								    expr2		    
								  ); 
					}
					else
					{
					    // H_term_printf("normal SE-concat !\n");

					    // treat as normal expr !
					    expr = vc_bvConcatExpr( hvc, 
								    expr1,
								    sub_rval.r_value.expression
								  );  
						
					}// end of if( )															
					( ( (H_R_value *)value )->r_value).expression = expr;

					vc_DeleteExpr(expr1);

					if(expr2 != NULL)
				        {
					    vc_DeleteExpr(expr2);
				        }// end of if(expr2)

					// ( ( (H_R_value *)value )->r_value_bits_size   = bit_num;

					// H_term_printf("unsigned casting finished !\n");

					break;
				}
				case CAST_SIGNED:
				{
					// Expr vc_bvSignExtend(VC vc, Expr child, int nbits); 

					bit_num = ( (H_R_value *)value )->r_value_bits_size ;
					
					HExpr t_expr = ( sub_rval.r_value ).expression;
					expr = vc_bvSignExtend( hvc, 
								t_expr, 
								bit_num
							      ); 										
					( ( (H_R_value *)value )->r_value).expression = expr;

					break;
				}		
				case CAST_HIGH:
				{
					/*
					mask =  ( 1 << ( sub_rval.r_value ).r_value_bits_size ) - 
						     (  1 << ( sub_rval.r_value ).r_value_bits_size -
						     		     ( (H_R_value *)value )->r_value_bits_size 
						     		  ) 
						     ) ;
					
					( ( (H_R_value *)value )->r_value ).value  =  ( ( sub_rval.r_value ).value & mask ) >>
														     ( ( sub_rval.r_value ).r_value_bits_size -
						     		    							( (H_R_value *)value )->r_value_bits_size 
						     		  						     ); 
					*/

					bit_low  =  sub_rval.r_value_bits_size - 
						    ( (H_R_value *)value )->r_value_bits_size ;

					bit_num = ( (H_R_value *)value )->r_value_bits_size ;
					
					/*
					H_term_printf( "casting high : bit_low = 0x%x, bit_high = 0x%x\n",
						       bit_low,
						       bit_low + bit_num - 1
						     );
					 */
					expr = vc_bvExtract( hvc,
							     ( sub_rval.r_value ).expression,
							     bit_low + bit_num - 1, // high bit index
							     bit_low 		    // low bit index
							   );

					( ( (H_R_value *)value )->r_value ).expression = expr;
					
					// Expr vc_bvExtract(VC vc, Expr child, int high_bit_no, int low_bit_no); 
					
					break;
				}
				case CAST_LOW:
				{       // cast(R_ECX:reg32_t)L:reg8_t;
					// ( ( (H_R_value *)value )->r_value ).value  = (sub_rval.r_value).value & mask;
					bit_low  = 0;

					bit_num = ( (H_R_value *)value )->r_value_bits_size ;
					

					expr = vc_bvExtract( hvc,
							     ( sub_rval.r_value ).expression,
							     bit_low + bit_num - 1,   	 // high bit index
							     bit_low 			 // low bit index
							   );
					/*
					H_term_printf( "low casting finished --- bitnum = %d, expr is %s\n",
						       bit_num,
						       exprString(expr)
						     );
					*/
					/*
					H_term_printf( "casting low ---- expr = %s\n", 
						       exprString(expr)
						     );
					*/

					( ( (H_R_value *)value )->r_value ).expression = expr;
					
					break;
				}
				case CAST_FLOAT:
				{
					break;
				}
				case CAST_INTEGER:
				{
					// ( ( (H_R_value *)value )->r_value ).value  = (sub_rval.r_value).value & mask;					
					break;
				}
				case CAST_RFLOAT:
				{
					break;
				}
				case CAST_RINTEGER:
				{
					break;
				}				
			}// end of switch{ }	

			break;
		}
	}// end of switch{ }
		

			
				
				
	/* ---------------------------------------------------------------------------- */
	// 类型
	



	

	/*	
	  	enum cast_t 
	  	{
		    CAST_UNSIGNED, CAST_SIGNED, CAST_HIGH, CAST_LOW,
		    CAST_FLOAT, CAST_INTEGER, CAST_RFLOAT, CAST_RINTEGER 
		};
	  */


	

	

	
	
	
}// end of Cast:: R_value_calculate( )

// ./ir/exp.cpp:2755: error: invalid conversion from ‘const char*’ to ‘char*’


Cast::Cast( Exp *e, reg_t w, cast_t t ) 
  : Exp(CAST), exp(e), typ(w), cast_type(t)
{ }

Cast::Cast( const Cast &other ) 
  : Exp(CAST), typ(other.typ), cast_type(other.cast_type)
{
  exp = other.exp->clone();
}

Cast *
Cast::clone() const
{
  return new Cast(*this);
}

void Cast::destroy( Cast *expr )
{
    assert(expr);

    Exp::destroy(expr->exp);

    delete expr;
}

string Cast::tostring() const
{
  string wstr, tstr;

  wstr = Exp::string_type(this->typ);

  switch ( cast_type )
  {
    case CAST_UNSIGNED: tstr = "U"; break;
    case CAST_SIGNED:   tstr = "S"; break;
    case CAST_HIGH:     tstr = "H"; break;
    case CAST_LOW:      tstr = "L"; break;
    case CAST_FLOAT:    tstr = "F"; break;
    case CAST_INTEGER:  tstr = "I"; break;
    case CAST_RFLOAT:   tstr = "RF"; break;
    case CAST_RINTEGER: tstr = "RI"; break;
    default: 
      cout << "Unrecognized cast type" << endl;
      assert(0);
  }

  /*
  H_term_printf( "cast wstr : %s\n",
		 wstr.c_str( )
	       );

  H_term_printf( "cast exp : %s\n",
		 exp->tostring().c_str( )
	       );
  */
  string ret = "cast(" + exp->tostring() + ")" + tstr + ":" + wstr;
  return ret;
}

string Cast::cast_type_to_string( const cast_t ctype )
{
  string  tstr;
  switch ( ctype )
  {
  //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  // Do NOT change this. It is used in producing XML output.
  //!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    case CAST_UNSIGNED: tstr = "Unsigned"; break;
    case CAST_SIGNED:   tstr = "Signed"; break;
    case CAST_HIGH:     tstr = "High"; break;
    case CAST_LOW:      tstr = "Low"; break;
    case CAST_FLOAT:    tstr = "Float"; break;
    case CAST_INTEGER:  tstr = "Integer"; break;
    case CAST_RFLOAT:   tstr = "ReinterpFloat"; break;
    case CAST_RINTEGER: tstr = "ReinterpInteger"; break;
    default:
      cout << "Unrecognized cast type" << endl;
      assert(0);
  }

  return tstr;
}
/* ===================================================================== */ // NAME





// LET
/* ===================================================================== */
void  Let:: L_value_calculate( HVC    hvc, char *  value)
{

}// end of Let:: L_value_calculate( )


void Let:: R_value_calculate( HVC    hvc, char *  value)
{

}// end of Let:: R_value_calculate( )



///////////////////////////// LET ////////////////////////////////
Let::Let(Exp *v, Exp *e, Exp *i) : Exp(LET), var(v), exp(e), in(i)
{
  /* empty */
}

Let *Let::clone() const
{

  return new Let(*this);
}


Let::Let(const Let &other) : Exp(LET)
{
  var = other.var->clone();
  exp = other.exp->clone();
  in = other.in->clone();

}

void
Let::destroy(Exp *exp)
{
  assert(LET == exp->exp_type);
  Let *let = (Let *)exp;
  Exp::destroy(let->var);
  Exp::destroy(let->exp);
  Exp::destroy(let->in);
  delete exp;
}

string
Let::tostring() const
{
  string s = "(let " + var->tostring() + " = " + exp->tostring()
    + " in " + in->tostring() + ")";
  return s;
}
/* ===================================================================== */ // LET







//======================================================================
// 
// Shorthand functions for creating expressions
//
// Functions preceded with a _ are versions that do not make deep
// copies of their expression arguments before using them.
// 
//======================================================================

Exp *ecl( Exp *exp )
{
    assert(exp);
    return exp->clone();
}

Constant *ex_const(uint32_t value )
{
  return new Constant(REG_32, value);
}


Constant *ex_const(reg_t t, const_val_t value )
{
    return new Constant(t, value);
}


Name *ex_name( string name )
{
    return new Name(name);
}

UnOp *_ex_not( Exp *arg )
{
    return new UnOp(NOT, arg);
}

UnOp *ex_not( Exp *arg )
{
  arg = arg->clone();
    return _ex_not(arg);
}

BinOp *_ex_add( Exp *arg1, Exp *arg2 )
{
    return new BinOp(PLUS, arg1, arg2);
}

BinOp *ex_add( Exp *arg1, Exp *arg2 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
    return _ex_add(arg1, arg2);
}

BinOp *_ex_sub( Exp *arg1, Exp *arg2 )
{
    return new BinOp(MINUS, arg1, arg2);
}

BinOp *ex_sub( Exp *arg1, Exp *arg2 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
    return _ex_sub(arg1, arg2);
}

BinOp *_ex_mul( Exp *arg1, Exp *arg2 )
{
    return new BinOp(TIMES, arg1, arg2);
}

BinOp *ex_mul( Exp *arg1, Exp *arg2 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
    return _ex_mul(arg1, arg2);
}

BinOp *_ex_div( Exp *arg1, Exp *arg2 )
{
    return new BinOp(DIVIDE, arg1, arg2);
}

BinOp *ex_div( Exp *arg1, Exp *arg2 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
  return _ex_div(arg1, arg2);
}

BinOp *_ex_and( Exp *arg1, Exp *arg2 )
{
    return new BinOp(BITAND, arg1, arg2);
}

BinOp *_ex_and( Exp *arg1, Exp *arg2, Exp *arg3 )
{
    return _ex_and(arg1, _ex_and(arg2, arg3));
}

BinOp *_ex_and( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4, Exp *arg5, Exp *arg6, Exp *arg7 )
{
    return _ex_and( _ex_and(arg1, arg2, arg3), _ex_and(arg4, arg5, arg6), arg7 );
}

BinOp *ex_and( Exp *arg1, Exp *arg2 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
    return _ex_and(arg1, arg2);
}

BinOp *ex_and( Exp *arg1, Exp *arg2, Exp *arg3 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
  arg3 = arg3->clone();
    return _ex_and(arg1, arg2, arg3);
}

BinOp *ex_and( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4, Exp *arg5, Exp *arg6, Exp *arg7 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
  arg3 = arg3->clone();
  arg4 = arg4->clone();
  arg5 = arg5->clone();
  arg6 = arg6->clone();
  arg7 = arg7->clone();
    return _ex_and(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

BinOp *_ex_or( Exp *arg1, Exp *arg2 )
{
    return new BinOp(BITOR, arg1, arg2);
}

BinOp *_ex_or( Exp *arg1, Exp *arg2, Exp *arg3 )
{
    return _ex_or(arg1, _ex_or(arg2, arg3));
}

BinOp *_ex_or( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4, Exp *arg5, Exp *arg6 )
{
    return _ex_or( _ex_or(arg1, arg2, arg3), _ex_or(arg4, arg5, arg6) );
}

BinOp *_ex_or( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4, Exp *arg5, Exp *arg6, Exp *arg7 )
{
    return _ex_or( _ex_or(arg1, arg2, arg3), _ex_or(arg4, arg5, arg6), arg7 );
}

BinOp *ex_or( Exp *arg1, Exp *arg2 )
{
  arg1 = arg1->clone();
  arg2 = arg2->clone();
    return _ex_or(arg1, arg2);
}

BinOp *ex_or( Exp *arg1, Exp *arg2, Exp *arg3 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    arg3 = arg3->clone();
    return _ex_or(arg1, arg2, arg3);
}

BinOp *ex_or( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4, Exp *arg5, Exp *arg6 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    arg3 = arg3->clone();
    arg4 = arg4->clone();
    arg5 = arg5->clone();
    arg6 = arg6->clone();
    return _ex_or(arg1, arg2, arg3, arg4, arg5, arg6);
}

BinOp *ex_or( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4, Exp *arg5, Exp *arg6, Exp *arg7 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    arg3 = arg3->clone();
    arg4 = arg4->clone();
    arg5 = arg5->clone();
    arg6 = arg6->clone();
    arg7 = arg7->clone();
    return _ex_or(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

BinOp *_ex_xor( Exp *arg1, Exp *arg2 )
{
    return new BinOp(XOR, arg1, arg2);
}

BinOp *_ex_xor( Exp *arg1, Exp *arg2, Exp *arg3 )
{
    return _ex_xor(arg1, _ex_xor(arg2, arg3));
}

BinOp *_ex_xor( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4 )
{
    return _ex_xor( _ex_xor(arg1, arg2), _ex_xor(arg3, arg4) );
}

BinOp *_ex_xor( Exp *arg1, Exp *arg2, Exp *arg3, Exp *arg4,
                       Exp *arg5, Exp *arg6, Exp *arg7, Exp *arg8 )
{
    return _ex_xor( _ex_xor(arg1, arg2, arg3, arg4), _ex_xor(arg5, arg6, arg7, arg8) );
}

BinOp *ex_xor( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return _ex_xor(arg1, arg2);
}

BinOp *ex_xor( Exp *arg1, Exp *arg2, Exp *arg3 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    arg3 = arg3->clone();
    return _ex_xor(arg1, arg2, arg3);
}

BinOp *_ex_shl( Exp *arg1, Exp *arg2 )
{
    return new BinOp(LSHIFT, arg1, arg2);
}

BinOp *ex_shl( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(LSHIFT, arg1, arg2);
}

BinOp *ex_shl( Exp *arg1, int arg2 )
{
    arg1 = arg1->clone();
    return new BinOp(LSHIFT, arg1, ex_const(arg2));
}

BinOp *_ex_shr( Exp *arg1, Exp *arg2 )
{
    return new BinOp(RSHIFT, arg1, arg2);
}

BinOp *ex_shr( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(RSHIFT, arg1, arg2);
}

BinOp *ex_shr( Exp *arg1, int arg2 )
{
    arg1 = arg1->clone();
    return new BinOp(RSHIFT, arg1, ex_const(arg2));
}

BinOp *_ex_sar( Exp *arg1, Exp *arg2 )
{
    return new BinOp(ARSHIFT, arg1, arg2);
}

BinOp *ex_sar( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(ARSHIFT, arg1, arg2);
}

BinOp *ex_sar( Exp *arg1, int arg2 )
{
    arg1 = arg1->clone();
    return new BinOp(ARSHIFT, arg1, ex_const(arg2));
}

BinOp *_ex_eq( Exp *arg1, Exp *arg2 )
{
    return new BinOp(EQ, arg1, arg2);
}

BinOp *ex_eq( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(EQ, arg1, arg2);
}

BinOp *_ex_neq( Exp *arg1, Exp *arg2 )
{
    return new BinOp(NEQ, arg1, arg2);
}

BinOp *ex_neq( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(NEQ, arg1, arg2);
}

BinOp *ex_gt( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(GT, arg1, arg2);
}

BinOp *ex_lt( Exp *arg1, Exp *arg2 )
{   
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(LT, arg1, arg2);
}

BinOp *ex_ge( Exp *arg1, Exp *arg2 )
{
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(GE, arg1, arg2);
}

BinOp *ex_le( Exp *arg1, Exp *arg2 )
{   
    arg1 = arg1->clone();
    arg2 = arg2->clone();
    return new BinOp(LE, arg1, arg2);
}

Cast *ex_u_cast( Exp *arg, reg_t width )
{
  arg = arg->clone();
  return new Cast(arg, width, CAST_UNSIGNED);
}

Cast *_ex_u_cast( Exp *arg, reg_t width )
{
    return new Cast(arg, width, CAST_UNSIGNED);
}

Cast *ex_s_cast( Exp *arg, reg_t width )
{
    arg = arg->clone();
    return new Cast(arg, width, CAST_SIGNED);
}

Cast *_ex_s_cast( Exp *arg, reg_t width )
{
    return new Cast(arg, width, CAST_SIGNED);
}

Cast *ex_h_cast( Exp *arg, reg_t width )
{
    arg = arg->clone();
    return new Cast(arg, width, CAST_HIGH);
}

Cast *ex_l_cast( Exp *arg, reg_t width )
{
    arg = arg->clone();
    return new Cast(arg, width, CAST_LOW);
}

Cast *_ex_l_cast( Exp *arg, reg_t width )
{
    return new Cast(arg, width, CAST_LOW);
}

Cast *ex_i_cast( Exp *arg, reg_t width )
{
    arg = arg->clone();
    return new Cast(arg, width, CAST_INTEGER);
}

Cast *ex_f_cast( Exp *arg, reg_t width )
{
    arg = arg->clone();
    return new Cast(arg, width, CAST_FLOAT);
}

Cast *ex_ri_cast( Exp *arg, reg_t width )
{
    arg = arg->clone();
    return new Cast(arg, width, CAST_RINTEGER);
}

Cast *ex_rf_cast( Exp *arg, reg_t width )
{
    arg = arg->clone();
    return new Cast(arg, width, CAST_RFLOAT);
}

