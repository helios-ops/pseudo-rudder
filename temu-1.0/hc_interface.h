/********************************************************************
 * AUTHORS: Vijay Ganesh, David L. Dill
 *
 * BEGIN DATE: November, 2005
 *
 * LICENSE: Please view LICENSE file in the home dir of this Program
 ********************************************************************/
// -*- c++ -*-
#ifndef _cvcl__include__c_interface_h_
#define _cvcl__include__c_interface_h_

/*
#ifndef __cplusplus
    #define __cplusplus
#endif
*/

#ifdef __cplusplus
extern "C"{
#endif


  //This gives absolutely no pointer typing at compile-time. Most C
  //users prefer this over stronger typing. User is the king. A
  //stronger typed interface is in the works.
  typedef void* HVC;
  typedef void* HExpr;
  typedef void* HType;



  // o  : optimizations
  // c  : check counterexample
  // p  : print counterexample
  // h  : help
  // s  : stats
  // v  : print nodes
  void vc_setFlags(char c);
  
  //! Flags can be NULL
  HVC vc_createValidityChecker(void);
  
  typedef HVC(*VC_CREATEVALIDITYCHECKER)(void);

  // Basic types
  HType vc_boolType(HVC vc);
  
  //! Create an array type
  HType vc_arrayType(HVC vc, HType typeIndex, HType typeData);

  /////////////////////////////////////////////////////////////////////////////
  // Expr manipulation methods                                               //
  /////////////////////////////////////////////////////////////////////////////

  //! Create a variable with a given name and type 
  /*! The type cannot be a function type. The var name can contain
    only variables, numerals and underscore. If you use any other
    symbol, you will get a segfault. */  
  HExpr vc_varExpr(HVC vc, char * name, HType type);

  //The var name can contain only variables, numerals and
  //underscore. If you use any other symbol, you will get a segfault.
  HExpr vc_varExpr1(HVC vc, char* name, 
		  int indexwidth, int valuewidth);

  //! Get the expression and type associated with a name.
  /*!  If there is no such Expr, a NULL Expr is returned. */
  //Expr vc_lookupVar(VC vc, char* name, Type* type);
  
  //! Get the type of the Expr.
  HType vc_getType(HVC vc, HExpr e);
  int   vc_getBVLength(HVC vc, HExpr e);  


  //! Create an equality expression.  The two children must have the same type.
  HExpr vc_eqExpr(HVC vc, HExpr child0, HExpr child1);
  
  // Boolean expressions
  
  // The following functions create Boolean expressions.  The children provided
  // as arguments must be of type Boolean.
  HExpr vc_trueExpr(HVC vc);

  typedef HExpr(*VC_TRUEEXPR)(HVC VC);

  HExpr vc_falseExpr(HVC vc);
  HExpr vc_notExpr(HVC vc, HExpr child);
  HExpr vc_andExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_andExprN(HVC vc, HExpr* children, int numOfChildNodes);
  HExpr vc_orExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_orExprN(HVC vc, HExpr* children, int numOfChildNodes);

  // ->
  HExpr vc_impliesExpr(HVC vc, HExpr hyp, HExpr conc);
  
  HExpr vc_iffExpr(HVC vc, HExpr left, HExpr right);

  // if --- then --- else
  HExpr vc_iteExpr(HVC vc, HExpr ifpart, HExpr thenpart, HExpr elsepart);

  
  //Boolean to single bit BV Expression
  HExpr vc_boolToBVExpr(HVC vc, HExpr form);

  // Arrays

/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
  //! Create an expression for the value of array at the given index
  HExpr vc_readExpr(HVC vc, HExpr array, HExpr index);

  //! Array update; equivalent to "array WITH [index] := newValue"
  HExpr vc_writeExpr(HVC vc, HExpr array, HExpr index, HExpr newValue);
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */  


  // Expr I/O
  //! Expr vc_parseExpr(VC vc, char* s);

  //! Prints 'e' to stdout.
  void vc_printExpr(HVC vc, HExpr e);

  //! Prints 'e' into an open file descriptor 'fd'
  void vc_printExprFile(HVC vc, HExpr e, int fd);

  //! Prints state of 'vc' into malloc'd buffer '*buf' and stores the 
  //  length into '*len'.  It is the responsibility of the caller to 
  //  free the buffer.
  void vc_printStateToBuffer(HVC vc, char **buf, unsigned long *len);

  //! Prints 'e' to malloc'd buffer '*buf'.  Sets '*len' to the length of 
  //  the buffer. It is the responsibility of the caller to free the buffer.
  void vc_printExprToBuffer(HVC vc, HExpr e, char **buf, unsigned long * len);

  //! Prints counterexample to stdout.
  void vc_printCounterExample(HVC vc);

  //! Prints variable declarations to stdout.
  void vc_printVarDecls(HVC vc);

  //! Prints asserts to stdout.
  void vc_printAsserts(HVC vc);

  //! Prints the state of the query to malloc'd buffer '*buf' and stores
  //! the length of the buffer to '*len'.  It is the responsibility of the
  //  caller to free the buffer.
  void vc_printQueryStateToBuffer(HVC vc, HExpr e,char **buf,unsigned long *len);

  //! Prints query to stdout.
  void vc_printQuery(HVC vc);

  /////////////////////////////////////////////////////////////////////////////
  // Context-related methods                                                 //
  /////////////////////////////////////////////////////////////////////////////
  
  //! Assert a new formula in the current context.  
  /*! The formula must have Boolean type. */
  void vc_assertFormula(HVC vc, HExpr e);
  
  //! Simplify e with respect to the current context
  HExpr vc_simplify(HVC vc, HExpr e);
  
  //! Check validity of e in the current context. e must be a FORMULA
  //
  //if returned 0 then input is INVALID. 
  //
  //if returned 1 then input is VALID
  //
  //if returned 2 then ERROR
  int vc_query(HVC vc, HExpr e);
  
  //! Return the counterexample after a failed query.
  HExpr vc_getCounterExample(HVC vc, HExpr e);

  //! get size of counterexample, i.e. the number of variables/array
  //locations in the counterexample.
  int vc_counterexample_size(HVC vc);
  
  //! Checkpoint the current context and increase the scope level
  //void vc_push(VC vc);
  
  //! Restore the current context to its state at the last checkpoint
  //void vc_pop(VC vc);
  
  //! Return an int from a constant bitvector expression
  int getBVInt(HExpr e);
  //! Return an unsigned int from a constant bitvector expression
  unsigned int getBVUnsigned(HExpr e);
  //! Return an unsigned long long int from a constant bitvector expressions
  unsigned long long int getBVUnsignedLongLong(HExpr e);
  
  /**************************/
  /* BIT VECTOR OPERATIONS  */
  /**************************/
  HType vc_bvType(HVC vc, int no_bits);
  HType vc_bv32Type(HVC vc);
  
  HExpr vc_bvConstExprFromStr(HVC vc, char* binary_repr);
  HExpr vc_bvConstExprFromInt(HVC vc, int n_bits, unsigned int value);
  HExpr vc_bvConstExprFromLL(HVC vc, int n_bits, unsigned long long value);
  HExpr vc_bv32ConstExprFromInt(HVC vc, unsigned int value);
  
  HExpr vc_bvConcatExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_bvPlusExpr(HVC vc, int n_bits, HExpr left, HExpr right);
  HExpr vc_bv32PlusExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_bvMinusExpr(HVC vc, int n_bits, HExpr left, HExpr right);
  HExpr vc_bv32MinusExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_bvMultExpr(HVC vc, int n_bits, HExpr left, HExpr right);
  HExpr vc_bv32MultExpr(HVC vc, HExpr left, HExpr right);
  // left divided by right i.e. left/right
  HExpr vc_bvDivExpr(HVC vc, int n_bits, HExpr left, HExpr right);
  // left modulo right i.e. left%right
  HExpr vc_bvModExpr(HVC vc, int n_bits, HExpr left, HExpr right);
  // left divided by right i.e. left/right
  HExpr vc_signBvDivExpr(HVC vc, int n_bits, HExpr left, HExpr right);
  // left modulo right i.e. left%right
  HExpr vc_signBvModExpr(HVC vc, int n_bits, HExpr left, HExpr right);

  // <
  HExpr vc_bvLtExpr(HVC vc, HExpr left, HExpr right);

  // <=
  HExpr vc_bvLeExpr(HVC vc, HExpr left, HExpr right);

  // >
  HExpr vc_bvGtExpr(HVC vc, HExpr left, HExpr right);

  // >=
  HExpr vc_bvGeExpr(HVC vc, HExpr left, HExpr right);
  
  HExpr vc_sbvLtExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_sbvLeExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_sbvGtExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_sbvGeExpr(HVC vc, HExpr left, HExpr right);
  
  HExpr vc_bvUMinusExpr(HVC vc, HExpr child);

  // bitwise operations: these are terms not formulas  
  HExpr vc_bvAndExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_bvOrExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_bvXorExpr(HVC vc, HExpr left, HExpr right);
  HExpr vc_bvNotExpr(HVC vc, HExpr child);
  
  HExpr vc_bvLeftShiftExpr(HVC vc, int sh_amt, HExpr child);
  HExpr vc_bvRightShiftExpr(HVC vc, int sh_amt, HExpr child);
  /* Same as vc_bvLeftShift only that the answer in 32 bits long */
  HExpr vc_bv32LeftShiftExpr(HVC vc, int sh_amt, HExpr child);
  /* Same as vc_bvRightShift only that the answer in 32 bits long */
  HExpr vc_bv32RightShiftExpr(HVC vc, int sh_amt, HExpr child);
  HExpr vc_bvVar32LeftShiftExpr(HVC vc, HExpr sh_amt, HExpr child);
  HExpr vc_bvVar32RightShiftExpr(HVC vc, HExpr sh_amt, HExpr child);
  HExpr vc_bvVar32DivByPowOfTwoExpr(HVC vc, HExpr child, HExpr rhs);

  HExpr vc_bvExtract(HVC vc, HExpr child, int high_bit_no, int low_bit_no);
  HExpr vc_bvBoolExtract(HVC vc, HExpr child, int bit_no);  
  HExpr vc_bvSignExtend(HVC vc, HExpr child, int nbits);
  
  /*C pointer support:  C interface to support C memory arrays in CVCL */
  HExpr vc_bvCreateMemoryArray(HVC vc, char * arrayName);
  HExpr vc_bvReadMemoryArray( HVC vc, 
			  					    HExpr array, HExpr byteIndex, int numOfBytes);
  
  HExpr vc_bvWriteToMemoryArray(HVC vc, 
			       				        HExpr array, HExpr  byteIndex, HExpr element, int numOfBytes);
  
  HExpr vc_bv32ConstExprFromInt(HVC vc, unsigned int value);
  
  //const char* exprString(HExpr e);
  char* exprString(HExpr e);

  // const char* typeString(HType t);
  char* typeString(HType t);

  HExpr getChild(HExpr e, int i);

  //1.if input expr is TRUE then the function returns 1;
  //
  //2.if input expr is FALSE then function returns 0;
  //
  //3.otherwise the function returns -1
  int vc_isBool(HExpr e);

  /* Register the given error handler to be called for each fatal error.*/
  void vc_registerErrorHandler(void (*error_hdlr)(const char* err_msg));

  int vc_getHashQueryStateToBuffer(HVC vc, HExpr query);

  //destroys the STP instance, and removes all the created expressions
  void vc_Destroy(HVC vc);

#ifdef __cplusplus
};
#endif

#endif


