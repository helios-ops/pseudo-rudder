#include <stdlib.h>

#include "H_STP_stub.h"
#include "stp_variables.h"

#include "hc_interface.h"

extern OBTAIN_STP_UTILS_FROM_PLUGIN	  Obtain_stp_utils_From_plugin;

void HH_Obtain_stp_utils_From_plugin( )
{
    Obtain_stp_utils_From_plugin(
    vc_createValidityChecker,
    vc_setFlags,

vc_boolType,
vc_arrayType,

vc_varExpr,
vc_varExpr1,


vc_getType,
vc_getBVLength,

vc_eqExpr,
vc_trueExpr,
vc_falseExpr,

vc_notExpr,
vc_andExpr,
vc_andExprN,

vc_orExpr,
vc_orExprN,

vc_impliesExpr,
vc_iffExpr,
vc_iteExpr,


vc_boolToBVExpr,

vc_readExpr,
vc_writeExpr,

vc_printExpr,
vc_printExprFile,
NULL, // vc_printStateToBuffer,
vc_printExprToBuffer,

vc_printCounterExample,
vc_printVarDecls,
vc_printAsserts,

vc_printQueryStateToBuffer,
vc_printQuery,
vc_assertFormula,

vc_simplify,
vc_query,

vc_getCounterExample,
vc_counterexample_size,

vc_push,
vc_pop,

getBVInt,
getBVUnsigned,
getBVUnsignedLongLong,


vc_bvType,
vc_bv32Type,

vc_bvConstExprFromStr,
vc_bvConstExprFromInt,
vc_bvConstExprFromLL,
vc_bv32ConstExprFromInt,

vc_bvConcatExpr,

vc_bvPlusExpr,
vc_bv32PlusExpr,

vc_bvMinusExpr,
vc_bv32MinusExpr,

vc_bvMultExpr,
vc_bv32MultExpr,

vc_bvDivExpr,
vc_bvModExpr,
vc_sbvDivExpr,
vc_sbvModExpr,

vc_bvLtExpr,
vc_bvLeExpr,

vc_bvGtExpr,
vc_bvGeExpr,


vc_sbvLtExpr,
vc_sbvLeExpr,

vc_sbvGtExpr,
vc_sbvGeExpr,

vc_bvUMinusExpr,

vc_bvAndExpr,
vc_bvOrExpr,
vc_bvXorExpr,
vc_bvNotExpr,

vc_bvLeftShiftExpr,
vc_bvRightShiftExpr,

vc_bv32LeftShiftExpr,
vc_bv32RightShiftExpr,

vc_bvVar32LeftShiftExpr,
vc_bvVar32RightShiftExpr,


vc_bvVar32DivByPowOfTwoExpr,

vc_bvExtract,
vc_bvBoolExtract,

vc_bvSignExtend,


vc_bvCreateMemoryArray,

vc_bvReadMemoryArray,

vc_bvWriteToMemoryArray,


exprString,

typeString,

getChild,

vc_isBool,

vc_registerErrorHandler,

vc_getHashQueryStateToBuffer,

vc_Destroy,

vc_DeleteExpr,
vc_getWholeCounterExample,
vc_getTermFromCounterExample,

obtaint_stp_vars_array

 );


}














































