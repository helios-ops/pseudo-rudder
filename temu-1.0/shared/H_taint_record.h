#ifndef HH_H_taint_record_H
	#define HH_H_taint_record_H


	#include "hc_interface.h"
	

	typedef struct H_taint_record
	{
		HExpr  	  h_expr;
		uint32_t  origin;		
		uint32_t  offset;

	}H_taint_record_t;

	extern FILE *my_log;
#endif
