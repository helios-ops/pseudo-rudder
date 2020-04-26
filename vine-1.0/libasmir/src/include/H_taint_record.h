#ifndef HH_H_taint_record_H
	#define HH_H_taint_record_H

	// #include <ctypes.h>
	#include <inttypes.h>

	// #include "hc_interface.h"
	#include "H_STP_stub.h"

	typedef struct H_taint_record
	{
		HExpr  	  h_expr;
		int	  type;
		uint32_t  origin;
		uint32_t  offset;

	}H_taint_record_t;

	

	
#endif
