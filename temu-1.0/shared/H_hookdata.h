#ifndef H_HOOKDATA_H
	#define H_HOOKDATA_H

	#include "hc_interface.h"

	typedef enum H_datatype
	{
	    BYTE = 0,
	    WORD,
	    DWORD,
	    STRING
	}H_datatype_t;


	typedef struct H_hookdata
	{
	    HVC       hvc;

	    int       taint_opnd_num;
	    char *    type;
	    
	}H_hookdata_t, *PH_hookdata;
#endif
