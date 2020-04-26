#ifndef H_INSN_TAINT_STATE_H
	#define H_INSN_TAINT_STATE_H

	#include <ctypes.h>
	#include <inttypes.h>
	#include <malloc.h>
	#include "H_taint_record.h"

	#include "../taintcheck.h"



	/*
		Records up the taint influences of a specific insn
   	 */
	typedef struct H_taintinfo_ENTRY
	{
		char 		  type;
		char		  size;
		uint8_t		  taint;				
		int 		  mode;	
		uint32_t	  addr;
		uint8_t * 	  records;

		// specific the pre-states of the taint records for the dst operands
		H_taint_record_t  * dst_taint_record;
		struct H_taintinfo_ENTRY * next;

	}H_TAINTINFO_ENTRY, *PH_TAINTINFO_ENTRY;


	typedef struct H_taintinfo_list
	{
		PH_TAINTINFO_ENTRY  head;
		PH_TAINTINFO_ENTRY  end;
		int		    count;
	}H_TAINTINFO_LIST, *PH_TAINTINFO_LIST;



	extern H_TAINTINFO_LIST taint_info_list;



	void init_taintinfo_list( );
	void delete_taintinfo_list( );

	PH_TAINTINFO_ENTRY Add_taintinfo_entry( taint_operand_t  * dst_opnd,
						int		   mode 
					      );
	
#endif

