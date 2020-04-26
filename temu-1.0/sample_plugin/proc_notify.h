#ifndef H_PROC_NOTIFY_H
	#define H_PROC_NOTIFY_H

	#include "H_test_config.h"

	/*
	void HHui_CreateProcessNotify( uint32_t pid,
			      	       uint32_t cr3
			     	     );

	*/

	void H_Load_MainModule_Notify( uint32_t pid,
			       	       char *   proc_name
			     	     );

	void HHui_remove_proc(uint32_t pid);


	#ifdef H_MANUALLY_SEARCHING_FOR_BRANCHES
	void H_search_new_path( );
	#endif
#endif
