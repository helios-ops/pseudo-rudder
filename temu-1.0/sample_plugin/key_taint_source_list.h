#ifndef KEY_TAINT_SOURCE_LIST_H

	#define KEY_TAINT_SOURCE_LIST_H

	typedef struct key_taint_source_entry
	{
		int 			 	 origin;
		struct key_taint_source_entry *  next;
	}KEY_TAINT_SOURCE_ENTRY, *PKEY_TAINT_SOURCE_ENTRY;

	typedef struct key_tainty_source_list
	{
		PKEY_TAINT_SOURCE_ENTRY  head;
		PKEY_TAINT_SOURCE_ENTRY  tail;
	}KEY_TAINT_SOURCE_LIST, *PKEY_TAINT_SOURCE_LIST;


// operations
/* ----------------------------------------------------------------------------------------------- */	
	PKEY_TAINT_SOURCE_LIST KEYSTROKE_init_taint_source_list( );

	void KEYSTROKE_Delete_taint_source_list(PKEY_TAINT_SOURCE_LIST list);



	PKEY_TAINT_SOURCE_ENTRY KEYSTROKE_Add_taint_source_entry( PKEY_TAINT_SOURCE_LIST list, 
						  	          int		         taint_id
				   	     			);


	/*  if finding out taint_id in list, return true; else false */
	int  KEYSTROKE_Find_specific_taint_source_in_list( PKEY_TAINT_SOURCE_LIST list,
							   int 			  taint_id
							  );
/* ----------------------------------------------------------------------------------------------- */	


#endif
// key_taint_source_list.h
