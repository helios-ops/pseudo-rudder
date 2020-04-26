#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include "key_taint_source_list.h"

PKEY_TAINT_SOURCE_ENTRY KEYSTROKE_Add_taint_source_entry( PKEY_TAINT_SOURCE_LIST list, 
						          int		         taint_id
			   		      		)
{
	if(list == NULL)
	{
		return NULL;
	}// end of if( )

	PKEY_TAINT_SOURCE_ENTRY entry = (PKEY_TAINT_SOURCE_ENTRY)malloc(sizeof(KEY_TAINT_SOURCE_ENTRY)) ;
	if(entry == NULL)
	{
	  	printf("struct KEY_TAINT_SOURCE_ENTRY allocation fault !\n");
		return NULL;
	}
	else
	{
	   	entry->origin = taint_id;
	}// end of if( )

	entry->next = NULL;

	if(list->head == NULL)
	{
		list->head = entry;	
		list->tail = entry;
	}
	else
	{
		list->tail  = entry;
	}// end of if( )

	return entry;
}// end of Add_taint_source_entry( PKEY_TAINT_SOURCE_LIST list, PKEY_TAINT_SOURCE_ENTRY entry)


void KEYSTROKE_delete_taint_source_list(PKEY_TAINT_SOURCE_LIST list)
{
	if(list == NULL)
	{
		return ;
	}// end of if( )

	PKEY_TAINT_SOURCE_ENTRY entry = list->head->next;
	while(list->head != NULL)
	{
		free(list->head) ;
		list->head = entry;
	} // end of while{ }
	
}// end of delete_taint_source_list(PKEY_TAINT_SOURCE_LIST list)


int KEYSTROKE_Find_specific_taint_source_in_list( PKEY_TAINT_SOURCE_LIST list,
						   int 		   	 taint_id
						 )
{
	PKEY_TAINT_SOURCE_ENTRY entry = list->head;
	while(entry != NULL)
	{
		if(entry->origin == taint_id)
		{
			return 0;
		}// end of if( )
		
		entry = entry->next;
	}// end of while{ }

	return 1;
}// end of KEYSTROKE_Find_specific_taint_source_in_list(PKEY_TAINT_SOURCE_LIST list,int taint_id)



PKEY_TAINT_SOURCE_LIST KEYSTROKE_init_taint_source_list( )
{
	PKEY_TAINT_SOURCE_LIST taint_source_list = (PKEY_TAINT_SOURCE_LIST)malloc(sizeof(KEY_TAINT_SOURCE_LIST));
	if(taint_source_list == NULL)
 	{
		printf("error malloc( ) for plugin !\n");
		return NULL;
	}// end of if( ) 

	taint_source_list->head = NULL;
	taint_source_list->tail = NULL;

	return taint_source_list;
}// end of KEYSTROKE_init_taint_source_list( )
