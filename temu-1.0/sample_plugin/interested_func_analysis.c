#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <inttypes.h>

#include "hc_interface.h"
#include "h_atoi.h"
#include "../shared/hookapi.h"
#include "../TEMU_main.h"
#include "interested_func_analysis.h"
#include "H_taint_record.h"
#include "call_analysis.h"
#include "record_potential_error2file.h"
#include "module_notify.h"

#include "H_test_config.h"


/* =================================================================================================== */
#include "string_interested_func_analysis.h"
#include "memory_interested_func_analysis.h"

/* =================================================================================================== */


extern HVC      HHui_VC;
extern HExpr    path_Expr;

extern char     monitored_proc[128];
extern uint32_t HHui_target_cr3;

static h_interested_func_list_t h_func_list;


char * interested_funcs_names[ ] = { 
				     // string-utls
				     "_strcpy",
				     "_strlen",

				     // memory-utils
				     "_malloc",
				     "_free",

				     NULL
				   };

hook_proc_t interested_funcs_hookfns[ ] = { 
	    				    // string-utls
					    _strcpy_hook_call,
				       	    _strlen_hook_call,

					    // memory-utils
					    _malloc_hook_call,
					    _free_hook_call,

					    NULL
				          };


void Hook_interested_funcs( )
{
#ifndef HHUI_IDA_INTEREdSTED_FUNC_IGNORE
    int i = 0;
    h_interested_func_entry_t * entry = NULL;

    for(entry = h_func_list.head; entry != NULL; entry = entry->next)
    {
        for(i = 0; interested_funcs_names[i] != NULL; i = i + 1)
        {
	    if( strcmp( entry->name,
			interested_funcs_names[i]
		      ) == 0
	      )
	    {
                hookapi_hook_function( 0,
			               entry->addr,
				       interested_funcs_hookfns[i], // hookfn
   	   			       NULL,			    // parametre
				       0			    // size of parametre
			             );
		break;
	    }// end of if()
        }// end of for{i}
    }// end of for{entry}
#endif
}// end of Hook_interested_funcs( )


static void add_h_interested_func_entry_to_list(h_interested_func_entry_t * entry)
{
#ifndef HHUI_IDA_INTEREdSTED_FUNC_IGNORE
    if(h_func_list.count == 0)
    {
	h_func_list.head = entry;
	h_func_list.end  = entry;	
    }
    else
    {
	(h_func_list.end)->next = entry;
	h_func_list.end	= (h_func_list.end)->next;
    }// end of if( )

    h_func_list.count = h_func_list.count + 1;
#endif
}// end of add_h_interested_func_entry_to_list( )


void interest_func_list_init( )
{
#ifndef HHUI_IDA_INTEREdSTED_FUNC_IGNORE
    int  i     = 0;
    int  fd    = 0;
    char buffer[1024];
    int  count = 0;
    char databuf[1024];
    char * tmp_pos = NULL;

    char * end_pos = NULL;
    char * pre_idx = NULL;
    char * cur_start_idx = NULL;
    char * cur_end_idx	 = NULL;

    char   str_ida_file_name[1024];
    count = sprintf( str_ida_file_name,
		     "./IDA_analysis/%s_interest_func_vaddr",
		     monitored_proc		     
		   );
    str_ida_file_name[count] = '\0';

    h_func_list.head  = NULL;
    h_func_list.end   = NULL;
    h_func_list.count = 0;

    fd = open( str_ida_file_name, // "IDA_analysis",
	       O_RDWR
	     );
    if(fd < 0)
    {
	return;
    }// end of if(fd < 0)

    count = read( fd,
		  buffer,
		  1024
		);
    buffer[count] = '\0';
    end_pos = (char *)((uint32_t)buffer + count - 1);
    pre_idx 	  = buffer;
    cur_start_idx = buffer;
    cur_end_idx   = buffer;

    h_interested_func_entry_t * entry = NULL;

    while(pre_idx < end_pos)
    {
	entry = (h_interested_func_entry_t *)malloc( sizeof(h_interested_func_entry_t) );
	entry->next = NULL;

	add_h_interested_func_entry_to_list(entry);

	// func-name extraction
	/* -------------------------------------------------- */
	cur_start_idx = strstr( pre_idx,
				"-"
			      );

	cur_start_idx = cur_start_idx + 1;
	pre_idx	      = cur_start_idx;
	
	cur_end_idx   = strstr( pre_idx,
				"-"
			      );
	memcpy( entry->name,
		cur_start_idx,
		(int)(cur_end_idx - cur_start_idx)
	      );
	(entry->name)[ (int)(cur_end_idx - cur_start_idx) ] = '\0';

	pre_idx	      = cur_end_idx + 1;	
	/* -------------------------------------------------- */		
	// func-name extraction


	// func-addr extraction
	/* -------------------------------------------------- */
	cur_start_idx = strstr( pre_idx,
				":"
			      );

	cur_start_idx = cur_start_idx + 1;
	pre_idx	      = cur_start_idx;
	
	cur_end_idx   = strstr( pre_idx,
				":"
			      );
	i = 0;
	for(tmp_pos = cur_start_idx; tmp_pos < cur_end_idx; tmp_pos = tmp_pos + 1)
	{
	    databuf[i] = tmp_pos[0];
	    i = i + 1;
	}// end of for{tmp_pos}
	// databuf[i + 1] = '\0';
	databuf[i] = '\0'; 

	entry->addr = h_atohex(databuf);

	pre_idx = cur_end_idx + 1;
	/* -------------------------------------------------- */		
	// func-addr extraction	

    }// end of while{pre_idx}

    if(fd >= 0)
    {
	close(fd);
    }// end of if(fd)

    // TEMU hook!    
    Hook_interested_funcs( );
#endif
}// end of interest_func_list_init( )


void interest_func_list_delete( )
{
#ifndef HHUI_IDA_INTEREdSTED_FUNC_IGNORE
    h_interested_func_entry_t * entry = NULL;
    
    for(entry = h_func_list.head; entry != h_func_list.end;)
    {
	h_func_list.head = entry->next;
	free(entry);

	entry = h_func_list.head;
    }// end of for{entry}

    free( h_func_list.end );

    h_func_list.head  = NULL;
    h_func_list.end   = NULL;
    h_func_list.count = 0;
#endif
}// end of interest_func_list_delete( )


/* =================================================================================================== */
int is_interested_func(char * str_func_name)
{
    int i = 0;
    for(i = 0; interested_funcs_names[i] != NULL; i = i + 1)
    {
	if(strcmp(interested_funcs_names[i], str_func_name) == 0)
	{
	    return i;
	}// end of if(strcmp)
    }// end of for{i}

    return -1;
}// end of is_interested_func( )


void hook_interested_func( int      func_index,
			   uint32_t func_vaddr,
			   uint32_t func_argsize
			 )
{
    hookapi_hook_function( 0,
			   func_vaddr,
			   interested_funcs_hookfns[func_index], // hookfn
   	   		   NULL,			    	 // parametre
			   0			    		 // size of parametre
			 );
}// end of hook_interested_func( )
/* =================================================================================================== */

