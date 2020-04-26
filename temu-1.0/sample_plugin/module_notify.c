#include <stdio.h>
#include <fcntl.h>

#include <malloc.h>
#include <string.h>

#include "main.h"

#include "hc_interface.h"
#include "module_notify.h"

#include "../TEMU_main.h"

#include "H_test_config.h"


extern HVC HHui_VC;
extern plugin_interface_t my_interface;

/*
// now does not introduce up the module filtering mechanism !
#ifdef MODULE_FILTERING
	#undef MODULE_FILTERING
#endif
*/

// Now we introduce up the the module filtering mechanism !
#ifndef MODULE_FILTERING
	#define MODULE_FILTERING
#endif


PMODULE_INFO_LIST HHui_module_list = NULL;


// module filters
static char * Modules_Ignored[ ] = {
					"ntdll.dll",
					"kernel32.dll",
					"user32.dll",
					"rpcrt4.dll",
					"advapi32.dll",
					"version.dll",
					"apphelp.dll"// ,

					// test for VisualPng.exe
					/* -------------------------------------------- */
					// "zlib1.dll",
					// "libpng13.dll"
					/* -------------------------------------------- */
				   };

#ifndef MODULE_FILTERING
	#define MODULE_FILTERING
#endif


char   module_path[128];
char * module_ptr = NULL;

// external data 
/* ------------------------------------------------------------------------------------------------------ */
extern uint32_t HHui_target_cr3;
extern INIT_TRANSLATION HH_Init_Translation;

/* ------------------------------------------------------------------------------------------------------ */
// external data 





// functions
/* ------------------------------------------------------------------------------------------------------ */

int Is_module_ignored(char * name)
{
// #ifdef MODULE_FILTERING
/*
    for(int i=0; i<(sizeof(Modules_Ignored))/(sizeof(char *)); i=i+1)
    {
	if( strcmp( name,
		    Modules_Ignored[i]
		  ) == 0
	  )
	{
	    return 1 ;
	}// end of if( )
    }// end of for{i}
 */

/*
    interested_module_entry_list_t * entry = h_interested_modules_list.head;
    while(entry != NULL)
    {
	if( strcmp( entry->name,
		    name
		  ) == 0
	  )
 	{
	    return 
	}// end of if(strcmp)

	entry = entry->next;
    }// end of while{entry}   
*/
    

// #endif

/*
#ifdef INTERESTED_MODULE_MONITOR
    if(Is_module_focused(name) == 0)
    {
	return 1;
    }// end of if(Is_module_focused)
#endif
*/

    return 0 ;
}// end of Is_module_ignored( )



// Recording future modules dynamically loaded after the initialization phase !
void HHui_load_module( uint32_t pid, 
		       uint32_t cr3, 
		       char *   name, 
		       uint32_t base, 
		       uint32_t size
		     )
{
	int fd 	      = -1;
	int isFocused = 0;
	PMODULE_ENTRY  entry = NULL;

	// Ignore those modules we do not want to consider
	/*
	if( Is_module_ignored(name) == 1 )
	{
	    return;
        }// end of if( )
	*/

	// Just only focus on those modules that reside in our monitored process's namespace !
	if( (HHui_target_cr3 == cr3) &&
	    (HHui_target_cr3 != 0)
	  )
	{
	    #ifdef INTERESTED_MODULE_MONITOR
		// not our interested module !
            	if( ( isFocused = Is_module_focused(name) ) == -1)
        	{
			return;	
	        }// end of if(Is_module_focused)
	    #endif

		/*
		if( strcmp( name, 
			    "kernel32.dll"
			  ) == 0
		  )
		{			
			HHui_ReadFile_Hooking(&HHui_VC) ;
			
		}// end of if( )
		*/

		// we should ignore thos modules that we explicitly denote as not-interested !
		if( Find_specific_module_in_list( HHui_module_list,
			 		    	  name, 
		       		  	    	  base, 
		       		  	    	  size
				                ) == NULL
		  )
		{
			term_printf("Module %s loaded in our monitored process's name space !\n", name);

			entry = Add_modinfo_entry( HHui_module_list,
			 			   name, 
		       			  	   base, 
		       			  	   size
			   		   	 );

			entry->isFocused = isFocused;

#ifdef HHUI_FUNC_SUMMARY_ENABLED		
			if(entry->isFocused)
			{
			    function_summary_init(entry);
			}// end of if(entry)
#endif			
			/*
			if(isFocused == 1)
			{
			    entry->isFocused = 1;
			}
			else
			{
			    entry->isFocused = 0;
			}// end of if(isFocused)
			 */
			
			/*
			    void HH_Init_Translation( char *   prog_name,
						      uint32_t base_va,
						      uint32_t size
					   	    )
			 */
			module_ptr = (char *)((char *)module_path + 16);
			  
			// Ensure the image file copy to be IR-lifted would be in the current directory

			// term_printf("module name is ");
			strcpy(module_ptr, name);

			module_path[16 + strlen(name)] = (char)0;
			term_printf("module path is %s\n", module_path);

			fd = open( module_path,
				   O_RDWR
				 );

			if(fd == -1)
			{
			    return;
			}
			else
			{
			    close(fd);
			    HH_Init_Translation( module_path,
					         base,
					         size,
					         term_printf
					       );
			}// end of if( )


			term_printf("Module Added!\n");
		}// end of if( )

	}// end of if()
	
}// end of HHui_load_module( uint32_t pid, uint32_t cr3, char * name, uint32_t base, uint32_t size)





PMODULE_ENTRY Add_modinfo_entry( PMODULE_INFO_LIST list, 
		                 char *	           name,
			         uint32_t	   base,
				 uint32_t	   size     
			       )
{
    if(list == NULL)
    {
	return NULL;
    }// end of if( )

    PMODULE_ENTRY entry = (PMODULE_ENTRY)malloc(sizeof(MODULE_ENTRY)) ;
    if(entry == NULL)
    {
	printf("struct KEY_TAINT_SOURCE_ENTRY allocation fault !\n");
	return NULL;
    }
    else
    {
	strcpy( (entry->module_info).name, 
		name
	      );

	(entry->module_info).base = base;
	(entry->module_info).size = size;				
    }// end of if( )

    entry->next = NULL;

    if(list->module_entry_head == NULL)
    {
	list->module_entry_head = entry;	
	list->module_entry_tail = entry;
    }
    else
    {
	list->module_entry_tail->next = entry;
	list->module_entry_tail       = entry;
    }// end of if( )
    
    
    (entry->func_list).head  = NULL;
    (entry->func_list).end   = NULL;
    (entry->func_list).count = 0;

/*
#ifdef INTERESTED_MODULE_MONITOR
    entry->isFocused = 0;

    if(Is_module_focused(name) == 1)
    {
	entry->isFocused = 1;
    }// end of if(Is_module_focused)
#endif
*/
	return entry;
}// end of Add_taint_source_entry( PKEY_TAINT_SOURCE_LIST list, PKEY_TAINT_SOURCE_ENTRY entry)




void Delete_module_list( )
{
	if( ( HHui_module_list == NULL ) || 
	    ( HHui_module_list->module_entry_head == NULL)
	  )
	{
		return ;
	}// end of if( )

	
	PMODULE_ENTRY entry = (HHui_module_list->module_entry_head)->next;
	while(HHui_module_list->module_entry_head != NULL)
	{
		free(HHui_module_list->module_entry_head) ;
		HHui_module_list->module_entry_head = entry;
		
		if(entry == NULL)
		{
			break;
		}// end of if( )

		entry = (HHui_module_list->module_entry_head)->next;
	} // end of while{ }
	
	free(HHui_module_list);
	HHui_module_list = NULL;

}// end of delete_taint_source_list(PKEY_TAINT_SOURCE_LIST list)



PMODULE_ENTRY Find_specific_module_in_list( PMODULE_INFO_LIST  list,
					    char *	       name, 
		       		  	    uint32_t	       base, 
		       		  	    uint32_t	       size
				          )
{
	PMODULE_ENTRY entry = list->module_entry_head;
	while(entry != NULL)
	{
		if(strcmp( (entry->module_info).name, 
			   name
		         ) == 0
		  )
		{
			if( (base == (entry->module_info).base) &&
			    (size == (entry->module_info).size)
			  )
			{
				return entry;
			}// end of if( )
			
		}// end of if( )
		
		entry = entry->next;
	}// end of while{ }

	return NULL;
}// end of Find_specific_module_in_list( )




void init_module_list( )
{
	module_path[0]	 = '.';
	module_path[1]   = '/';
	module_path[2]   = 't';
	module_path[3]   = 'e';
	module_path[4]   = 's';
	module_path[5]   = 't';
	module_path[6]   = '_';
	module_path[7]   = 'p';
	module_path[8]   = 'r';
	module_path[9]   = 'o';
	module_path[10]   = 'g';
	module_path[11]   = 'r';
	module_path[12]   = 'a';
	module_path[13]   = 'm';
	module_path[14]   = 's';
	module_path[15]   = '/';


	HHui_module_list = (PMODULE_INFO_LIST)malloc(sizeof(MODULE_INFO_LIST));
	if(HHui_module_list == NULL)
 	{
		printf("error malloc( ) for module list !\n");
		return;
	}// end of if( ) 

	HHui_module_list->module_entry_head = NULL;
	HHui_module_list->module_entry_tail = NULL;

	// return module_list;
}// end of KEYSTROKE_init_taint_source_list( )



/* checks whether a specific virtual address falls in the range of our intrested modules */
PMODULE_ENTRY Find_Module_for_VA(uint32_t v_addr)
{
    PMODULE_INFO_LIST list = HHui_module_list ;
    if(list == NULL)
    {
	return NULL;
    }// end of if( )

    PMODULE_ENTRY m_entry = list->module_entry_head;
    while(m_entry != NULL)
    {
	if( ( v_addr >= (uint32_t)(m_entry->module_info).base ) &&
	    ( v_addr <= ((uint32_t)(m_entry->module_info).base + (uint32_t)(m_entry->module_info).size) )
	  )
	{
	#ifdef INTERESTED_MODULE_MONITOR 
	    // denoting that any subsequent taint-introduction would be forbidden until a focused domain is entered.
	    if(m_entry->isFocused == 1)
	    {
	#endif
		my_interface.is_in_focused_module = 1;

	#ifdef INTERESTED_MODULE_MONITOR
	    }
	    else
	    {
		my_interface.is_in_focused_module = 0;
	    }// end of if(m_entry)	    
	#endif

	    return m_entry;	
	}// end of if( )
		
	m_entry = m_entry->next;

    }// end of while{ }

    return m_entry;
}// end of Find_Module_for_VA( )



int IsInOurMonitoredModules(uint32_t vaddr)
{
    PMODULE_ENTRY entry = Find_Module_for_VA(vaddr);
    
    if(entry == NULL)
    {
	return 0;
    }// end of if( )

    return 1;
}// end of IsInOurMonitoredModules( )


void Display_current_modules_in_list( )
{
    if(HHui_module_list == NULL)
    {
	term_printf("Module list initialization has not succeeded !\n");
	return;
    }// end of if( )

    PMODULE_ENTRY m_entry = HHui_module_list->module_entry_head;
    while(m_entry != NULL)	
    {
	term_printf( "Display: Currently loaded module : %s, base address = %08x, size = %08x, focused = %d \n", 
		     (m_entry->module_info).name,
		     (m_entry->module_info).base,
		     (m_entry->module_info).size,
		     m_entry->isFocused
		   );
			
	m_entry = m_entry->next ;
    }// end of while{m_entry}

}// end of Display_current_modules_in_list( )


void Gather_init_modules_info( char *   name,
			       int      pid,
			       uint32_t cr3
			     )
{
	uint32_t proc_id	 = 0;
	int 	 modules_num	 = find_process(
						cr3,
						name,
						&proc_id
					       );

	
	old_modinfo_t * old_mods = (old_modinfo_t *)malloc(sizeof(old_modinfo_t) * modules_num) ;
	if(old_mods == NULL)
	{
		printf("Getting old modules failed !\n");
		return;
	}// end of if( )


	if(HHui_module_list == NULL)
	{
		printf("Module list hasn't initialized yet !\n");
		return;
	}// end of if( )
	
	get_proc_modules( pid,
		          old_mods,
		    	  sizeof(old_modinfo_t) * modules_num
		        );

	for(int i=0; i<modules_num; i=i+1)
	{
		// Ignore those modules we do not want to consider
		if( Is_module_ignored( old_mods[i].name ) == 1 )
		{
		    continue ;
		}// end of if( )


		Add_modinfo_entry( HHui_module_list, 
			           old_mods[i].name,
				   old_mods[i].base,
				   old_mods[i].size     
			   	 );
		term_printf("module %s\n", old_mods[i].name);
	}// end of for{ }

}// end of Gather_init_modules_info( )




#ifdef INTERESTED_MODULE_MONITOR

static interested_module_entry_list_t h_interested_modules_list;


/* based on focused-module list, we set the 'isFocused' values of those corresponding 'interested_module_entry_t'
 */
void get_focused_modules(char * interested_module_name)
{
    char   buffer[1024];
    int    i = 0;
    int    count     = 0;
    char * end_idx   = NULL;
    char * start_idx = interested_module_name;
    interested_module_entry_t * entry = h_interested_modules_list.head;

    end_idx = strstr( start_idx,
		      "-"
		    );

    while(end_idx != NULL)
    {	
	/*		
	memcpy( buffer,
		start_idx,
		(int)(end_idx - start_idx)
	      );
	buffer[(int)(end_idx - start_idx)] = '\0';
	*/

	while(entry != NULL)
	{
	    /*
	    if( strcmp( entry->name,
			buffer
		      ) == 0 
	      )
	    {
		entry->isFocused = 1;
		break;
	    }// end of if(strcmp)
	    */
	    for(i = 0; i < (int)(end_idx - start_idx); i = i + 1)
	    {
		if( start_idx[i] != (entry->name)[i] )
		{
		    goto NEXT;
		}// end of if(start_idx)
	    }// end of for{i}

	    entry->isFocused = 1;
	    break;

NEXT:	    entry = entry->next;
	}// end of while{entry}

	start_idx = end_idx + 1;
	end_idx   = strstr( start_idx,
			    "-"
			  );
    }// end of while{end_idx}

}// end of get_focused_modules( )


void get_focused_modules_from_file( )
{
    // HHui Fixme: A better solution
    char buffer[100000];
    int  fd    = -1;
    int  count = 0;

    umask(0);
    fd = open( "H_focused_modules-list",
	       O_RDWR
	     );
    if(fd >= 0)
    {
	count = read( fd,
		      buffer,
		      100000
		    );
	buffer[count] = '\0';
	get_focused_modules(buffer);

	close(fd);
    }// end of if(fd)
}// end of get_focused_modules_from_file( )


void remove_interested_module_list( )
{
    interested_module_entry_t * entry = h_interested_modules_list.head;
    while(entry != NULL)
    {
	h_interested_modules_list.head = entry->next;

	free(entry->name);
	free(entry);

	entry = h_interested_modules_list.head;
    }// end of while{entry} 

    h_interested_modules_list.count = h_interested_modules_list.count - 1;
    h_interested_modules_list.head  = NULL;
    h_interested_modules_list.end   = NULL;
}// end of remove_interested_module_list( )


int Is_module_focused(char * name)
{
    interested_module_entry_t * entry = h_interested_modules_list.head;
    while(entry != NULL)
    {
	// is interested module
	if( strcmp( entry->name,
		    name
		  ) == 0 )
	{	    
	    if(entry->isFocused == 1)
	    {
	        // is Focused 
		return 1;
	    }
	    else
	    {
		return 0;
	    }// end of if(entry)
	}// end of if(strcmp)

	entry = entry->next;
    }// end of while{entry}

    // not monitored at all
    return -1;
}// end of Is_module_focused( )

void dbg_display_total_interested_modules( )
{
    interested_module_entry_t * entry = h_interested_modules_list.head;
    while(entry != NULL)
    {
	term_printf( "%s-- isfocused = %d\n",
		     entry->name,
		     entry->isFocused
		   );
	entry = entry->next;
    }// end of while{entry}
}// end of dbg_display_total_interested_modules( )


/* builds up interested module list (not focused modules) */
void get_total_modules(char * name)
{
    char * end_idx   = NULL;
    char * start_idx = name;
    interested_module_entry_t * entry = NULL;

    h_interested_modules_list.head  = NULL;
    h_interested_modules_list.end   = NULL;
    h_interested_modules_list.count = 0;

    end_idx = strstr( start_idx,
		      "-"
		    );

    while(end_idx != NULL)
    {
	entry 	         = (interested_module_entry_t *)malloc(sizeof(interested_module_entry_t));
	entry->name      = (char *)malloc(sizeof(char) * ( (int)(end_idx - start_idx) + 1 ));
	entry->isFocused = 0;

	memcpy( entry->name,
		start_idx,
		(int)(end_idx - start_idx)
	      );
	entry->name[(int)(end_idx - start_idx)] = '\0';
	entry->next = NULL;
	
	if(h_interested_modules_list.head == NULL)
	{
	    h_interested_modules_list.head = entry;
	    h_interested_modules_list.end  = entry;
	}
	else
	{
	    (h_interested_modules_list.end)->next = entry;
	    h_interested_modules_list.end	  = entry;
	}// end of if(h_interested_modules_list)
	h_interested_modules_list.count = h_interested_modules_list.count + 1;	

	start_idx = end_idx + 1;
	end_idx   = strstr( start_idx,
			    "-"
			  );
    }// end of while{end_idx}    
}// end of get_total_modules( )


// same version of get_total_modules( ). except we fetch the names from file
void get_total_modules_from_file( )
{
    // HHui Fixme: a better solution...
    char buffer[100000];
    int  fd    = -1;
    int  count = 0;
    umask(0);
    fd = open( "H_total-interested-modules-list",
	       O_RDWR
	     );
    if(fd >= 0)
    {
	count = read( fd,
		      buffer,
		      100000
		    );
	buffer[count] = '\0';
	get_total_modules(buffer);

        close(fd);
    }// end of if(fd)
}// end of get_total_modules_from_file( )



#endif
/* ------------------------------------------------------------------------------------------------------ */
// fucntions







