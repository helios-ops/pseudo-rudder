#ifndef HHUI_MODULE_NOTIFY_H
	#define HHUI_MODULE_NOTIFY_H
	
	#include <ctype.h>
	#include <inttypes.h>

	#include "../shared/procmod.h"
	#include "function_summary.h"
	
	typedef struct module_entry
	{
	    tmodinfo_t module_info;	    
	    function_summary_list_entry_t func_list;
		
	    int isFocused;
	    struct module_entry * next;
	}MODULE_ENTRY, *PMODULE_ENTRY;


	typedef struct tmodinfo_list_t
	{
	    PMODULE_ENTRY module_entry_head;
	    PMODULE_ENTRY module_entry_tail;
	}MODULE_INFO_LIST, * PMODULE_INFO_LIST;


	typedef struct interested_module_entry
	{
	    char * name;
	    int    isFocused;
	    struct interested_module * next;
	}interested_module_entry_t, *Pinterested_module_entry_t;


	typedef struct interested_module_entry_list
	{
	    interested_module_entry_t * head;
	    interested_module_entry_t * end;
	    int count;
	}interested_module_entry_list_t, *Pinterested_module_entry_list_t;


// external data declaration
/* -------------------------------------------------------------------------------------------------- */	
	extern PMODULE_INFO_LIST HHui_module_list;
/* -------------------------------------------------------------------------------------------------- */	
// external data declaration




// external functions' declaration
/* -------------------------------------------------------------------------------------------------- */	
	void HHui_load_module( uint32_t pid, 
			       uint32_t cr3, 
			       char *   name, 
			       uint32_t base, 
			       uint32_t size
			     );

	PMODULE_ENTRY Add_modinfo_entry( PMODULE_INFO_LIST list, 
		                 	 char *	           name,
			        	 uint32_t	   base,
					 uint32_t	   size     
			      	       );


	void init_module_list( );

	
	void Delete_module_list( );



	PMODULE_ENTRY Find_specific_module_in_list( PMODULE_INFO_LIST  list,
						    char *	       name, 
			       		  	    uint32_t	       base, 
			       		  	    uint32_t	       size
					          );

        // Find the module for the specific virtual address in the monitored process's address space
	PMODULE_ENTRY Find_Module_for_VA(uint32_t v_addr);

	void Display_current_modules_in_list( ) ;

	void Gather_init_modules_info( char *   name,
			      	       int      pid,
			       	       uint32_t cr3
			     	     );

	int IsInOurMonitoredModules(uint32_t vaddr);

#ifndef INTERESTED_MODULE_MONITOR
    #define INTERESTED_MODULE_MONITOR
#endif

	// interested modules' utils
#ifdef INTERESTED_MODULE_MONITOR

	void remove_interested_module_list( );
	int Is_module_focused(char * name);

	// builds up interested module list
	void get_total_modules(char * name);

	// same version as get_total_modules( ) except that we import the module-names from file
	void get_total_modules_from_file( );

	// set the 'isFocused' values of the corresponding interested
	void get_focused_modules(char * interested_module_name);

	// same version as get_focused_modules( ) except that we import the module-names from file
	void get_focused_modules_from_file( );

	void dbg_display_total_interested_modules( );
#endif
/* -------------------------------------------------------------------------------------------------- */	
// external functions' declaration


    

	
#endif
