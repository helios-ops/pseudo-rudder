#include <stdlib.h>
#include <malloc.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <xed-interface.h>

#include "module_notify.h"
#include "call_analysis.h"
#include "../TEMU_main.h"
#include "../shared/hookapi.h"
#include "H_hookdata.h"
#include "../TEMU_lib.h"

#include "H_test_config.h"


extern PMODULE_ENTRY cur_module;
extern uint32_t      HHui_target_cr3;
// extern plugin_interface_t my_interface;

static H_callstack_list_t h_callstack_list;
static int callstack_fd = 0;


// snapshot-state related
/* ======================================================================== */
static void H_callstack_list_save( QEMUFile * f,
				   void     * opaque
			  	 )
{
    TEMU_CompressState_t state;
    uint32_t separator = 0;

    H_callstack_entry_t * entry = NULL;

    if( TEMU_compress_open( &state, 
			    f
			  ) < 0
      )
    {
	return;
    }// end of if(TEMU_compress_open)

    if(h_callstack_list.count == 0)
    {
	TEMU_compress_buf( &state,
		     	   (uint8_t *)&separator,
		           4
		         );    
    }
    else
    {
	TEMU_compress_buf( &state,
		     	   ( (uint8_t *)&(h_callstack_list.count) ),
		           4
		         );   

	entry = h_callstack_list.head;
	while(entry != NULL)
	{
	    TEMU_compress_buf( &state,
		               ( (uint8_t *)&(entry->ebp) ),
		               4
		             );   	    
	    entry = entry->next;
	}// end of while{entry}

	H_callstack_list_delete( );	
    }// end of if(h_callstack_list.count)
    
    
}// end of H_callstack_list_save( )


static int H_callstack_list_load( QEMUFile * f,
				  void	   * opaque,
				  int	     version_id  
			  	)
{
    TEMU_CompressState_t state;
    uint32_t value;
    uint32_t i     = 0;
    uint32_t count = 0;

    if( TEMU_decompress_open( &state,
			      f
			    ) < 0
      )
    {
	return -EINVAL;
    }// end of if(TEMU_decompress_open)

    TEMU_decompress_buf( &state,
			 (uint8_t *)&count,
			 4
		       );    
    if(count != 0)
    {
	H_callstack_list_init( );
	
	while(i != count)
	{
            TEMU_decompress_buf( &state,
			         (uint8_t *)&value,
			         4
		               );
	    H_callstack_list_add_entry(value);

	    i = i + 1;
	}// end of while{i}
    }// end of if(value)
    
    return 0;
}// end of H_callstack_list_load( )


void H_callstack_snapshot_util_init( )
{
    register_savevm( "H_callstack_list",
		     0,
		     1,
		     H_callstack_list_save,
		     H_callstack_list_load,
		     NULL
		   );
}// end of H_callstack_snapshot_util_init( )
/* ======================================================================== */


void H_callstack_list_init( )
{
    h_callstack_list.head  = NULL;
    h_callstack_list.end   = NULL;
    h_callstack_list.count = 0;

    umask(0);
    callstack_fd = open( "callstack.log",
		        (O_CREAT | O_RDWR),
			(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		       );
}// end of H_callstack_list_init( )


void H_callstack_list_delete( )
{
    H_callstack_entry_t * entry = h_callstack_list.head;
    while(entry != NULL)
    {
	h_callstack_list.head = entry->next;
	free(entry);
	entry = h_callstack_list.head;
    }// end of while{entry}

    h_callstack_list.head  = NULL;
    h_callstack_list.end   = NULL;
    h_callstack_list.count = 0;

    if(callstack_fd > 0)
    {
        close(callstack_fd);
    }// end of if(callstack_fd)

}// end of H_callstack_list_delete( )


void H_callstack_list_add_entry(uint32_t ebp)
{
    H_callstack_entry_t * entry = (H_callstack_entry_t *)malloc(sizeof(H_callstack_entry_t));
    entry->ebp  = ebp;
    entry->next = NULL;
    entry->prev = NULL;

    if(h_callstack_list.head == NULL)
    {
	h_callstack_list.head = entry;
	h_callstack_list.end  = entry;
    }
    else
    {
	entry->prev		     = h_callstack_list.end;
	(h_callstack_list.end)->next = entry;
	h_callstack_list.end	     = entry;	
    }// end of if(h_callstack_list)

    h_callstack_list.count = h_callstack_list.count + 1;
}// end of H_callstack_list_add_entry( )


/* hook function invoked when any called procedure returns */
static int H_call_analysis_ret(void * opaque)
{
    H_callstack_data_t  * hookdata = (H_callstack_data_t *)opaque;
    H_callstack_entry_t * entry    = h_callstack_list.end;

    uint32_t pre_eip = 0;

    uint32_t cr3 = 0;
    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if( !( (HHui_target_cr3 != 0) && 
	   (HHui_target_cr3 == cr3)
         )
      )
    {
	return 0;
    }// end of if(HHui_target_cr3)

    if(hookdata->ebp == 0x12ff84)
    {
	TEMU_read_mem( hookdata->ebp,
		       4,
		       &pre_eip
		     );
	term_printf( "hookdata->ebp == 0x12ff84, [0x12ff84] = %x\n",
		     pre_eip
		   );
    }// end of if(hookdata->ebp)

    while(entry != NULL)
    {
	if(entry->ebp == hookdata->ebp)
	{
	    if(entry == h_callstack_list.end)
	    {
		if(entry == h_callstack_list.head)
		{
		    h_callstack_list.head = NULL;
		    h_callstack_list.end  = NULL;
		}
		else
		{
		    (entry->prev)->next  = NULL;
	   	    h_callstack_list.end = entry->prev;
		}// end of if(entry)		
	    }
	    else if(entry == h_callstack_list.head)
	    {
		(entry->next)->prev   = NULL;
		h_callstack_list.head = entry->next;
	    }
	    else
	    {
		(entry->prev)->next = entry->next;
  	        (entry->next)->prev = entry->prev;
	    }// end of if(entry)

	    free(entry);
	    break;
	}// end of if(entry->ebp)

	entry = entry->prev;
    }// end of while{entry}

    h_callstack_list.count = h_callstack_list.count - 1;

    // free(hookdata->handle);
    hookapi_remove_hook(hookdata->handle);
    free(hookdata);
    return 0;
}// end of H_call_analysis_ret( )

void H_call_analysis(uint32_t next_eip)
{
    uint32_t cr3 = 0;
    uint32_t esp = 0;
    uint32_t eip = 0;
    uint32_t pre_eip = 0;

    char     buffer[1024];
    int      count = 0;
 
    char     buf[15];
    char     str[128];

    H_callstack_data_t *  hookdata = NULL;

    xed_decoded_inst_t xedd;
    xed_error_enum_t   xed_error;

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if( (HHui_target_cr3 != 0) && 
	(HHui_target_cr3 == cr3)
      )
    {
	eip = *TEMU_cpu_eip;
	
	if(cur_module == NULL)
	{
	    return;
	}// end of if(Find_Module_for_VA)	

    #ifdef HHUI_CALLSTACK_MONITOR_ONLY_APPLEVEL
	if(*TEMU_cpu_eip >= 0x80000000)
	{
	    return;
	}// end of if(*TEMU_cpu_eip)
    #endif

	esp = TEMU_cpu_regs[R_ESP];
	TEMU_read_mem( esp,
		       4,
		       &pre_eip
		     );
	
	TEMU_read_mem( eip, 
		       15, 
		       buf
		     );

	// filter out those instructions that are not 'CALL'
	if( ( (buf[0] != (char)0xE8) &&
	      (buf[0] != (char)0xFF)
	    ) &&
	    (buf[0] != (char)0x9A)
	  )
	{
	    return;
	}// end of if(buf)

 	if(0x12ff84 == esp)
	{
	    term_printf( "esp = 0x12ff84, [esp] = %x\n",
			 pre_eip
		       );
	}
	
	/* here, I would hook the corresponding RET point in 
	   order to clear the previously pushed CALL record
 	 */
	hookdata = (H_callstack_data_t *)malloc(sizeof(H_callstack_data_t));
	hookdata->ebp    = esp;
	hookdata->handle = hookapi_hook_return( next_eip,
			   			H_call_analysis_ret,
			     			hookdata,
			     			sizeof(H_callstack_data_t)
		           		      );

	
	xed_decoded_inst_set_mode( &xedd, 
		  	           XED_MACHINE_MODE_LEGACY_32, 
				   XED_ADDRESS_WIDTH_32b
				 );	    		
	xed_error = xed_decode( &xedd, 
	    	     	        STATIC_CAST(const xed_uint8_t*,buf),
		                15
			      );
	if(xed_error == XED_ERROR_NONE) 
        {
            xed_decoded_inst_dump_intel_format( &xedd, 
						str, 
						sizeof(str), 
						0
					      );
	}// end of if(xed_error)
		
	count = sprintf( buffer,
			 "[%x]=%x, cur_eip=%x, insn: %s, insn[0]=0x%x\n",
		         esp,
		         pre_eip,
		         eip,
			 str,
			 buf[0]
		       );
	buffer[count] = '\0';
 	
	H_callstack_list_add_entry(esp);
	
	write( callstack_fd,
	       buffer,
	       count
	     );	
	
    }// end of if(HHui_target_cr3)

}// end of H_call_analysis( )


/* return 1 indicates OK, 0 indicating none */
int Find_callstack_by_vaddr( uint32_t   vaddr,
			     uint32_t * eip_base
			   )
{
    H_callstack_entry_t * entry = h_callstack_list.end;
    while(entry != NULL)
    {
	if(vaddr < entry->ebp)
	{
	    *eip_base = entry->ebp;
	    return 1;
	}// end of if(vaddr)

	entry = entry->prev;
    }// end of while{entry}

    return 0;
}// end of Find_callstack_by_vaddr( )


int Fetch_all_ebps_from_callstack(uint32_t ** ebp_array)
{
    H_callstack_entry_t * entry = h_callstack_list.head;
    int i = 0;

    if(h_callstack_list.count == 0)
    {
	return 0;
    }// end of if(h_callstack_list.count)

    *ebp_array = (uint32_t *)malloc(sizeof(uint32_t) * h_callstack_list.count);
    while(entry != NULL)
    {
	(*ebp_array)[i] = entry->ebp;
	entry = entry->next;

	/*
	term_printf( "callstack[%d] =  0x%x, ",
		     i,
		     (*ebp_array)[i]
		   );
	*/
	i = i + 1;
    }// end of while{entry}

    return h_callstack_list.count;
}// end of Fetch_all_ebps_from_callstack( )


void dump_callstack( )
{
    uint32_t ebp;
    uint32_t eip;
    int	     i = 0;
    H_callstack_entry_t * entry = h_callstack_list.head;

    while(entry != NULL)
    {
	ebp = entry->ebp;
	TEMU_read_mem( ebp,
		       4,
		       &eip
		     );

	term_printf( "%d: [0x%x] = 0x%x\n",
		     i,
		     ebp,
		     eip
		   );
	i = i + 1;
	entry = entry->next;
    }// end of while{entry}
}// end of dump_callstack( )



