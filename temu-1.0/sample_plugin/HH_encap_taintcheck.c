#include <stdlib.h>
#include <inttypes.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>

#include "../taintcheck.h"
#include "H_taint_record.h"
#include "HH_encap_taintcheck.h"

#include "../TEMU_main.h"
#include "../TEMU_lib.h"

HH_encap_tc_vaddr_list_t  h_encap_vaddr_tclist;

			  // h_encap_vaddr_tclist;

/* ---------------------------------------------------------------------------------------------------------------------- */
void HHui_init_tc_vaddr_list( )
{
    h_encap_vaddr_tclist.head  = NULL;
    h_encap_vaddr_tclist.end   = NULL;

    h_encap_vaddr_tclist.count = 0;
}// end of HHui_init_tc_vaddr_list( )


void HHui_delete_tc_vaddr_list( )
{
    if(h_encap_vaddr_tclist.count == 0)
    {
	return;
    }// end of if( ) 
	
    PHH_encap_tc_vaddr_entry_t entry = (h_encap_vaddr_tclist.head)->next;

    while(h_encap_vaddr_tclist.head != NULL)
    {
	free(h_encap_vaddr_tclist.head) ;
	h_encap_vaddr_tclist.head = entry;
		
	if(entry == NULL)
	{
	    break;
	}// end of if( )

	entry = (h_encap_vaddr_tclist.head)->next;
    }// end of while{ }
	
	//free(HHui_module_list);
	//HHui_module_list = NULL;

    h_encap_vaddr_tclist.count = 0;	
    h_encap_vaddr_tclist.head  = NULL;
    h_encap_vaddr_tclist.end   = NULL;
        
}// end of HHui_delete_tc_vaddr_list( )




void HHui_add_tainted_vaddr( uint32_t vaddr,
			     uint32_t size
			   )
{
    PHH_encap_tc_vaddr_entry_t entry = (PHH_encap_tc_vaddr_entry_t)malloc(sizeof(HH_encap_tc_vaddr_entry_t));
    entry->vaddr = vaddr;
    entry->size  = size;
    entry->next  = NULL;

    if(h_encap_vaddr_tclist.count == 0)
    {
	h_encap_vaddr_tclist.head = entry;	
	h_encap_vaddr_tclist.end  = entry;
    }
    else
    {
	(h_encap_vaddr_tclist.end)->next = entry;
	h_encap_vaddr_tclist.end         = entry;
    }// end of if( )

    h_encap_vaddr_tclist.count = h_encap_vaddr_tclist.count + 1;

    // term_printf("111\n");

}// end of HHui_add_tainted_vaddr( )


void HHui_encap_taintcheck_taint_virtmem( uint32_t  vaddr,
					  uint32_t  size,
					  uint64_t  taint,
					  uint8_t * h_records
					)
{
    HHui_add_tainted_vaddr( vaddr,
			    size
			  );

    taintcheck_taint_virtmem( vaddr,
			      size,
			      taint,
			      h_records
			    );
}// end of HHui_encap_taintcheck_taint_virtmem( )



void HHui_encap_taintcheck_virtmem_save( QEMUFile * f,
					 void     * opaque
				       )
{
    TEMU_CompressState_t state;
    PHH_encap_tc_vaddr_entry_t entry = h_encap_vaddr_tclist.head;

    if( TEMU_compress_open( &state, 
			    f
			  ) < 0
      )
    {
	return;
    }// end of if(TEMU_compress_open)
    
    TEMU_compress_buf( &state,
		       ( (uint8_t *)( &(h_encap_vaddr_tclist.count) 
			   	    ) 
		       ),
		       4
		     );

    while(entry != NULL)
    {
        TEMU_compress_buf( &state,
		           ( (uint8_t *)( &(entry->vaddr) 
			   	        ) 
		           ),
		           4
		         );

        TEMU_compress_buf( &state,
		           ( (uint8_t *)( &(entry->size) 
			   	        ) 
		           ),
		           4
		         );	
	entry = entry->next;
    }// end of while{entry}    

    TEMU_compress_close(&state);
}// end of HHui_encap_taintcheck_virtmem_save( )


int HHui_encap_taintcheck_virtmem_load( QEMUFile * f,
				        void     * opaque,
	  			        int	   version_id
				      )
{
    int i     = 0;
    int count = 0;
    uint32_t vaddr = 0;
    uint32_t size  = 0;

    TEMU_CompressState_t state;
    
    HHui_delete_tc_vaddr_list( );
    HHui_init_tc_vaddr_list( );

    if( TEMU_decompress_open( &state,
			      f
			    ) < 0
      )
    {
	return -EINVAL;
    }// end of if(TEMU_decompress_open)

    TEMU_decompress_buf( &state,
		         ( (uint8_t *)&count ),
		         4
		       );	
    if(count == 0)
    {
	return 0;
    }// end of if(h_encap_vaddr_tclist.count)
    
    while(i < count)
    {	
	TEMU_decompress_buf( &state,
		 	     &vaddr,
		             4
		       	   );	
	TEMU_decompress_buf( &state,
		 	     &size,
		             4
		       	   );

	HHui_add_tainted_vaddr( vaddr,
			        size
			      );
	i = i + 1;
    }// end of while{i}

}// end of HHui_encap_taintcheck_virtmem_load( )


void HHui_encap_taintcheck_virtmem_register( )
{
    register_savevm( "HHui_encap_taintcheck_virtmem",
		     0,
		     1,
		     HHui_encap_taintcheck_virtmem_save,
		     HHui_encap_taintcheck_virtmem_load,
		     NULL
		   );
}// end of func_summ_taintcheck_register( )
/* ---------------------------------------------------------------------------------------------------------------------- */
