#include <stdlib.h>
#include <inttypes.h>
#include <malloc.h>
#include <errno.h>

#include "../shared/hookapi.h"
#include "../TEMU_main.h"
#include "../TEMU_lib.h"
#include "func_summ_hook.h"
#include "H_hookdata.h"

static func_ret_hook_list_t h_func_ret_hooks;

void init_func_ret_hook_list( )
{
    h_func_ret_hooks.head  = NULL;
    h_func_ret_hooks.end   = NULL;
    h_func_ret_hooks.count = 0;
}// end of init_func_ret_hook_list( )


void delete_func_ret_hook_list( )
{
    fun_ret_hook_entry_t * entry = h_func_ret_hooks.head;
    while(entry != NULL)
    {
	h_func_ret_hooks.head = (h_func_ret_hooks.head)->next;

	free(entry);
	entry = h_func_ret_hooks.head;
    }// end of while{entry}

    h_func_ret_hooks.count = 0;
}// end of delete_func_ret_hook_list( )


int find_func_ret_hook_in_list( uint32_t    eip,
				uint32_t    esp,
				hook_proc_t hookfn
			      )
{
    fun_ret_hook_entry_t * entry = h_func_ret_hooks.head;
    while(entry != NULL)
    {
	if( ( (entry->eip == eip) &&
	      (entry->esp == esp)
	    ) &&
	    (entry->hookfn == hookfn)
	  )
	{
	    return 1;
	}// end of if()

	entry = entry->next;
    }// end of while{entry}

    return 0;
}// end of find_func_ret_hook_in_list( )


void del_tail_entry_from_func_ret_hook_list( uint32_t    eip,
					     uint32_t    esp,
					     hook_proc_t hookfn
				           )
{
    fun_ret_hook_entry_t * entry = h_func_ret_hooks.end;
    if(entry == NULL)
    {
	return;
    }// end of if(entry)

    if( ( (entry->eip != eip) ||
	  (entry->esp != esp)
        ) ||
	(entry->hookfn != hookfn)
      )
    {
	return;
    }// end of if(entry)

    if(entry == h_func_ret_hooks.head)
    {
	h_func_ret_hooks.head = NULL;
	h_func_ret_hooks.end  = NULL;
    }
    else
    {
	(entry->prev)->next   = NULL;
	h_func_ret_hooks.end  = entry->prev;
    }// end of if(entry)

    free(entry);
    h_func_ret_hooks.count = h_func_ret_hooks.count - 1;

}// end of del_entry_from_func_ret_hook_list( )


void add_entry_2_func_ret_hook_list( uint32_t    eip,
				     uint32_t	 esp,
				     hook_proc_t hookfn,
				     void *	 func_entry,
				     uint32_t    sizeof_opaque 
				   )
{
    if( find_func_ret_hook_in_list( eip,
				    esp,
				    hookfn
			          )== 1
      )
    {
	return;
    }// end of if(find_func_ret_hook_in_list)

    fun_ret_hook_entry_t * entry = (fun_ret_hook_entry_t *)malloc(sizeof(fun_ret_hook_entry_t));
    entry->eip   	 = eip;
    entry->esp		 = esp;
    entry->hookfn	 = hookfn;
    entry->func_entry	 = func_entry;
    entry->sizeof_opaque = sizeof_opaque;
    entry->next		 = NULL;
    entry->prev		 = h_func_ret_hooks.end;

    if(h_func_ret_hooks.head == NULL)
    {
	h_func_ret_hooks.head = entry;
	h_func_ret_hooks.end  = entry;
    }   
    else
    {
	(h_func_ret_hooks.end)->next = entry;
	h_func_ret_hooks.end 	     = entry;
    }// end of if(h_func_ret_hooks.head)

    h_func_ret_hooks.count = h_func_ret_hooks.count + 1;
}// end of add_entry_2_func_ret_hook_list( )


void func_hook_save( QEMUFile * f,
		     void     * opaque
		   )
{
    TEMU_CompressState_t state;
    fun_ret_hook_entry_t * entry = NULL;

    if( TEMU_compress_open( &state, 
			    f
			  ) < 0
      )
    {
	return;
    }// end of if(TEMU_compress_open)

    TEMU_compress_buf( &state,
		       &(h_func_ret_hooks.count),
		       4
		     );
    if(h_func_ret_hooks.count == 0)
    {
	TEMU_compress_close(&state);
	return;
    }// end of if(h_func_ret_hooks.count)
    
    entry = h_func_ret_hooks.head;
    while(entry != NULL)
    {
        TEMU_compress_buf( &state,
		           &(entry->eip),
		           4
		         );

        TEMU_compress_buf( &state,
		           &(entry->esp),
		           4
			 );
	
        TEMU_compress_buf( &state,
		           &(entry->hookfn),
		           4
		         );

        TEMU_compress_buf( &state,
		           &(entry->func_entry),
		           4
		         );

	TEMU_compress_buf( &state,
		           &(entry->sizeof_opaque),
		           4
		         );

	entry = entry->next;
    }// end of while{entry}

    TEMU_compress_close(&state);

    // delete_func_ret_hook_list( );

}// end of func_hook_save( )



int func_hook_load( QEMUFile * f,
		    void     * opaque,
  		    int	       version_id
		  )
{
    TEMU_CompressState_t   state;

    uint32_t  count;
    uint32_t  eip;
    uint32_t  esp;
    uint32_t  hookfn;
    uint32_t  func_entry;
    uint32_t  sizeof_opaque;

    fun_ret_hook_entry_t * entry      = NULL;
    fun_ret_hook_entry_t * last_entry = NULL;

    delete_func_ret_hook_list( );

    H_function_summary_data_t * hookdata = NULL;

    if( TEMU_decompress_open( &state,
			      f
			    ) < 0
      )
    {
	return -EINVAL;
    }// end of if(TEMU_decompress_open)

    init_func_ret_hook_list( );

    TEMU_decompress_buf( &state,
	                 (uint8_t *)(&count),
		         4
		       );    
    if(count == 0)
    {
	return 0;
    }// end of if(value)
    
    
    // init_func_ret_hook_list( );    

    while(count != 0)
    {
        TEMU_decompress_buf( &state,
	                     (uint8_t *)(&eip),
		             4
		           );    
	
        TEMU_decompress_buf( &state,
	                     (uint8_t *)(&esp),
		             4
		           );    

	TEMU_decompress_buf( &state,
	                     (uint8_t *)( &(hookfn) ),
		             4
		           );    

	TEMU_decompress_buf( &state,
	                     (uint8_t *)( &(func_entry) ),
		             4
		           );    
 	TEMU_decompress_buf( &state,
	                     (uint8_t *)( &(sizeof_opaque) ),
		             4
		           );
    
	hookdata = (H_function_summary_data_t *)malloc(sizeof(H_function_summary_data_t));
        hookdata->func_summary_entry = func_entry;

/*
	hookdata->handle 	     = hookapi_hook_return( eip,
							    hookfn,
							    hookdata,
							    sizeof_opaque
							  );	
*/

        hookdata->handle = HH_hookapi_hook_return( eip, 
						   esp,
               					   hookfn, 
       		        			   hookdata,
               					   sizeof_opaque
               	      				 );

	/*
	add_entry_2_func_ret_hook_list( eip,
				        esp,
				        hookfn,
				        func_entry,
				        sizeof_opaque 
				      );
	*/

	count = count - 1;		
    }// end of while{h_func_ret_hooks.count}
    

    return 0;
}// end of func_hook_load( )


void register_func_hook( )
{
    register_savevm( "func_hook",
		     0,
		     1,
		     func_hook_save,
		     func_hook_load,
		     NULL
		   );
}// end of register_func_hook( )
