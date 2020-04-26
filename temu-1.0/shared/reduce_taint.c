/*
TEMU is Copyright (C) 2006-2009, BitBlaze Team.

TEMU is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU LGPL, version 2.1 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about TEMU and other BitBlaze software, see our
web site at: http://bitblaze.cs.berkeley.edu/
*/

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config.h"
#include "procmod.h"
#include "hooks/function_map.h"
#include "TEMU_main.h"
#include "hookapi.h"
#include "read_linux.h"

#include "../sample_plugin/H_test_config.h"

// STP related !
#include "hc_interface.h"
#include "../sample_plugin/H_taint_record.h"
#include "../sample_plugin/H_hookdata.h"
#include "../sample_plugin/HVM_state.h"

// adding all introduced STP-variables into list
#include "../sample_plugin/stp_variables.h"



#if TAINT_ENABLED

static int HHui_CreateFileA_return(void * opaque)
{
    H_CreateFileA_data_t * hookdata = (H_CreateFileA_data_t *)opaque;
    // uint32_t   = hookdata->esp;
    int	     fd       = -1;
    uint32_t filename = hookdata->filename;

    uint32_t cr3      = 0;

    if(temu_plugin->monitored_cr3 == 0)
    {
	goto HHui_CreateFileA_RETURNING;
    }// end of if( )

    TEMU_read_register( cr3_reg,
			&cr3
		      );    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	goto HHui_CreateFileA_RETURNING;
    }// end of if( )

    TEMU_read_register( eax_reg,
   		 	&fd
		      );
    if(fd == -1)
    {
	goto HHui_CreateFileA_RETURNING;
    }// end of if( )

    /*
    TEMU_read_mem( (org_esp + 4), // 1st parametre in the callstack !
		   4,
		   &filename
		 );
    */     
    temu_plugin->add_filehandle_to_list( filename, 			
					 fd
				       );

    term_printf( "\n ------------------------------ \n");

HHui_CreateFileA_RETURNING:
    hookapi_remove_hook(hookdata->handle);
    free(hookdata);
    return 0;
}// end of HHui_CreateFileA_return( )


/* though CreateFileW( )'s prototype differs from CreateFileA( )'s, it do share
   the same stack-frame with the latter. So the inner hooking do stay the same.
 */
static int HHui_CreateFileW_call(void * opaque)
{
#ifdef H_DEBUG_TEST
    static uint32_t last_eip = 0;
#endif

    uint32_t		   filename;
    uint32_t 	           ret_eip;
    H_CreateFileA_data_t * hookdata = NULL;

    // filter out those objects beyond our monitoring range 
    uint32_t cr3;

/*
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)
*/

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
		   4,
		   &filename
		 );

#ifdef H_DEBUG_TEST
    if(last_eip != 0)
    {
	if(last_eip == ret_eip)
	{
	    term_printf("warning: repeat callage for CreateFileW( )!\n");
	}// end of if(last_eip)
    }// end of if(last_eip)

    last_eip = ret_eip;
#endif

    term_printf( "\n ------------------------------ \nCreateFileW( ) called at address %x:\n",
		 ret_eip
	       );

    hookdata = (H_CreateFileA_data_t *)malloc(sizeof(H_CreateFileA_data_t));
    // hookdata->esp    = TEMU_cpu_regs[R_ESP];
    hookdata->filename = filename;
    hookdata->handle   = hookapi_hook_return( ret_eip,
					      HHui_CreateFileA_return,
		 		              hookdata,		            // parametre for HHui_OpenFile_return( )
 		  			      sizeof(H_CreateFileA_data_t)  // parametre size
		       			    );
    return 0;
}// end of HHui_CreateFileW_call( )


static int HHui_CreateFileA_call(void * opaque)
{
    uint32_t		   filename;
    uint32_t 	           ret_eip;
    H_CreateFileA_data_t * hookdata = NULL;

    // filter out those objects beyond our monitoring range 
    uint32_t cr3;

/*
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)
*/

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );

    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
		   4,
		   &filename
		 );
    hookdata = (H_CreateFileA_data_t *)malloc(sizeof(H_CreateFileA_data_t));
    // hookdata->esp    = TEMU_cpu_regs[R_ESP];
    hookdata->filename = filename;
    hookdata->handle   = hookapi_hook_return( ret_eip,
				  	      HHui_CreateFileA_return,
		 		              hookdata,		            // parametre for HHui_OpenFile_return( )
 		  			      sizeof(H_CreateFileA_data_t)  // parametre size
		       			    );
    return 0;
}// end of HHui_CreateFileA_call( )


static HHui_free_return(void * opaque)
{
    uint32_t cr3   = 0;
    uint32_t vaddr = 0;
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if(temu_plugin)

    
    TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4),
		   4,
		   &vaddr
		 );    
    delete_entry_from_heap_data_list(vaddr);

    return 0;
}// end of HHui_free_call( )


static int HHui_free_call(void * opaque)
{
    uint32_t cr3   = 0;
    uint32_t vaddr = 0;
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if(temu_plugin)

    
    TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4),
		   4,
		   &vaddr
		 );    
    delete_entry_from_heap_data_list(vaddr);

    return 0;
}// end of HHui_free_call( )


static int HHui_malloc_return(void * opaque)
{
    H_normal_data_t * hookdata = (H_normal_data_t *)opaque;
    uint32_t size = 0;
    uint32_t addr = 0;

    TEMU_read_mem( TEMU_cpu_regs[R_ESP], // size: 1st parametre in the callstack 
		   4,
		   &size
		 );
    
    TEMU_read_register( eax_reg,
			&addr
		      );
    if(addr != 0)
    {
	temu_plugin->add_entry_to_heap_data_list( addr,
					   	  size
			  	    		);
    }// end of if(addr)

    hookapi_remove_hook(hookdata->handle);
    free(hookdata);

    return 0;

}// end of HHui_malloc_ret( )

static int HHui_malloc_call(void * opaque)
{
    H_normal_data_t * hookdata = NULL;
    uint32_t cr3     = 0;
    uint32_t ret_eip = 0;

    HVM_param_t ** hvm_param = (HVM_param_t **)(opaque);

    int i = 0;
    uint64_t tcbmap  = 0;
    H_taint_record_t h_records[4]; 
    HVC      hvc           = *((*hvm_param)->hvc);
    HExpr    cur_path_expr = *((*hvm_param)->path_expr);
    HExpr    tmp_expr1 = NULL;
    HExpr    tmp_expr2 = NULL;
    HExpr    tmp_expr3 = NULL;
    int      qresult   = 0;
    uint32_t tmp_value = 0;
    char *   tmp_str   = NULL;

    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if(temu_plugin)
    
    
#ifdef HHUI_API_CALL_CHECK_TAINT_PARAMETRE
    tcbmap = taintcheck_check_virtmem( TEMU_cpu_regs[R_ESP],
				       4,
				       h_records
				     );
    if(tcbmap != 0)
    {
	if(tcbmap & 1)
	{
	    tmp_expr1 = (h_records[0]).h_expr;
	}
	else
	{
	    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
			   1,
			   &tmp_value
			 );
	    tmp_expr1 = vc_bvConstExprFromInt( hvc,
					       8,
					       tmp_value
					     );
	}// end of if(tcbmap)

	for(i = 1; i < 4; i = i + 1)
	{
	    if(tcbmap & (1 << i))
	    {
	        tmp_expr2 = (h_records[i]).h_expr;
	    }
	    else
	    {
	        TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + i),
			       1,
			       &tmp_value
			     );
	        tmp_expr2 = vc_bvConstExprFromInt( hvc,
					           8,
					           tmp_value
					         );
	    }// end of if(tcbmap)

	    tmp_expr1 = vc_bvConcatExpr( hvc,
					 tmp_expr2,
					 tmp_expr1
				       );
	}// end of for{i}

	tmp_expr2 = vc_bvConstExprFromInt( hvc,
					   32,
					   0
					 );
	tmp_expr3 = vc_bvLeExpr( hvc,
				 tmp_expr1,
				 tmp_expr2
			       );
		
	vc_push(hvc);
	qresult = vc_query( hvc,
			    vc_notExpr( hvc,
					vc_andExpr( hvc,
						    cur_path_expr,
						    tmp_expr3
					          )
				      )
			  );
	vc_pop(hvc);

	if(qresult == 0)
	{
	    term_printf("We find a parametre-error in malloc( ) !\n");

	    tmp_str = exprString(tmp_expr3);
	    if(temu_plugin->HHui_record_error_expr_2_file != NULL)
	    {
	        temu_plugin->HHui_record_error_expr_2_file(tmp_str);
	    }// end of if(temu_plugin)
	    free(tmp_str);
	}// end of if(qresult)
    }// end of if(tcbmap)
#endif

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );
    hookdata = (H_normal_data_t *)malloc(sizeof(H_normal_data_t));
    hookdata->handle = hookapi_hook_return( ret_eip,
					    HHui_malloc_return,
		         		    hookdata,		     // parametre for HHui_OpenFile_return( )
		         		    sizeof(H_normal_data_t)  // parametre size
		      			  );

    return 0;
}// end of HHui_malloc_call( )



extern HExpr hhui_expr;

// HHui elementary HOOKing for CloseHandle( )
/* ============================================================================================== */
static int HHui_CloseHandle_call( void * opaque )
{
    uint32_t ret_eip;
   
    // filter out those objects beyond our monitoring range 
    /* ------------------------------------------------------------------------------- */
    uint32_t cr3;

    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )

//    if( 0 == temu_plugin->IsInMonitoredModules(*TEMU_cpu_eip)
//      )
//    {
//	return 0;
//    }// end of if( )
    /* ------------------------------------------------------------------------------- */ // filter out those objects beyond our monitoring range 


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
    if(temu_plugin->current_monitored_thread == 0)
    {
	return 0;
    }// end of if(my_interface.current_monitored_thread)

    if(temu_plugin->current_monitored_thread == get_current_tid( ))
    {
	return 0;
    }// end of if(my_interface.current_monitored_thread)
#endif


    uint32_t fd = -1;
    TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4), // 1st parametre in the callstack 
		   4,
		   &fd
		 );

    if(NULL != temu_plugin->delete_filehandle_from_list)
    {
	temu_plugin->delete_filehandle_from_list(fd);
    }// end of if( )

    return 0;    
}// end of HHui_CloseHandle_call( )


void HHui_CloseHandle_Hooking( )
{
    hookapi_hook_function_byname( "kernel32.dll", 
				  "CloseHandle", 
				  0,
				  HHui_CloseHandle_call, 
				  NULL, // data, 
				  0     // sizeof(HVC **)
				);
}// end of HHui_CloseHandle_Hooking( )

/* ============================================================================================== */




// HHui elementary HOOKing for OpenFile( )
/* ============================================================================================== */
static int HHui_OpenFile_return( void * opaque )
{

    // term_printf( "111111111111111 !\n");

    H_OpenFile_data_t * hookdata = (H_OpenFile_data_t *)opaque;
    uint32_t cr3 = 0;

    char * filename = NULL;    
    uint32_t org_esp = hookdata->esp;

    uint32_t ret_eip = 0;
    TEMU_read_mem( org_esp, 
		   4,
		   &ret_eip
		 );
/*
    term_printf( "Hooking HHui_OpenFile_return( ) ---- eip = 0x%x, esp = 0x%x !\n",
		 ret_eip,
		 org_esp
	       );
 */

    TEMU_read_mem( (org_esp + 4), // 1st parametre in the callstack !
		   4,
		   &filename
		 );
    
    int	fd  = -1;
    TEMU_read_register( eax_reg,
   		 	&fd
		      );
    if(fd == -1)
    {
	goto HHui_OpenFile_RETURNING;
    }// end of if( )

    if(temu_plugin->monitored_cr3 == 0)
    {
	goto HHui_OpenFile_RETURNING;
    }// end of if( )

    TEMU_read_register( cr3_reg,
			&cr3
		      );    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	goto HHui_OpenFile_RETURNING;
    }// end of if( )

    // it's in our monitored range !
//    if( 1 == temu_plugin->IsInMonitoredModules(*TEMU_cpu_eip)
//      )
//    {

	/*
	term_printf( "openfile( ) --- filename = %s\n",
		     filename
		   );
	 */

	temu_plugin->add_filehandle_to_list( filename, 
				  	     // strlen(filename),
					     fd
				           );
//    }// end of if( )    

HHui_OpenFile_RETURNING:
    hookapi_remove_hook(hookdata->handle);
    free(hookdata);
    return 0;
}// end of HHui_OpenFile_return( )


static int HHui_OpenFile_call( void * opaque )
{
    uint32_t ret_eip;

    // filter out those objects beyond our monitoring range    
    /* -------------------------------------------------------------------------------- */
    uint32_t cr3;

/*
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)
*/

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )
    
//    if( 0 == temu_plugin->IsInMonitoredModules(*TEMU_cpu_eip)
//      )
//    {
//	return 0;
//    }// end of if( )
    /* -------------------------------------------------------------------------------- */ // filter out those objects beyond our monitoring range

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );
/*
    term_printf( "Hooking HHui_OpenFile_call( ) ---- eip = 0x%x, esp = 0x%x !\n",
		 ret_eip,
		 TEMU_cpu_regs[R_ESP]
	       );
 */
    /*
    char * filename = NULL;
    TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4),
	  	   4,
		   &filename
	         );
    term_printf( "Hooking HHui_OpenFile_call( ) ---- eip - %8x, filename = 0x%x, content is %s !\n",
		 ret_eip,
		 (uint32_t)filename,
		 filename
	       );    
    */
    H_OpenFile_data_t * hookdata = (H_OpenFile_data_t *)malloc( sizeof(H_OpenFile_data_t) );
    hookdata->esp = (uint32_t)( TEMU_cpu_regs[R_ESP] );   
    hookdata->handle = hookapi_hook_return( ret_eip,
					    HHui_OpenFile_return,
		         		    hookdata, 	    	       // parametre for HHui_OpenFile_return( )
		         		    sizeof(H_OpenFile_data_t)  // parametre size
		      			  );
    return 0;
}// end of HHui_OpenFile_call( )



void HHui_OpenFile_Hooking( )
{
      // HVC ** data = (HVC **)malloc(sizeof(HVC *)) ;
      // *data 	  = hvc;

      hookapi_hook_function_byname( "kernel32.dll", 
				    "OpenFile", 
				    0,
				    HHui_OpenFile_call, 
				    NULL, // data, 
				    0     // sizeof(HVC **)
				  );  	

}// end of HHui_OpenFile_Hooking( )

/* ============================================================================================== */ 









// HHui elementary taint source introduction for ReadFile( )
/* ============================================================================================== */
static int HHui_ReadFile_taint_source_id = 0 ;

static int HHui_ReadFile_return( void * opaque )
{
    H_ReadFile_data_t * hookdata = (H_ReadFile_data_t *)opaque;
    

    HVC      hvc     = *((HVC *)(hookdata->hvc)) ;
    uint32_t org_esp = hookdata->esp;
    

    char     var_name[300];
    int	     var_name_len = 0;
    
    char     id_name[100];
    int	     id_name_len;

    char     sub_id_name[100];
    int	     sub_id_name_len;

    uint32_t len_ptr ;
    uint32_t length;

    uint32_t buf_addr;

    int      eax = 0;

    uint32_t cr3;

#ifdef H_USE_PROTOCOL_ANALYSIS
    int    total_length_domain_count = 0;
    int *  total_length_domains	     = NULL;

    int    h_proto_i = 0;
    int    h_proto_j = 0;
#endif

    if(temu_plugin->monitored_cr3 == 0)
    {
	goto RETURNING ;
    }// end of if( )

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    
    if(cr3 != temu_plugin->monitored_cr3)
    {
	goto RETURNING;
    }// end of if( )


    // HHui added at March 6th, 2012
    /* ---------------------------------------------------- */
    TEMU_read_register( eax_reg,
			&eax
		      );    

    // ReadFile( ) encounters an error !
    if(eax == 0)
    {
	goto RETURNING;
    }// end of if(eax)
    /* ---------------------------------------------------- */


    H_taint_record_t * myrecord = NULL;

    int      i = 0;
    int	     j = 0;


    uint32_t input_len = 0 ;

    uint32_t ret_eip = 0 ;

    uint32_t file_offset = 0;
    char * file_name     = NULL;

    char tmpbuf[ ] = "hhui";

    Pfile_handle_entry_t filehandle_entry = NULL;
    int fd = -1;
    TEMU_read_mem( (org_esp + 4), // 1st parametre for ReadFile( ) --- file-descriptor !
		   4,
		   &fd
		 );

    if( ( temu_plugin->fetch_filehandle_entry_by_fd != NULL ) && 
	( ( filehandle_entry = temu_plugin->fetch_filehandle_entry_by_fd(fd) 
	  ) != NULL 
	)
      )
    {
	file_offset = filehandle_entry->foffset;
	file_name   = filehandle_entry->fname;
	
	term_printf( "filename : %s\n", 
		     file_name
		   );	
    }
    else
    {
    #ifdef HHUI_DEBUG_MODIFY_STATE
	if(temu_plugin->dbg_enable_taint == 1)
	{
	    file_name   = tmpbuf;
	    file_offset = 0;
	    goto HHUI_READFILE_RETURN_NEXT;
	}// end of if()
    #endif

	goto RETURNING;
    }// end of if( )

HHUI_READFILE_RETURN_NEXT:
/*
    term_printf( "ReadFile( ) cur eip = %08x\n",
		 *TEMU_cpu_eip
	       );
 */
    /* ---------------------------------------------------------------------------------------------------- */
    TEMU_read_mem( org_esp + 12, // 3rd parametre for ReadFile( ) --- ptr to the length
		   4,
		   &input_len
 		 );
/*
    term_printf( "ReadFile( ) input length = %d\n",
		 input_len
	       );
 */
    /* ---------------------------------------------------------------------------------------------------- */


    // Length of ReadFile( )
    /* ---------------------------------------------------------------------------------------------------- */
    TEMU_read_mem( org_esp + 16, // 4th parametre for ReadFile( ) --- ptr to the length  // (uint32_t)( TEMU_cpu_regs[R_ESP]
		   4,
		   &len_ptr
 		 );

    // The length of data from ReadFile( )
    TEMU_read_mem( len_ptr, // ptr to the data length
		   4,
		   &length
 		 );


    // HHui added at March 6th, 2012
    /* ---------------------------------------------------- */
    // ReadFile( ) read no input data !
    if(length <= 0)
    {
	goto RETURNING;
    }// end of if(eax)
    /* ---------------------------------------------------- */


// HHui added for LEN-analysis at August 15th, 2011 
    add_record_to_H_taint_origin_list( fd,
				       1,  // from file
				       file_offset,
				       (file_offset + length - 1)
				     );

    /* ---------------------------------------------------------------------------------------------------- */


    // Buffer of ReadFile( )
    /* ---------------------------------------------------------------------------------------------------- */
    TEMU_read_mem( org_esp + 8, // 2nd parametre for ReadFile( ) --- lpBuffer 
		   4,
		   &buf_addr
 		 );
/*
    term_printf( "ReadFile( ) output buffer = 0x%8x, tainted size = %d\n",
		 buf_addr,
		 length
	       );
 */
    /* ---------------------------------------------------------------------------------------------------- */           

    

    // var base-name !
    /* ------------------------------------------------------------------------------- */
    // HHui_ReadFile_taint_source_id = HHui_ReadFile_taint_source_id + 1 ;

    strcpy(var_name, "H_FILE_source_");
    var_name_len	   = strlen("H_FILE_source_");
    var_name[var_name_len] = (char)0;

    for(j=0; j<4; j=j+1)
    {
	id_name[j] = (char)0 ;
    }// end of for{i}

    sprintf( id_name, 
	     "%s_", 
	     file_name// ,
	     // file_offset // HHui_ReadFile_taint_source_id
	   );
    id_name_len = strlen(id_name) ;

	
    strcpy( var_name + var_name_len,
	    id_name
	  );
/*
    term_printf( "ReadFile( ) taint source introduction : %s ----- total length is %d\n", 
		 var_name,
		 length
	       );
 */
    var_name[var_name_len + id_name_len]     = '_';
    var_name[var_name_len + id_name_len + 1] = (char)0;
    /* ------------------------------------------------------------------------------- */



    for(j=0; j<4; j=j+1)
    {
        sub_id_name[j] = (char)0;
    }// end of for{j}


// signalling to the SYM-EXE monitor that some taints have been introduced to the target program !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
    temu_plugin->symexe_enabled_for_taint = 1;	
#endif


    // formalize the whole input as an array  ---- TO DO
    /* -------------------------------------------------------------------------------- */
    /*
    HType data_type  = vc_bvType( hvc,
				  8
				);
    
    HType index_type = vc_bv32Type(hvc);


    HType mystp_array__type = vc_arrayType( hvc,
					    index_type,
					    data_type
					  );
     */
    /* -------------------------------------------------------------------------------- */ // formalize the whole input as an array



// should we utilize protocol-analysis results so as to guide sym-taints' introduction ??
#ifdef H_USE_PROTOCOL_ANALYSIS
    if( (temu_plugin != NULL) && 
	(temu_plugin->proto_util != NULL)
      )
    {
	(temu_plugin->proto_util)->h_protocol_analysis_init( 0,
							     0,
							     file_name,
							     &total_length_domain_count,
							     &total_length_domains
							   );
    }// end of if(temu_plugin)
#endif

    
    HType mystp_type;	

    // taint every byte in the memory units buf_addr points to
    for(i=0; i<length; i=i+1)
    {	

// HHui added at March 12th, 2012 for protocol-analysis combination 
/* ========================================================================================= */
AGAIN_INTRODUCE_TAINT:

#ifdef H_USE_PROTOCOL_ANALYSIS
/*
 &total_length_domain_count,
 &total_length_domains,
 &domain_lengths
 */
	for(h_proto_i = 0; h_proto_i < total_length_domain_count; h_proto_i = h_proto_i + 1)
	{
	    if( (i >= total_length_domains[h_proto_i * 2]) && 
		(i <= total_length_domains[h_proto_i * 2 + 1])
	      )
	    {
		i = i + 1;

		// HHui patched at March 25th, 2012 --- the last one !
		/* ======================================================== */
		if( i == length)
		{
		    goto GOOD_READFILE_HOOKING_END;
		}// end of if(i)
		/* ======================================================== */

		goto AGAIN_INTRODUCE_TAINT;
	    }// end of if(i)
	}// end of for{h_proto_i}
#endif
/* ========================================================================================= */
// HHui added at March 12th, 2012 for protocol-analysis combination 



	/* ===================================================================================== */	
	myrecord 	 = (H_taint_record_t *)malloc( sizeof(H_taint_record_t) );

	// myrecord->origin = HHui_ReadFile_taint_source_id;
	myrecord->origin = 0x80000000 | fd;
        // myrecord->origin = fd;
	myrecord->type   = 1;
	myrecord->offset = file_offset + i;


	sprintf( sub_id_name,
		 "%d",
		 (file_offset + i)
	       );
	
	sub_id_name_len = strlen(sub_id_name);
	
	strcpy( var_name + var_name_len + id_name_len + 1,
		sub_id_name
	      );

	mystp_type = vc_bvType( hvc,
			        8
			      );		

	term_printf( "Readfile( ) varname for [0x%x]: %s\n",
		     buf_addr + i,
		     var_name
		   );
	/*
	myrecord->h_expr = vc_varExpr1( hvc, 
				        var_name,
					32,
					8
 				        // mystp_type   // value width
				       );	
	*/
	myrecord->h_expr = vc_varExpr( hvc,
				       var_name,
				       mystp_type
		  		     );

	// add introduced tainted variable(byte-wised introduction) to list
 	add_stp_vlist_entry( myrecord->h_expr );


/*		
	char * expr_str = exprString( myrecord->h_expr );
	term_printf( "sym-expression is %s -- addr is 0x%8x\n",
	   	     expr_str,
		     (uint32_t)(myrecord->h_expr)
		   );

 */

	// hhui_expr = myrecord->h_expr;

	/*
	HExpr ps_expr = vc_bvSignExtend( hvc, 
				     	 myrecord->h_expr, 
					 32
				       ); 

	*/

	/*
	HType mytype = vc_getType( hvc,
				   myrecord->h_expr
				 );
	char * type_str = typeString( mytype );
	term_printf( "type is %s -- \n",
	   	     expr_str
		   );
	*/

	// vc_printExpr(hvc, myrecord->h_expr);

	/* ===================================================================================== */	

	if(temu_plugin->HHui_encap_taintcheck_taint_virtmem != NULL)
	{
	    temu_plugin->HHui_encap_taintcheck_taint_virtmem( buf_addr + i, // vaddr
							      1,            // size
							      (uint64_t)1,  // taint-bitmap: 1 bit per byte
					      	              myrecord
						            );
	}// end of if(temu_plugin->HHui_encap_taintcheck_taint_virtmem)

	/*	
  	taintcheck_taint_virtmem( buf_addr + i, // vaddr
				  1,            // size
			          1,            // taint-bitmap: 1 bit per byte
			      	  myrecord
			        );	
	*/
	
    }// end of for{i}

GOOD_READFILE_HOOKING_END:

    filehandle_entry->foffset = file_offset + length;

#ifdef HH_TRACE_MONITOR    
    if(temu_plugin->trace_fd >= 0)
    {
        TEMU_read_mem( org_esp, // 1st parametre for ReadFile( ) --- file-descriptor !
		       4,
		       &ret_eip
		     );

	var_name_len = sprintf( var_name,
				"ReadFile( ) called at 0x%x: introduce taint [%d --- %d]\n",
				ret_eip,
				file_offset,
				filehandle_entry->foffset
			      );
	var_name[var_name_len] = '\0';

        write( temu_plugin->trace_fd,
	       var_name,
	       var_name_len
	     );
    }// end of if(my_interface.trace_fd)
#endif

    // term_printf("scanf( ) taint source introduction : %s\n", var_name);

    // free(hookdata);

RETURNING:

    // hookapi_record_t *
    hookapi_remove_hook(hookdata->handle);

    // term_printf("ReadFile hooking : hookapi_remove_hook( ) \n");

    // opaque data !
    free(hookdata);

    // ( ( (hookapi_record_t *)(hookdata->handle) )->opaque ) = NULL;

    return 0;
}// end of HHui_ReadFile_return( )


static int HHui_ReadFile_call( void * opaque )
{
    uint32_t fd = -1;
    uint32_t ret_eip;    
    uint32_t cr3;
    int      i = 0;
    char     filename[256];
/*
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)
*/

    TEMU_read_register( cr3_reg,
			&cr3
		      );

    // term_printf("HHui_ReadFile_call( ) called !\n");

    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )    

    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	// free(opaque);
	return 0;
    }// end of if( )
    
    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip		 
	         );
/*
    term_printf( "Hooking HHui_ReadFile_call( ) ---- eip - %8x !\n",
		 ret_eip
	       );    
 */
    TEMU_read_mem( (TEMU_cpu_regs[R_ESP] + 4),
		   4,
		   &fd
		 );

    /* checks whether the file currently reading is a interested taint source. Only sure 
       should we introduce some taints in the futural returning point for this ReadFile( ).
     */
    /* =================================================================================== */
    if( !( ( temu_plugin->fetch_filehandle_entry_by_fd != NULL ) && 
	   ( temu_plugin->fetch_filehandle_entry_by_fd(fd) != NULL )
         )
      )
    {	
	/* here are several state-monitoring utils which we could change by calling the corresponding 
	   modifying functions during the debugging session. 
	   Notify: when we build the final version, these should be disabled !
	 */
    #ifdef HHUI_DEBUG_MODIFY_STATE
	if(temu_plugin->dbg_enable_taint == 1)
	{
	    temu_plugin->current_monitored_thread = get_current_tid( );
	
	#ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
	    (temu_plugin->thc_util)->h_add_thread_context_2_list( temu_plugin->current_monitored_thread );
	#endif

	    goto HHUI_READFILE_RETURN_ENDING;
	}// end of if()
    #endif

	return 0;
    }// end of if( )
    /* =================================================================================== */


#ifdef HHUI_MONITOR_ONLY_ONE_TAINT_INTRODUCED_THREAD
  if(temu_plugin->current_monitored_thread == 0)
  {
      temu_plugin->current_monitored_thread = get_current_tid( );

  #ifdef H_HARDCODE_PATCH_TEMU_THREAD_CONTEXT
      (temu_plugin->thc_util)->h_add_thread_context_2_list( temu_plugin->current_monitored_thread );
  #endif

  }
  else if(temu_plugin->current_monitored_thread != get_current_tid( ))
  {
      return 0;
  }// end of if(temu_plugin)
#endif

    H_ReadFile_data_t * hookdata = NULL;

HHUI_READFILE_RETURN_ENDING:
    hookdata = (H_ReadFile_data_t *)malloc( sizeof(H_ReadFile_data_t) );

    hookdata->hvc = (HVC *)( (* (HVC **)opaque) );
    hookdata->esp = (uint32_t)( TEMU_cpu_regs[R_ESP] );
    

    hookdata->handle = hookapi_hook_return( ret_eip,
					    HHui_ReadFile_return,
		         		    hookdata, 	    	       // parametre for HHui_Getchar_return( )
		         		    sizeof(H_ReadFile_data_t)  // parametre size
		      			  );

    return 0;
}// end of HHui_ReadFile_call( )



/* WINBASEAPI __out LPVOID WINAPI MapViewOfFile(
					         __in HANDLE hFileMappingObject,
					         __in DWORD  dwDesiredAccess,
					         __in DWORD  dwFileOffsetHigh,
					         __in DWORD  dwFileOffsetLow,
					         __in SIZE_T dwNumberOfBytesToMap
					       );
 */
static int HHui_MapViewOfFile_return(void * opaque)
{
    int    i 	      = 0;
    int    base_count = 0;
    int    count      = 0;
    char   var_name[1024];
    char * ch_idx = 0;
    H_taint_record_t *   myrecord   = NULL;
    
    H_MapViewOfFile_data_t * hookdata   = (H_MapViewOfFile_data_t *)opaque;
    Pfile_handle_entry_t     file_entry = (hookdata->fileMap_entry)->file_entry;

    HVC	  hvc  = *(hookdata->hvc);
    HType mytp = vc_bvType( hvc,
			    8
			  );

    uint32_t dwFileOffsetHigh         = hookdata->dwFileOffsetHigh;
    uint32_t dwFileOffsetLow          = hookdata->dwFileOffsetLow;
    uint32_t dwNumberOfBytesToMap     = hookdata->dwNumberOfBytesToMap;

    // HHui Fixme: Here I only care for 32-bit system !
    uint32_t offset = dwFileOffsetLow;
    uint32_t va = 0;
    TEMU_read_register( eax_reg,
			&va
		      );
    if(va == 0)
    {
	goto HHUI_MAPVIEWOFFILE_RETURN_POINT;
    }// end of if(va)


// signalling to the SYM-EXE monitor that some taints have been introduced to the target program !
#ifdef HHUI_SYMEXE_DISABLE_UNTIL_TAINT_APPEAR
    temu_plugin->symexe_enabled_for_taint = 1;	
#endif

    // HHui Fixme: TODO a complete taint-introduction !
    /* --------------------------------------------------------------------------------- */    
    if(dwNumberOfBytesToMap != 0)
    {
	count = sprintf( var_name,
			 "H_FILE_source_%s_",
			 file_entry->fname			 
		       );
	var_name[count] = '\0';
	base_count = count;

	for(i = 0; i < dwNumberOfBytesToMap;i = i + 1)
	{
	    count = sprintf( var_name + base_count,
			     "%d",
			     (i + offset)
			   );	    
	    var_name[base_count + count] = '\0';	

	    myrecord = (H_taint_record_t *)malloc(sizeof(H_taint_record_t));
	    myrecord->origin = 0x80000000 | (file_entry->fd);
	    myrecord->offset = i + offset;
	    myrecord->type   = 1; // from disk
	    myrecord->h_expr = vc_varExpr( hvc,
				           var_name,
				           mytp
		  		         );
	    // add introduced tainted variable(byte-wised introduction) to list
 	    add_stp_vlist_entry(myrecord->h_expr);
	    
	    if(temu_plugin->HHui_encap_taintcheck_taint_virtmem != NULL)
	    {
	        temu_plugin->HHui_encap_taintcheck_taint_virtmem( va + i,      // vaddr
							          1,           // size
							          (uint64_t)1, // taint-bitmap: 1 bit per byte
					      	                  myrecord
						                );
	    }// end of if(temu_plugin->HHui_encap_taintcheck_taint_virtmem)

	    term_printf( "MapViewOfFile( ) varname for [0x%x]: %s\n",
		         va + i,
		         var_name
		       );
	}// end of for{i}

    #ifdef HH_TRACE_MONITOR    
        if(temu_plugin->trace_fd >= 0)
        {
	    count = sprintf( var_name,
			     "MapViewOfFile( ): introduce taint [%d --- %d]\n",
			     offset,
			     (offset + dwNumberOfBytesToMap)
			   );
	    var_name[count] = '\0';
            write( temu_plugin->trace_fd,
	           var_name,
	           count
	         );
        }// end of if(my_interface.trace_fd)
    #endif

    }
    else
    {
// TODO: [HHui Fixme] As dwNumberOfBytesToMap==0, we should consider the whole section !
	term_printf("MapViewOfFile( )...???\n");
    }// end of if(dwNumberOfBytesToMap)
    /* --------------------------------------------------------------------------------- */

HHUI_MAPVIEWOFFILE_RETURN_POINT:
    hookapi_remove_hook(((H_MapViewOfFile_data_t *)opaque)->handle);
    free((H_MapViewOfFile_data_t *)opaque);

    return 0;
}// end of HHui_MapViewOfFile_return( )


static int HHui_MapViewOfFile_call(void * opaque)
{
    HVC	*    hvc = *( (HVC **)opaque );
    uint32_t fmap_handle;
    uint32_t ret_eip;
    H_MapViewOfFile_data_t *         hookdata   = NULL;
    PfileMapping_handle_entry_list_t fmap_entry = NULL;

    uint32_t dwFileOffsetHigh;
    uint32_t dwFileOffsetLow;
    uint32_t dwNumberOfBytesToMap = 0;

    // filter out those objects beyond our monitoring range 
    uint32_t cr3;

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );

    // obtain the file handle
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
		   4,
		   &fmap_handle
		 );

    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 12,
		   4,
		   &dwFileOffsetHigh
		 );

    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 16,
		   4,
		   &dwFileOffsetLow
		 );

    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 16,
		   4,
		   &dwNumberOfBytesToMap
		 );


    // checks whether this file-map object is an interested one for taint-introduction.
    if( (temu_plugin != NULL) &&
	(temu_plugin->fetch_fileMappinghandle_entry_by_handle != NULL)
      )
    {
        fmap_entry = temu_plugin->fetch_fileMappinghandle_entry_by_handle(fmap_handle);
        if(fmap_entry != NULL)
        {
	    hookdata = (H_MapViewOfFile_data_t *)malloc(sizeof(H_MapViewOfFile_data_t));
	    hookdata->hvc		   = hvc;
	    hookdata->fileMap_entry	   = fmap_entry;
            hookdata->fmap_d		   = fmap_handle;
	    hookdata->dwFileOffsetHigh     = dwFileOffsetHigh;
	    hookdata->dwFileOffsetLow      = dwFileOffsetLow;
	    hookdata->dwNumberOfBytesToMap = dwNumberOfBytesToMap;
            hookdata->handle = hookapi_hook_return( ret_eip,
				     	            HHui_MapViewOfFile_return,
		 		                    hookdata,	
 		  			            sizeof(H_MapViewOfFile_data_t)  // parametre size
		       			          );    
        }// end of if(file_entry)    
    }// end of if(temu_plugin)
    return 0;
}// end of HHui_MapViewOfFile_call( )
/*
    WINBASEAPI __out HANDLE WINAPI CreateFileMappingA(
						       __in     HANDLE hFile,
						       __in_opt LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
						       __in     DWORD flProtect,
						       __in     DWORD dwMaximumSizeHigh,
						       __in      DWORD dwMaximumSizeLow,
						       __in_opt LPCSTR lpName
						     );

    WINBASEAPI __out HANDLE WINAPI CreateFileMappingW(
						       __in     HANDLE hFile,
						       __in_opt LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
						       __in     DWORD flProtect,
						       __in     DWORD dwMaximumSizeHigh,
						       __in     DWORD dwMaximumSizeLow,
						       __in_opt LPCWSTR lpName
						     );
 */
static int HHui_CreateFileMappingA_return(void * opaque)
{
    uint32_t eax = 0;
    TEMU_read_register( eax_reg,
			&eax
		      );
    if(eax == -1)
    {
	goto H_CREATEFILEMAPPINGA_RETURN;
    }// end of if(eax)

    if(temu_plugin->add_fileMappinghandle_to_list != NULL)    
    {
	temu_plugin->add_fileMappinghandle_to_list( ( (H_CreateFileMappingA_data_t *)opaque )->fmap_name,
						    // file-mapping object's name
						    eax, // file-mapping object's handle
						    // ( (H_CreateFileMappingA_data_t *)opaque )->file_d, // file-desc
						    ( (H_CreateFileMappingA_data_t *)opaque )->file_entry,
						    ( (H_CreateFileMappingA_data_t *)opaque )->size,
						    ( (H_CreateFileMappingA_data_t *)opaque )->a_or_w  // ascii or unicode
						  );
    }// end of if(temu_plugin)

H_CREATEFILEMAPPINGA_RETURN:
    hookapi_remove_hook(((H_CreateFileMappingA_data_t *)(opaque))->handle);
    free(opaque);
    return 0;
}// end of HHui_CreateFileMappingA_return( )

static int HHui_CreateFileMappingA_call(void * opaque)
{
    uint32_t		   filehandle;
    uint32_t		   fmap_name;
    uint32_t 	           ret_eip;
    int			   size = 0;

    H_CreateFileMappingA_data_t * hookdata   = NULL;
    Pfile_handle_entry_t   file_entry = NULL;

    // filter out those objects beyond our monitoring range 
    uint32_t cr3;

/*
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)
*/

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );

    // obtain the file handle
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
		   4,
		   &filehandle
		 );

    if( (temu_plugin != NULL) &&
	(temu_plugin->fetch_filehandle_entry_by_fd != NULL)
      )
    {
        file_entry = temu_plugin->fetch_filehandle_entry_by_fd(filehandle);
        if(file_entry != NULL)
        {
	    // obtain the size of the file-mapping object
	    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 20,
			   4,
			   &size
			 );

	    // obtain the name of the file mapping object, which would be bound to an interested file.
	    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 24,
		           4,
		           &fmap_name
		         );
	
	    hookdata = (H_CreateFileMappingA_data_t *)malloc(sizeof(H_CreateFileMappingA_data_t));
	    hookdata->a_or_w     = 0;  // ascii
	    // hookdata->file_d    = filehandle;	
	    hookdata->file_entry = file_entry;
            hookdata->fmap_name  = fmap_name;
	    hookdata->size       = size;
            hookdata->handle     = hookapi_hook_return( ret_eip,
				       	                HHui_CreateFileMappingA_return,
		 		                        hookdata,	
 		  			                sizeof(H_CreateFileMappingA_data_t)  // parametre size
		       			              );    
        }// end of if(file_entry)
    }// end of if(temu_plugin)
    
    return 0;   
}// end of HHui_CreateFileMappingA_call( )


static int HHui_CreateFileMappingW_call(void * opaque)
{
    int			   size = 0;
    uint32_t		   filehandle;
    uint32_t		   fmap_name;
    uint32_t 	           ret_eip;
    H_CreateFileMappingA_data_t * hookdata   = NULL;
    Pfile_handle_entry_t   file_entry = NULL;

    // filter out those objects beyond our monitoring range 
    uint32_t cr3;

/*
    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)
*/

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
	         );

    // obtain the file handle
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
		   4,
		   &filehandle
		 );

    if( (temu_plugin != NULL) &&
	(temu_plugin->fetch_filehandle_entry_by_fd != NULL)
      )
    {
        file_entry = temu_plugin->fetch_filehandle_entry_by_fd(filehandle);
        if(file_entry != NULL)
        {
	    // obtain the name of the file mapping object, which would be bound to an interested file.
	    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 24,
		           4,
		           &fmap_name
		         );
	
	    // obtain the size of the file-mapping object
	    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 20,
			   4,
			   &size
			 );

	    hookdata = (H_CreateFileMappingA_data_t *)malloc(sizeof(H_CreateFileMappingA_data_t));
	    // hookdata->file_d    = filehandle;
	    hookdata->file_entry = file_entry;
	    hookdata->a_or_w     = 1;  // unicode
            hookdata->fmap_name  = fmap_name;
	    hookdata->size	 = size;
            hookdata->handle     = hookapi_hook_return( ret_eip,
				     	                HHui_CreateFileMappingA_return,
		 		                        hookdata,	
 		  			                sizeof(H_CreateFileMappingA_data_t)  // parametre size
		       			              );
	}// end of if(file_entry)
    }// end of if(temu_plugin)
        
    return 0;
}// end of HHui_CreateFileMappingW_call( )




/* DWORD WINAPI SetFilePointer( _in	    HANDLE hFile,
				_in	    LONG   lDistanceToMove,	  // low-order 32-bits pf a sign value
			        _in_out_opt PLONG  lpDistanceToMoveHigh,  // a ptr to high-order 32-bits for 64-bits archs
				_in	    DWORD  dwMoveMethod		  // de-facto starting point for tge file ptr's move
			      )
   dwMoveMethod: FILE_BEGIN   --- 0
		 FILE_CURRENT --- 1
		 FILE_END     --- 2
 */
static int HHui_SetFilePointer_return(void * opaque)
{
    // modify the file-pointer so as to correctly introduce taint to the monitored process.

    int eax = 0;    
    H_SetFilePointer_data_t * hookdata   = (H_SetFilePointer_data_t *)opaque;
    Pfile_handle_entry_t      file_entry = hookdata->file_entry;

    TEMU_read_register(	eax_reg,
			&eax
		      );
    if(eax == -1) // INVALID_SET_FILE_POINTER
    {
        goto SetFilePointer_return_RETURN_POINT;
    }// end of if(eax)

    /* =========================  possibly just 'eax' is correctly  ========================= */
    switch(hookdata->start_pos)
    {
	case 0: // FILE_BEGIN
	{
	    file_entry->foffset = hookdata->offset;
	    break;
	}
	case 1: // FILE_CURRENT
	{
	    file_entry->foffset = file_entry->foffset + hookdata->offset;
	    break;
	}
	case 2: // FILE_END
	{
	    file_entry->foffset = eax;
	    break;
	}
	default:
	{
	    break;
	}
    }// end of switch{hookdata->start_pos}
    /* =========================  possibly just 'eax' is correctly  ========================= */

SetFilePointer_return_RETURN_POINT:
    hookapi_remove_hook(hookdata->handle);
    free(hookdata);
    return 0;
}// end of HHui_SetFilePointer_return( )


static int HHui_SetFilePointer_call(void * opaque)
{
    H_SetFilePointer_data_t * hookdata = NULL;
    Pfile_handle_entry_t      fentry   = NULL;

    int      fd;
    int      start_pos;
    int      offset;
    uint32_t ret_eip = 0;

    // filter out those objects beyond our monitoring range 
    uint32_t cr3;
    TEMU_read_register( cr3_reg,
			&cr3
		      );
    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    
    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	return 0;
    }// end of if( )
    
    // 1st parametre: filehandle
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4,
	  	   4,
		   &fd
		 );
    
    // checks whether it's an interested file-source or not.
    if( (temu_plugin != NULL) &&
	(temu_plugin->fetch_filehandle_entry_by_fd != NULL)
      )
    {
	fentry = temu_plugin->fetch_filehandle_entry_by_fd(fd);
	if(fentry == NULL)
	{
	    return 0;
	}// end of if(fentry)
    }// end of if()

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip
		 );

// HHui Fixme: here just consider 32-bits archs; TODO: 64-bits archs...
    // 2nd and 3rd parametres: offset
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 8,
	  	   4,
		   &offset
		 );

    // 4th parametre: start_pos
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 16,
	  	   4,
		   &start_pos
		 );

    hookdata = (H_SetFilePointer_data_t *)malloc(sizeof(H_SetFilePointer_data_t));
    hookdata->fd 	 = fd;
    hookdata->start_pos  = start_pos;
    hookdata->offset     = offset;
    hookdata->file_entry = fentry;
    hookdata->handle     = hookapi_hook_return( ret_eip,
				        	HHui_SetFilePointer_return,
		 		                hookdata,	
 		  			        sizeof(H_SetFilePointer_data_t)  // parametre size
		       			      );    
    return 0;
}// end of HHui_SetFilePointer_call( )

/* ============================================================================================== */

uint32_t HHui_ws2_32_recv_taint_source_id ;

static int HHui_ws2_32_recv_return( void * opaque )
{
    H_recv_data_t * hookdata = (H_recv_data_t *)opaque;
    

    HVC      hvc     = *((HVC *)(hookdata->hvc)) ;
    uint32_t org_esp = hookdata->esp;
    

    char     var_name[100];
    int	     var_name_len = 0;
    
    char     id_name[100];
    int	     id_name_len;

    char     sub_id_name[100];
    int	     sub_id_name_len;

    uint32_t len_ptr ;
    uint32_t length;

    uint32_t buf_addr;

    
    uint32_t cr3;

    if(temu_plugin->monitored_cr3 == 0)
    {
	goto RECV_RETURNING_POINT ;
    }// end of if( )

    TEMU_read_register( cr3_reg,
			&cr3
		      );
    
    if(cr3 != temu_plugin->monitored_cr3)
    {
	goto RECV_RETURNING_POINT;
    }// end of if( )


    H_taint_record_t * myrecord = NULL;

    int      i = 0;
    int	     j = 0;


    // int input_len = 0 ;

    uint32_t ret_eip = 0 ;
    

    term_printf( "recv( ) cur eip = %08x\n",
		 *TEMU_cpu_eip
	       );

    // length
    /* ---------------------------------------------------------------------------------------------------- */
    TEMU_read_register( eax_reg,
			&length
		      );

    if( (length == 0) || 
	(length == -1)
      )
    {
	goto RECV_RETURNING_POINT;
    }// end of if( )
    /* ---------------------------------------------------------------------------------------------------- */



    // Buffer of recv( )
    /* ---------------------------------------------------------------------------------------------------- */
    TEMU_read_mem( org_esp + 8, // 2nd parametre for recv( ) --- lpBuffer 
		   4,
		   &buf_addr
 		 );

    term_printf( "recv( ) output buffer = 0x%8x, tainted size = %d\n",
		 buf_addr,
		 length
	       );
    /* ---------------------------------------------------------------------------------------------------- */           

    

    // var base-name !
    /* ------------------------------------------------------------------------------- */
    HHui_ws2_32_recv_taint_source_id = HHui_ws2_32_recv_taint_source_id + 1 ;
    strcpy(var_name, "H_RECV_source_");
    var_name_len	   = strlen("H_RECV_source_");
    var_name[var_name_len] = (char)0;

    for(j=0; j<4; j=j+1)
    {
	id_name[j] = (char)0 ;
    }// end of for{i}

    sprintf(id_name, "%d", HHui_ReadFile_taint_source_id);
    id_name_len = strlen(id_name) ;

	
    strcpy( var_name + var_name_len,
	    id_name
	  );

    term_printf( "ReadFile( ) taint source introduction : %s ----- total length is %d\n", 
		 var_name,
		 length
	       );

    var_name[var_name_len + id_name_len]     = '_';
    var_name[var_name_len + id_name_len + 1] = (char)0;
    /* ------------------------------------------------------------------------------- */



    for(j=0; j<4; j=j+1)
    {
        sub_id_name[j] = (char)0;
    }// end of for{j}

    
    HType mystp_type;	

    // taint every byte in the memory units buf_addr points to
    for(i=0; i<length; i=i+1)
    {	

	/* ===================================================================================== */	
	myrecord 	 = (H_taint_record_t *)malloc( sizeof(H_taint_record_t) );

	myrecord->origin = HHui_ws2_32_recv_taint_source_id;
	myrecord->offset = 0;


	sprintf( sub_id_name,
		 "%d",
		 i
	       );
	
	sub_id_name_len = strlen(sub_id_name);
	

	strcpy( var_name + var_name_len + id_name_len + 1,
		sub_id_name
	      );


	mystp_type = vc_bvType( hvc,
			        8
			      );
	
		

	term_printf( "recv( ) varname : %s\n",
		     var_name
		   );
	/*
	myrecord->h_expr = vc_varExpr1( hvc, 
				        var_name,
					32,
					8
 				        // mystp_type   // value width
				       );	
	*/
	myrecord->h_expr = vc_varExpr( hvc,
				       var_name,
				       mystp_type
		  		     );

	// add introduced tainted variable(byte-wised introduction) to list
 	add_stp_vlist_entry( myrecord->h_expr );

/*		
	char * expr_str = exprString( myrecord->h_expr );
	term_printf( "sym-expression is %s -- addr is 0x%8x\n",
	   	     expr_str,
		     (uint32_t)(myrecord->h_expr)
		   );
 */


	// hhui_expr = myrecord->h_expr;

	/*
	HExpr ps_expr = vc_bvSignExtend( hvc, 
				     	 myrecord->h_expr, 
					 32
				       ); 

	*/

	/*
	HType mytype = vc_getType( hvc,
				   myrecord->h_expr
				 );
	char * type_str = typeString( mytype );
	term_printf( "type is %s -- \n",
	   	     expr_str
		   );
	*/

	// vc_printExpr(hvc, myrecord->h_expr);

	/* ===================================================================================== */	


  	taintcheck_taint_virtmem( buf_addr + i, // vaddr
				  1,            // size
			          1,            // taint-bitmap: 1 bit per byte
			      	  myrecord
			        );	

	
    }// end of for{i}

    // term_printf("scanf( ) taint source introduction : %s\n", var_name);

    // free(hookdata);

RECV_RETURNING_POINT:

    // hookapi_record_t *
    hookapi_remove_hook(hookdata->handle);

    term_printf("recv hooking : hookapi_remove_hook( ) \n");

    // opaque data !
    free(hookdata);

    // ( ( (hookapi_record_t *)(hookdata->handle) )->opaque ) = NULL;

    return 0;
    
}// end of HHui_ws2_32_recv_return(  )

static int HHui_ws2_32_recv_call( void * opaque )
{
    uint32_t ret_eip;    
    uint32_t cr3;

    // compositional symbolic execution 
    if(temu_plugin->is_in_focused_module == 0)
    {
	return 0;
    }// end of if(temu_plugin)

    TEMU_read_register( cr3_reg,
			&cr3
		      );

    // term_printf("HHui_ReadFile_call( ) called !\n");

    if(temu_plugin->monitored_cr3 == 0)
    {
	return 0;
    }// end of if( )
    

    if( ( temu_plugin->monitored_cr3 != 0 ) && 
	( cr3 != temu_plugin->monitored_cr3 )
      )
    {
	// free(opaque);
	return 0;
    }// end of if( )
    

    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip		 
	         );
    term_printf( "Hooking HHui_ws2_32_recv_call( ) ---- eip - %8x !\n",
		 ret_eip
	       );    

    H_recv_data_t * hookdata = (H_recv_data_t *)malloc( sizeof(H_recv_data_t) );

    hookdata->hvc = (HVC *)( (* (HVC **)opaque) );
    hookdata->esp = (uint32_t)( TEMU_cpu_regs[R_ESP] );
    

    hookdata->handle = hookapi_hook_return( ret_eip,
					    HHui_ws2_32_recv_return,
		         		    hookdata, 	    	 // parametre for HHui_Getchar_return( )
		         		    sizeof(H_recv_data_t)  // parametre size
		      			  );
    return 0;
}// HHui_ws2_32_recv_call( )

































// HHui elementary taint source introduction
/* ============================================================================================== */

static HHui_keyboard_taint_source_id = 0 ;

static int HHui_scanf_return( void * opaque )
{
    HVC      hvc   = *((HVC *)opaque) ;

    char     var_name[20];
    char     id_name[3];
    
    uint32_t f_str_addr ; 		     // format string 
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 4, // skip eip for parametres to the 1st function parametre
		   4,
		   &f_str_addr
 		 );
       
    uint32_t opnd_addr;
    TEMU_read_mem( TEMU_cpu_regs[R_ESP] + 8, // skip eip for parametres to the 2nd function parametre
		   4,
		   &opnd_addr
 		 );
    
    HHui_keyboard_taint_source_id = HHui_keyboard_taint_source_id + 1 ;

    strcpy(var_name, "H_KEY_taint_source_");
    sprintf(id_name, "%d", HHui_keyboard_taint_source_id);
    strcat(var_name, id_name);

    term_printf("scanf( ) taint source introduction : %s\n", var_name);

    H_taint_record_t * myrecord = (H_taint_record_t *)malloc( sizeof(H_taint_record_t) );
    myrecord->origin = HHui_keyboard_taint_source_id;
    myrecord->offset = 0;

    // 4 byte taint record !
    /*
    myrecord->h_expr = vc_varExpr1( hvc, 
				    var_name,  
				    32,
 				    32
				  );



    // AL is the return value for getchar( )
    taintcheck_taint_virtmem( opnd_addr, // vaddr
			      4,    	 // size
			      15,   // taint-bitmap: 1 bit per byte
			      myrecord
			    );
    */
    
    return 0;
  
}// end of HHui_getchar_return( )

static int HHui_scanf_call( void * opaque )
{
    uint32_t ret_eip;
    TEMU_read_mem( TEMU_cpu_regs[R_ESP],
	  	   4,
		   &ret_eip		 
	         );
    term_printf("Hooking HHui_scanf_call( ) !\n");    

    hookapi_hook_return( ret_eip,
		         HHui_scanf_return,
		         (HVC *)opaque, // parametre for HHui_Getchar_return( )
		         sizeof(HVC)  // parametre size
		       );

    return 0;
}// end of HHui_scanf_call( )

/* ============================================================================================== */
// HHui elementary taint source introduction


static int ExAllocatePoolWithTag_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  return 0;
}

static int RtlAllocateHeap_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  return 0;
}

static int RtlReAllocateHeap_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 16, 0, NULL);
  return 0;
}

static int ExInterlockedPushEntryList_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  uint32_t vaddr;
  TEMU_read_mem(TEMU_cpu_regs[R_ESP] + 4, 4, &vaddr); // first argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  TEMU_read_mem(TEMU_cpu_regs[R_ESP] + 8, 4, &vaddr); // second argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  return 0;
}

static int InterlockedPushEntrySList_call(void *opaque)
{
  //fastcall
  taintcheck_reg_clean(R_ECX);
  taintcheck_reg_clean(R_EDX);
  uint32_t vaddr;
  TEMU_read_mem(TEMU_cpu_regs[R_ECX], 4, &vaddr); // first argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  TEMU_read_mem(TEMU_cpu_regs[R_EDX], 4, &vaddr); // second argument
  taintcheck_taint_virtmem(vaddr, 8, 0, NULL); //clean it
  return 0;
}

static int alloca_probe_ret(void *opaque)
{
  uint32_t *handle = (uint32_t *)opaque;
  hookapi_remove_hook(*handle);
  free(handle);
  taintcheck_reg_clean(R_ESP);
  return 0;
}

static int alloca_probe_call(void *opaque)
{
  uint32_t ret_eip;
  TEMU_read_mem(TEMU_cpu_regs[R_ESP], 4, &ret_eip);
  uint32_t *hook_handle = malloc(sizeof(uint32_t));
  if(hook_handle) {
    *hook_handle = hookapi_hook_return(ret_eip, alloca_probe_ret, 
			hook_handle, sizeof(uint32_t));
  }
  return 0;
}

static int _aligned_offset_malloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 12, 0, NULL);
  return 0;  
}

static int _aligned_offset_realloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 16, 0, NULL);
  return 0;  
}

static int calloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 8, 0, NULL);
  return 0;  
}

static int malloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 4, 0, NULL);
  return 0;  
}

static int realloc_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 8, 0, NULL);
  return 0;  
}

static int NtAllocateVirtualMemory_call(void *opaque)
{
  taintcheck_taint_virtmem(TEMU_cpu_regs[R_ESP]+4, 24, 0, NULL);
  return 0;  
}

void reduce_taint_init()
{
  hookapi_hook_function_byname("ntoskrnl.exe", "ExAllocatePoolWithTag", 
  		1, ExAllocatePoolWithTag_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "RtlAllocateHeap", 
  		1, RtlAllocateHeap_call, 0, 0);
  hookapi_hook_function_byname("ntdll.dll", "RtlAllocateHeap", 
  		1, RtlAllocateHeap_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "NtAllocateVirtualMemory",
		 1, NtAllocateVirtualMemory_call, 0, 0);  
  hookapi_hook_function_byname("ntdll.dll", "NtAllocateVirtualMemory",
		 1, NtAllocateVirtualMemory_call, 0, 0);  
  hookapi_hook_function_byname("ntoskrnl.exe", "ZwAllocateVirtualMemory",
		 1, NtAllocateVirtualMemory_call, 0, 0);  
  hookapi_hook_function_byname("ntdll.dll", "RtlReAllocateHeap", 
  		1, RtlReAllocateHeap_call, 0, 0);

  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedPushEntryList", 
  		1, ExInterlockedPushEntryList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedInsertHeadList", 
  		1, ExInterlockedPushEntryList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedInsertTailList", 
  		1, ExInterlockedPushEntryList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "InterlockedPushEntrySList", 
  		1, InterlockedPushEntrySList_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "ExInterlockedPushEntrySList", 
  		1, InterlockedPushEntrySList_call, 0, 0);
  hookapi_hook_function_byname("ntdll.dll", "_alloca_probe", 1, 
			alloca_probe_call, 0, 0);
  hookapi_hook_function_byname("ntoskrnl.exe", "_alloca_probe", 1,
			alloca_probe_call, 0, 0);

  /*
  hookapi_hook_function_byname("msvcrt.dll", "_aligned_offset_malloc",
		 1, _aligned_offset_malloc_call, 0, 0);

  hookapi_hook_function_byname("msvcrt.dll", "_aligned_offset_realloc",
		 1, _aligned_offset_realloc_call, 0, 0);
  hookapi_hook_function_byname("msvcrt.dll", "calloc", 1,
		 calloc_call, 0, 0);  
  */



/*
  hookapi_hook_function_byname("msvcrt.dll", "malloc", 1,
		 malloc_call, 0, 0);  


  hookapi_hook_function_byname("msvcrt.dll", "realloc", 1,
		 realloc_call, 0, 0);  

*/

} 

void HHui_Keyboard_taint_source_init( HVC hvc )
{
      hookapi_hook_function_byname( "test1.exe", 
				    "_scanf", 
				    1,
				    HHui_scanf_call, 
				    hvc, 
				    sizeof(HVC)
				  );  	

}// end of HHui_Keyboard_taint_source_init( )

void HHui_ReadFile_Hooking(HVC * hvc)
{
      HVC ** data = (HVC **)malloc(sizeof(HVC *)) ;
      *data 	  = hvc;

      hookapi_hook_function_byname( "kernel32.dll", 
				    "ReadFile", 
				    0,
				    HHui_ReadFile_call, 
				    data, 
				    sizeof(HVC **)
				  );  	

}// end of HHui_ReadFile_Hooking(HVC * hvc)


void HHui_ws2_32_recv_Hooking(HVC * hvc)
{
      HVC ** data = (HVC **)malloc(sizeof(HVC *)) ;
      *data 	  = hvc;

      hookapi_hook_function_byname( "ws2_32.dll", 
				    "recv", 
				    0,
				    HHui_ws2_32_recv_call, 
				    data, 
				    sizeof(HVC **)
				  );    
}// end of HHui_ws2_32_recv_Hooking( )


void HHui_CreateFile_Hooking( )
{
    hookapi_hook_function_byname( "kernel32.dll", 
				  "CreateFileA", 
				  0,
				  HHui_CreateFileA_call,
				  NULL,
				  0
				);

    hookapi_hook_function_byname( "kernel32.dll", 
				  "CreateFileW", 
				  0,
				  HHui_CreateFileW_call,
				  NULL,
				  0
				);    
}// end of HHui_CreateFile_Hooking( )


void HHui_CreateFileMapping_Hooking(HVC * hvc)
{
    HVC ** data = (HVC **)malloc(sizeof(HVC *)) ;
    *data 	= hvc;

    hookapi_hook_function_byname( "kernel32.dll", 
				  "CreateFileMappingA", 
				  0,
				  HHui_CreateFileMappingA_call,
				  NULL,
				  0
				);    

    hookapi_hook_function_byname( "kernel32.dll", 
				  "CreateFileMappingW", 
				  0,
				  HHui_CreateFileMappingW_call,
				  NULL,
				  0
				); 

    hookapi_hook_function_byname( "kernel32.dll",
				  "MapViewOfFile",
				  0,
				  HHui_MapViewOfFile_call,
				  data,
				  sizeof(HVC**)
				);
}// end of HHui_CreateFileMapping_Hooking( )


void HHui_SetFilePointer_Hooking( )
{    
    hookapi_hook_function_byname( "kernel32.dll", 
				  "SetFilePointer", 
				  0,
				  HHui_SetFilePointer_call,
				  NULL,
				  0
				);
}// end of HHui_SetFilePointer_Hooking( )


void HHui_heapdata_Hooking(HVM_param_t * hvm_param)
{
    HVM_param_t ** data = (HVM_param_t **)malloc(sizeof(HVM_param_t *)) ;
    *data 		= hvm_param;

    hookapi_hook_function_byname( "msvcrt.dll",
				  "malloc",
				  0,
				  HHui_malloc_call,
				  data,
				  sizeof(HVM_param_t **)
				);

    hookapi_hook_function_byname( "msvcrt.dll",
				  "free",
				  0,
				  HHui_free_call,
				  NULL, // data,
				  0     // sizeof(HVC **)
				);

}// end of HHui_malloc_Hooking( )

#endif //TAINT_ENABLED









