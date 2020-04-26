#include <inttypes.h>
#include <string.h>
#include <stdlib.h>


#include <sys/stat.h>
#include <apue.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>


#include "H_test_config.h"

#include "../taintcheck.h"
#include "../shared/procmod.h"
#include "../shared/hooks/function_map.h"
#include "../slirp/slirp.h"
#include "../TEMU_lib.h"
#include "../shared/hookapi.h"
#include "../shared/read_linux.h"
#include "../shared/reduce_taint.h"

#include "hc_interface.h"
#include "module_notify.h"

#include "insn_effect_restore.h"


#include "stp_variables.h"


#include "H_cpu.h"
#include "main.h"

#include "HVM_state.h"

#include "HH_encap_taintcheck.h"


#include "winxpsp2_vad.h"
#include "../TEMU_lib.h"


#include "winxpsp2_esp_range.h"
#include "interested_func_analysis.h"
#include "H_testcase_generation.h"

#include "record_potential_error2file.h"

#include "dbg_util.h"

//#include "H_STP_stub.h"

extern void HH_Obtain_stp_utils_From_plugin( );

// switches for several vulnerability scanning policies.
/* ======================================================================= */
extern int H_vulscan_once_enough_err_found;
/* ======================================================================= */


// external data
/* --------------------------------------------------------------------------------------------------------- */

extern plugin_interface_t 	  my_interface;

extern uint32_t 	  	  HHui_target_cr3;
extern char	 	    	  monitored_proc[128];
extern uint32_t  	 	  HHui_target_pid;

extern GET_HH_TEMU_INFO	    	  Get_HH_Temu_Info;
extern SET_HH_TEMU_CONCRETE_READ  Set_HH_Temu_Concrete_Read;

#ifdef H_DEBUG_TEST
extern GET_TEMU_DBGUTIL 	  Get_temu_dbgutil;
#endif

extern void * 			  parser_so_handle ;



extern tpage_entry_t **		  tpage_table; 	   //!<memory page table

extern uint64_t * 		  HH_regs_bitmap;    //!<bitmap for registers
extern uint8_t  * 		  HH_regs_records;   //!<taint records for registers

extern uint32_t * 		  HH_eflags_bitmap;  //!<bitmap for eflags
extern uint8_t  * 		  HH_eflags_records; //!<taint records for eflags


extern HVC 			  HHui_VC;
extern HExpr 			  path_Expr;  	    // VC for current path !

extern int  			  current_proc_set; // signals the beginning of monitorring


/* flag indicating whether or not the monitored process has been terminated. 
   0 ------- monitored but not terminated
   1 ------- terminated 
  -1 ------- proc not begin yet
 */
extern int			  cur_proc_terminated; 

extern PMODULE_INFO_LIST HHui_module_list;

// FILE * file_cur_monitored_proc = NULL;

/* --------------------------------------------------------------------------------------------------------- */


int cur_monitored_proc_fd  = -1 ;
int cur_monitored_proc_seq = 0;
char str_mon_file_name[1000];
int  str_mon_file_num_index = 0;


int performance_fd = -1;
static time_t start_time;
static char * start_time_str;

static time_t end_time;
static char * end_time_str;

QEMUTimer * qtimer_handle;

#ifdef H_DEBUG_TEST
extern int H_predicate_count;
#endif


void H_encap_BFS_restore_HVM_state_from_snapshot(void * opaque)
{
    qemu_del_timer(qtimer_handle);

    qemu_free_timer(qtimer_handle);

    // cur_proc_terminated = 2;
    cur_proc_terminated = 0;

    term_printf("sssssssssssss\n");

#ifdef H_VULSCAN_ONCE_ENOUGH
    H_vulscan_once_enough_err_found = 0;
#endif

    BFS_restore_HVM_state_from_snapshot( );


}// end of H_encap_BFS_restore_HVM_state_from_snapshot( )



// main module is the first loaded module !
void H_Load_MainModule_Notify( uint32_t pid,
			       char *   proc_name
			     )
{
    // char * str_mon_file_name = NULL;
    int	 tmp_idx = 0;
    char buffer[100];
    int  count   = 0;
    MODULE_ENTRY * h_module = HHui_module_list->module_entry_head;
    
    time(&start_time);
    start_time_str = ctime(&start_time);    
    count = sprintf( buffer,
		     "Analysis started at %s\n",
		     start_time_str
		   );
    buffer[count] = '\0';

    if(performance_fd == -1)
    {
	performance_fd = open( "performance_log",
			       (O_CREAT | O_RDWR),
			       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
			     );

	write( performance_fd,
	       buffer,
	       count
	     );
    }// end of if(performance_fd)

    

    // Test whether the monitor command has been ordered 
    if( current_proc_set != 1 )
    {
	return ;
    }// end of if( )
    

    if( strcmp( proc_name,
		monitored_proc
	      ) == 0
      )      
    {
	/* -------------------------------------------------------------------------------------------- */	
    #ifdef HH_TRACE_MONITOR

	cur_monitored_proc_seq = cur_monitored_proc_seq + 1;

	strcpy(str_mon_file_name, proc_name);        
	tmp_idx = strlen(proc_name);
        str_mon_file_name[tmp_idx] = '_';
        str_mon_file_name[tmp_idx + 1] = 't';
	str_mon_file_name[tmp_idx + 2] = 'r';	
	str_mon_file_name[tmp_idx + 3] = 'a';	
	str_mon_file_name[tmp_idx + 4] = 'c';	
	str_mon_file_name[tmp_idx + 5] = 'e';	
	str_mon_file_name[tmp_idx + 6] = '_';	
	tmp_idx	= tmp_idx + 7;
	str_mon_file_num_index = tmp_idx ;

	tmp_idx = tmp_idx + sprintf( str_mon_file_name + tmp_idx,
				     "%d",
				     cur_monitored_proc_seq
			    	   );
	str_mon_file_name[tmp_idx] = (char)0;
	
	
	umask(0);
	cur_monitored_proc_fd = open( str_mon_file_name,
				      (O_CREAT | O_RDWR),
				      (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
				    );

	if(cur_monitored_proc_fd == -1)
	{
	    term_printf("error creating insn_trace_file for monitored process !\n");	    
	}// end of if( )

	my_interface.trace_fd = cur_monitored_proc_fd;
    #endif
	/* -------------------------------------------------------------------------------------------- */



	term_printf( "Load desired main module !\n"
		   );

	HHui_target_cr3 	   = find_cr3(pid);

	HHui_target_pid		   = pid;
	my_interface.monitored_pid = pid;

	my_interface.monitored_cr3 = HHui_target_cr3;
	// TEMU_update_cr3( );


	// gather total module informations after initialization
	/*
	Gather_init_modules_info( monitored_proc,
				  HHui_target_pid,
			    	  HHui_target_cr3
			  	);

	*/

	/*
	term_printf( "H_read_concrete_register( )'s function address is 0x%8x\n",
		     H_read_concrete_register
		   );
	*/

	// Send all TEMU-related machine states querying utils to SYM-EXE 
	Set_HH_Temu_Concrete_Read( H_general_registers,
				   H_general_registers_bitmap,
				   				
				   (void *)( &H_map),

				   /* concrete reading means reading the original data before execution ! */
				   H_read_concrete_mem,
				   H_read_concrete_register,

				   /* concrete wrting --- possibly not important in the context of taint-based SYM-EXE, remain for possible extending */
				   H_write_concrete_mem,      // concrete mem write
			     	   H_write_concrete_register, // concrete register write

				   /* abstract reading of the symbolic machine states */
			     	   taintcheck_check_virtmem, 
			     	   taintcheck_register_check,

				   /* abstract writing of the symbolic machine states */
			     	   HHui_encap_taintcheck_taint_virtmem, // taintcheck_taint_virtmem
			     	   taintcheck_taint_register, 	        // HHui_encap_taintcheck_taint_register

				   // For SYM-ADDR-CONSTRAINTS' building and resolvation !
				   &(my_interface.monitored_vad),
				   build_symaddr_invalid_constraint,  // cares for OUT-OF-RANGE and INVALID-ACCESS errors 

				   // these 2 care for stack-overwrite errors 
				   symaddr_obtain_stack_range_constraint,
				   symaddr_stack_eip_overwritten_constraint,

				   // testcase generation for errors found during IR-SYMEXE
				   H_IRSYMEXE_error_testcase_generate_4_expr,

				   // switches for several vulnerability scanning policies.
				   /* ============================================================ */
				   &H_vulscan_once_enough_err_found
				   /* ============================================================ */
			   	);

	#ifdef H_DEBUG_TEST
	Get_temu_dbgutil( dbg_dump_expr,
			  predicate_change
			);
	#endif
	
	// machine state acquiring
        /* --------------------------------------------------------------------------------- */	
	tpage_table	  = Get_tpage_table( );
	  
	HH_regs_bitmap    = Get_regs_bitmap( );
	HH_regs_records   = Get_regs_records( );
	  
	HH_eflags_bitmap  = Get_eflags_bitmap( );  //!<bitmap for eflags
        HH_eflags_records = Get_eflags_records( ); //!<taint records for eflags
        /* --------------------------------------------------------------------------------- */
	  // machine state acquiring
  

	// term_printf("page table : %08x\n", tpage_table);
  

 	// Send the Temu-related information to the IR SymExe component	
	Get_HH_Temu_Info( TEMU_cpu_eflags, // concrete EFLAGS
		 	  TEMU_cpu_eip,   
		    	  TEMU_cpu_regs,   // concrete regs
		    	  tpage_table,     // mems
					    
 		    	  HH_regs_bitmap,  // taint regs
		    	  HH_regs_records,
		    
                    	  HH_eflags_bitmap, // taint EFLAGS
		    	  HH_eflags_records
		  	);

	// term_printf("aaaaaaaaaaaaaaaaaaaaaaaaaa!\n");
	
	// let SYM-EXE obtain the STP utils from us plugin
	// HH_Obtain_stp_utils_From_plugin( );
	HH_Obtain_stp_utils_From_plugin( );

	/*
	term_printf( "IR_SymEXE.so: vc_DeleteExpr( ) is at address 0x%x, vc_getWholeCounterExample( ) is at address 0x%x, vc_getTermFromCounterExample( ) is at address 0x%x\n",
	             vc_DeleteExpr,
	             vc_getWholeCounterExample,
	             vc_getTermFromCounterExample
	           );
	term_printf("HH_Obtain_stp_utils_From_plugin( ) finished !\n");
	*/	

	/* flag indicating whether or not the monitored process has been terminated. 
	   0 ------- monitored but not terminated
	   1 ------- terminated 
	  -1 ------- proc not begin yet
	 */
	cur_proc_terminated = 0;

	//term_printf("init_stp_vlist( ) finished !\n");
	
	// list keeping snapshots at every tainted branching points !
	init_vm_state_list( );
	// term_printf("init_vm_state_list( ) finished !\n");

	// list keeping all taint-writing's dest-vaddr and size( Maybe a superset but sufficient in real app-background ! )
	HHui_init_tc_vaddr_list( );
	// term_printf("HHui_init_tc_vaddr_list( ) finished !\n");

	
	interest_func_list_init( );


	/*	
	while(h_module != NULL)
	{
	    post_func_summ_init(h_module);
	    h_module = h_module->next;
	}// end of while{h_module}
	*/


    }// end of if(strcmp)

}// end of H_Load_MainModule_Notify( )



int HHui_path_id = 0;
void HHui_remove_proc(uint32_t pid)
{
	/* flag indicating whether or not the monitored process has been terminated. 
	   0 ------- monitored but not terminated
	   1 ------- terminated 
	  -1 ------- proc not begin yet
	 */
	// uint32_t current_cr3 = find_cr3(pid);

	/*
	term_printf( "Removing proc : HHui_target_pid = %d, pid = %d\n",
		     HHui_target_pid, 
		     pid
		   );
	*/
	int    count    = 0;
	char * str_expr = NULL;
  	char   path_expr_file[1000];
	int    f_name_len = 0;
        int    path_fd    = 0;

	int    tmp_idx    = 0;
        char   buffer[1000];

	if( ( HHui_target_pid != 0 ) && 
	    ( HHui_target_pid == pid )
	  )
	//if(current_cr3 == HHui_target_cr3)
	{
	    // cur_proc_terminated = 1;

	    my_interface.monproc_terminated = 1;

#ifdef HH_TRACE_MONITOR	
	    if(cur_monitored_proc_fd != -1)
	    {
		close(cur_monitored_proc_fd);
	    }// end of if( )

	    /* -------------------------------------------------------------------------------------------- */	
	    cur_monitored_proc_seq = cur_monitored_proc_seq + 1;

	    tmp_idx = str_mon_file_num_index + sprintf( str_mon_file_name + str_mon_file_num_index,
				         		"%d",
				         		cur_monitored_proc_seq
			    	       		      );
	    str_mon_file_name[tmp_idx] = (char)0;
	
	
	    umask(0);
	    cur_monitored_proc_fd = open( str_mon_file_name,
				          (O_CREAT | O_RDWR),
				          (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
				        );

	    if(cur_monitored_proc_fd == -1)
	    {
	        term_printf("error creating insn_trace_file for monitored process !\n");	    
	    }// end of if( )
	    /* -------------------------------------------------------------------------------------------- */
#endif

	    str_expr = exprString(path_Expr);

	    term_printf( "a final path constraint is %s, for pid = %d\n",
		         str_expr,
			 pid
		       );

	    // write the path-constraint to file
	    /* ------------------------------------------------------------------------------------------------ */
	    /*
	    path_expr_file[0] = '.';
	    path_expr_file[1] = '/';
	    HHui_path_id = HHui_path_id + 1;
	    f_name_len = sprintf( path_expr_file,
		     		  "%s_path_%d",
		     		  monitored_proc,
		     		  HHui_path_id  
		   		);
	    path_expr_file[2 + f_name_len] = (char)0;
	    */
	    HHui_path_id = HHui_path_id + 1;
	    f_name_len = sprintf( path_expr_file,
				  "./path_constraints/%s_path_%d",
				  monitored_proc,
		     		  HHui_path_id  
				);
	    path_expr_file[f_name_len] = '\0';

	    umask(0);
	    path_fd = open( path_expr_file,
			    (O_CREAT | O_RDWR),
			    (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		  	  );
	    if(path_fd != -1)
	    {
		write( path_fd, 
		       str_expr,
	 	       strlen(str_expr)
		     );

		close(path_fd);
	    }
	    else
	    {
	        term_printf("path-constraint file creat error !\n");
	    }// end of if( )
	    /* ------------------------------------------------------------------------------------------------ */ 
	    // write the path-constraint to file
	    
	    free(str_expr);

#ifdef H_PATH_EXPR_TESTCASE_GENERATION
	    H_testcase_generate_4_expr( HHui_path_id,
				   	path_Expr
				      );
#endif

	    // //extern HVM_state_list_t vm_list;
	    term_printf( "HVM_state_list_ count is %d\n",
			 vm_list.count
		       );

	    /* when an instance of the monitored image is terminated, we set the flag 'cur_proc_terminated' to NONSENSE,
	       but it would absolutely be resumed when a snapshot is scheduled to load !
	     */
	    // cur_proc_terminated = -1;

	    
	    if( vm_list.count == 0 )
  	    {
		time(&end_time);
		end_time_str = ctime(&end_time);
		count = sprintf( buffer,
				 "Analysis finished at %s\n",
				 end_time_str
			       );

	        if(performance_fd != -1)
	        {		    
		    write( performance_fd,
		           buffer,
		           count
		         );
		    close(performance_fd);
	        }// end of if(performance_fd)

		cur_proc_terminated = 1;
	    }
#ifdef H_MANUALLY_SEARCHING_FOR_BRANCHES
	    cur_proc_terminated = 1;
#else
	    else
	    {
		cur_proc_terminated = 1;

		qtimer_handle = qemu_new_timer( vm_clock,
						H_encap_BFS_restore_HVM_state_from_snapshot,
						NULL
					      );
 

		if(qtimer_handle)
		{
		    qemu_mod_timer( qtimer_handle, 
				    ( qemu_get_clock(vm_clock) + ticks_per_sec * 3)
				  );
		}// end of if( )

		/*
		do_enable_emulation( );
		
		BFS_restore_HVM_state_from_snapshot( HHui_VC,
					  	     &path_Expr // [ output ] : restoring the path-constraint for this branch
						   );

		str_expr = exprString(path_Expr);
		term_printf( "branching expr = %s\n",
			     str_expr
			   );
		*/
 	    }// end of if( )
#endif

	}// end of if( )
	

}// end of HHui_remove_proc( )



#ifdef H_MANUALLY_SEARCHING_FOR_BRANCHES
void H_search_new_path( )
{
    // cur_proc_terminated = 2;
    cur_proc_terminated = 2;

    term_printf("sssssssssssss\n");

    BFS_restore_HVM_state_from_snapshot( );    
}// end of H_search_new_path( )
#endif

