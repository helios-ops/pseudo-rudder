/* some utils manually-called during GDB-session */
#include <stdlib.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>

#include "H_test_config.h"

#include "hc_interface.h"
#include "H_taint_record.h"
#include "../TEMU_main.h"
#include "../TEMU_lib.h"

#include "winxpsp2_vad.h"
#include "winxpsp2_esp_range.h"

#include "H_testcase_generation.h"


extern plugin_interface_t my_interface;
extern HVC   HHui_VC;
extern HExpr path_Expr;


extern uint32_t * HH_eflags_bitmap;  //!<bitmap for eflags
extern uint8_t  * HH_eflags_records; //!<taint records for eflags

#ifdef H_DEBUG_TEST

extern void predicate_change( HVC   hvc,
			      HExpr pred_expr,
		       	      HExpr prev_total_expr,
		       	      HExpr total_expr
		     	    );


uint32_t dbg_query_term_val( HExpr term_expr,
		   	     HExpr base_expr 
		           )
{
    int      qresult = -1;
    uint32_t value   = 0;

    HExpr tmp_expr1 = NULL;
    HExpr tmp_expr2 = NULL;
    HWholeCounterExample wc = NULL;

    tmp_expr1 = vc_notExpr( HHui_VC,
			    base_expr
			  );
    vc_push(HHui_VC);
    qresult = vc_query( HHui_VC,
			tmp_expr1
		      );    
    vc_pop(HHui_VC);

    if(qresult == 0)
    {
        wc = vc_getWholeCounterExample(HHui_VC);
	tmp_expr2 = vc_getTermFromCounterExample( HHui_VC,
						  term_expr,
						  wc
						);
	value = getBVInt(tmp_expr2);
	term_printf( "dbg: value for term-expr[%x] is %x\n",
		     term_expr,
		     value
		   );

	vc_DeleteExpr(tmp_expr2);
    }
    else
    {
	term_printf( "dbg: no value for term-expr[%x] !\n",
		     term_expr
		   );
    }// end of if(qresult)

    vc_DeleteExpr(tmp_expr1);

    return value;
}// end of dbg_query_term_val( )


void dbg_check_symaddr_range( HExpr term_expr,
			      HExpr base_expr
			    )
{
    uint32_t start_addr = 0;
    uint32_t end_addr   = 0;
    uint32_t value = dbg_query_term_val( term_expr,
		   		         base_expr 
		           	       );
    if( dbg_addr_is_in_vad_range( value,
				  &start_addr,
				  &end_addr
			        ) == 0
      )
    {
	term_printf( "symaddr %x not in vad-range !\n",
		     value
		   );
    }
    else
    {
	term_printf( "symaddr %x in vad-range[%x - %x]!\n",
		     value,
		     start_addr,
		     end_addr
		   );	
	return;
    }// end of if(dbg_is_in_vad_range)	

    if( dbg_addr_is_in_stack_range( value,
				    &start_addr,
				    &end_addr
				  ) == 0
      )
    {
	term_printf( "symaddr %x not in stack-range !\n",
		     value
		   );	
    }
    else
    {
	term_printf( "symaddr %x in stack-range[%x - %x]!\n",
		     value,
		     start_addr,
		     end_addr
		   );	
    }// end of if(dbg_addr_is_in_stack_range)

}// end of dbg_check_symaddr_range( )


void dbg_check_addrs_in_range( uint32_t * addr_values,
			       int	  count
			     )
{
    uint32_t start_addr = 0;
    uint32_t end_addr   = 0;

    for(int i = 0; i < count; i = i + 1)
    {
        if( dbg_addr_is_in_vad_range( addr_values[i],
				      &start_addr,
				      &end_addr
			            ) == 0
          )
        {
	    term_printf( "symaddr %x not in vad-range !\n",
		         addr_values[i]
		       );
        }
        else
        {
	    term_printf( "symaddr %x in vad-range[%x - %x]!\n",
		         addr_values[i],
		         start_addr,
		         end_addr
		       );	
	    continue;
	}// end of if(dbg_is_in_vad_range)	

        if( dbg_addr_is_in_stack_range( addr_values[i],
				        &start_addr,
				        &end_addr
				      ) == 0
          )
        {
	    term_printf( "symaddr %x not in stack-range !\n",
		         addr_values[i]
		       );	
        }
        else
        {
	    term_printf( "symaddr %x in stack-range[%x - %x]!\n",
	  	         addr_values[i],
		         start_addr,
		         end_addr
		       );	
        }// end of if(dbg_addr_is_in_stack_range)
    }// end of for{i}
}// end of dbg_check_addrs_in_range( )

void dbg_dump_expr( HExpr  expr,
		    char * filename,
		    char * tc_filename,
		    int	   category    // 0 --- not-generate testcase
		  )
{
    char * str = exprString(expr);
    int    fd  = -1;
    int    len = strlen(str);

    umask(0);
    fd = open( filename,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );
    write( fd,
	   str,
	   len
	 );    

    close(fd);
    free(str);

    if(category != 0)
    {
        dbg_testcase_generate_4_expr( tc_filename,
		  		      expr
			            );
    }// end of if(category)

}// end of dbg_dump_path_expr( )



void dbg_dump_path_expr( )
{
    char * str = exprString(path_Expr);
    int    fd  = -1;
    int    len = strlen(str);

    umask(0);
    fd = open( "dbg_path_expr",
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );
    write( fd,
	   str,
	   len
	 );    

    close(fd);
    free(str);

    dbg_testcase_generate_4_expr( "dbg_path_expr_tc",
				   path_Expr
			        );
}// end of dbg_dump_path_expr( )



uint32_t dbg_interested_eip = 0;

/* NOTE:
   eax_reg --- 132
   ecx_reg --- 133
   edx_reg --- 134
   ebx_reg --- 135
   esp_reg --- 136
   ebp_reg --- 137
   esi_reg --- 138
   edi_reg --- 139
 */
void dbg_set_dbg_interested_eip(uint32_t eip)
{
    dbg_interested_eip = eip;

    my_interface.dbg_interested_eip = eip;
}// end of dbg_set_dbg_interested_eip( )


void dbg_taintcheck_register_check(int reg)
{
    char * str   = NULL;
    HExpr  expr1 = NULL;
    HExpr  expr2 = NULL;
    HVC    hvc   = HHui_VC;

    int  fd      = -1;
    char filename[100];
    int  f_count = 0;

    int i  = 0;
    uint32_t value;
    H_taint_record_t tc_records[4];
    char *   reg_names[ ] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    uint32_t tcbmap = taintcheck_register_check( reg - eax_reg,
						 0,
						 4,
						 tc_records
					       );
    TEMU_read_register( reg,
			&value
		      );
    term_printf( "con-reg: %s = %x\n",
		 reg_names[reg-eax_reg],
		 value
	       );

    if(tcbmap == 0)
    {
	term_printf( "dbg: %s[con] = %x\n",
		     reg_names[reg-eax_reg],
		     value
		   );
    }
    else
    {
	/* -------------------------------------------------------------------------- */
	if( (tcbmap & 1) == 0 )
	{
	    expr1 = vc_bvConstExprFromInt( hvc,
					   8,
					   (uint8_t)(value & 255)
					 );
	}
	else
	{
	    expr1 = tc_records[0].h_expr;
	}// end of if(tcbmap)

	for(i = 1; i < 4; i = i + 1)
	{
	    if( (tcbmap & (1 << i)) == 0 )
	    {
	        expr2 = vc_bvConstExprFromInt( hvc,
					       8,
					       (uint8_t)( ( value & ( (1 << (8 * (i + 1))
								      ) - 1 
								    )
							  ) >> (8 * i)
							)
					     );		
	    }
	    else
	    {
	        expr2 = tc_records[i].h_expr;
	    }// end of if(tcbmap)    

	    expr1 = vc_bvConcatExpr( hvc,
				     expr2,
				     expr1
				   );
	}// end of for{i}
	/* -------------------------------------------------------------------------- */

	str = exprString(expr1);

	term_printf( "dbg: %s[sym]\n", // = %s\n",
		     reg_names[reg-eax_reg] // ,
		     // str
		   );
	/*
	term_printf( "dbg: %s[sym] = %s\n",
		     reg_names[reg-eax_reg],
		     str
		   );
	 */
	umask(0);
	
	f_count = sprintf( filename,
			   "dbg_%s_expr",
			   reg_names[reg-eax_reg]
			 );
	filename[f_count] = '\0';

	fd 	= open( filename,
			(O_CREAT | O_RDWR),
		   	(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		      );
	write( fd,
	       str,
	       strlen(str)
	     );
	close(fd);

	free(str);
    }// end of if(tcbmap)

}// end of dbg_taintcheck_register_check( )


void dbg_taintcheck_memory_check(uint32_t vaddr)
{
    int  fd = -1;
    int  f_count = 0;
    char filename[100];

    char * str   = NULL;
    HExpr  expr1 = NULL;
    HExpr  expr2 = NULL;
    HVC    hvc   = HHui_VC;

    int i = 0;
    uint32_t value;
    H_taint_record_t tc_records[4];
    uint32_t tcbmap = taintcheck_check_virtmem( vaddr,
						4,
						tc_records
					      );
    TEMU_read_mem( vaddr,
		   4,
		   &value
		 );
    term_printf( "con-mem: [%x] = %x\n",
		 vaddr,
		 value
	       );

    if(tcbmap == 0)
    {
	term_printf( "dbg: mem[%x]-[con] = %x\n",
		     vaddr,
		     value
		   );
    }
    else
    {
	/* -------------------------------------------------------------------------- */
	if( (tcbmap & 1) == 0 )
	{
	    expr1 = vc_bvConstExprFromInt( hvc,
					   8,
					   (uint8_t)(value & 255)
					 );
	}
	else
	{
	    expr1 = tc_records[0].h_expr;
	}// end of if(tcbmap)

	for(i = 1; i < 4; i = i + 1)
	{
	    if( (tcbmap & (1 << i)) == 0 )
	    {
	        expr2 = vc_bvConstExprFromInt( hvc,
					       8,
					       (uint8_t)( ( value & ( (1 << (8 * (i + 1))
								      ) - 1 
								    )
							  ) >> (8 * i)
							)
					     );		
	    }
	    else
	    {
	        expr2 = tc_records[i].h_expr;
	    }// end of if(tcbmap)    

	    expr1 = vc_bvConcatExpr( hvc,
				     expr2,
				     expr1
				   );
	}// end of for{i}
	/* -------------------------------------------------------------------------- */

	str = exprString(expr1);
	term_printf( "dbg: mem[%x]-[sym]\n",
		     vaddr // ,
		     // str
		   );
	/*
	term_printf( "dbg: mem[%x]-[sym] = %s\n",
		     vaddr,
		     str
		   );
	 */
	umask(0);	
	f_count = sprintf( filename,
			   "dbg_mem_%x_expr",
			   vaddr
			 );
	filename[f_count] = '\0';

	fd = open( filename,
		   (O_CREAT | O_RDWR),
		   (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		 );
	write( fd,
	       str,
	       strlen(str)
	     );
	close(fd);

	free(str);
    }// end of if(tcbmap)
}// end of dbg_taintcheck_memory_check( )


void dbg_taintcheck_EFLAGS_check(int bit_nr)
{
    int  fd      = -1;
    int  f_count = 0;
    char filename[100];

    char * str = NULL;
    H_taint_record_t * record = NULL;
    int bit_indices[7] = { 0,  // CF
			   2,  // PF
			   4,  // AF
			   6,  // ZF
			   7,  // SF
			   10, // DF
			   11  // OF
		         };
    char * eflag_names[7] = { "CF",
			      "PF",
			      "AF",
			      "ZF",
			      "SF",
			      "DF",
			      "OF"
			    };
    record = &( ( (H_taint_record_t *)HH_eflags_records
	        )[ bit_indices[bit_nr] ]
	      );

    if( *HH_eflags_bitmap & (1 << bit_indices[bit_nr]) )
    {
	str = exprString(record->h_expr);
	term_printf( "dbg: %s-[sym] = %s\n",
		     eflag_names[bit_nr],
		     str
		   );

	umask(0);	
	f_count = sprintf( filename,
			   "dbg_%x_expr",
			   eflag_names[bit_nr]
			 );
	filename[f_count] = '\0';

	fd = open( filename,
		   (O_CREAT | O_RDWR),
		   (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
		 );
	write( fd,
	       str,
	       strlen(str)
	     );
	close(fd);

	free(str);
    }
    else
    {
	term_printf( "dbg: %s-[con] = %d\n",
		     eflag_names[bit_nr],
		     ( *TEMU_cpu_eflags & (1 << bit_indices[bit_nr]) 
		     ) >> bit_indices[bit_nr]
		   );
    }// end of if(*HH_eflags_bitmap)
}// end of dbg_taintcheck_EFLAGS_check( )


#ifdef H_DBG_CHECK_MONITORED_MACHINE_STATE
int dbg_monitored_sym_reg 	     = -1;
uint32_t dbg_monitored_mem_sym_vaddr = 0;
uint32_t dbg_monitored_mem_size	     = 0;

void dbg_set_monitored_sym_register(int regidx)
{  
    dbg_monitored_sym_reg = regidx;
}// end of dbg_set_monitored_sym_register( )

// breakpoint set by GDB !
void dbg_register_sym_change(int reg_idx)
{
    char * reg_names[ ] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    if(dbg_monitored_sym_reg == (reg_idx - R_EAX))
    {
	term_printf( "sym-status changed for %s\n",  //--> tcbmap = %x\n",
		     reg_names[reg_idx - R_EAX] //,
		     //tcbmap
		   );
    }// end of if(dbg_monitored_sym_reg)
}// end of dbg_register_sym_change( )


void dbg_set_monitored_sym_memory( uint32_t vaddr,
				   int	    size
				 )
{
    dbg_monitored_mem_sym_vaddr = vaddr;
    dbg_monitored_mem_size	= size;
}// end of dbg_set_monitored_sym_memory( )

// breakpoint set by GDB !
void dbg_memory_sym_change( uint32_t vaddr, 
			    int      size // ,
			    // uint32_t tcbmap
			  )
{
    if(dbg_monitored_mem_sym_vaddr == 0)
    {
	return;
    }// end of if(dbg_monitored_mem_sym_vaddr)

    if(vaddr == dbg_monitored_mem_sym_vaddr)
    {
        term_printf( "sym-status changed for [%x]\n", // (%d) --> tcbmap = %x\n",
	  	     vaddr,
		     size//,
		     // tcbmap
	           );
    }// end of if(vaddr)    
}// end of dbg_memory_sym_change( )



// HHui added at April 7th, 2012
/* ---------------------------------------------------------------------------- */
#ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
int dbg_monitored_taint_byte_idx = -1;

void dbg_taint_byte_refered(int idx)
{
    if(dbg_monitored_taint_byte_idx != -1)
    {
	if(idx == dbg_monitored_taint_byte_idx)
	{
	    term_printf( "taint-byte[%d] is referenced !\n",
			 dbg_monitored_taint_byte_idx
		       );
	}// end of if(idx)
    }// end of if(dbg_monitored_taint_byte_idx)
}// end of dbg_taint_byte_refered( )

void dbg_set_monitored_taint_byte_idx(int idx)
{
    dbg_monitored_taint_byte_idx = idx;
}// end of dbg_set_monitored_taint_byte_idx( )
#endif
/* ---------------------------------------------------------------------------- */


void dbg_set_dbgutil_4_temu( )
{
    my_interface.temu_dbg_util = (h_dbg_util_t *)malloc(sizeof(h_dbg_util_t));

    (my_interface.temu_dbg_util)->h_dbg_register_sym_change = dbg_set_monitored_sym_register;
    (my_interface.temu_dbg_util)->h_dbg_memory_sym_change   = dbg_memory_sym_change;

    // HHui added at April 7th, 2012
    #ifdef H_DBG_CHECK_TAINT_BYTE_REFERENCED
    (my_interface.temu_dbg_util)->h_dbg_taint_byte_refered  = dbg_taint_byte_refered;
    #endif

}// end of dbg_set_dbgutil_4_temu( )

void dbg_delete_dbgutil_4_temu( )
{
    free(my_interface.temu_dbg_util);
    my_interface.temu_dbg_util = NULL;
}// end of dbg_delete_dbgutil_4_temu( )

#endif


#endif

