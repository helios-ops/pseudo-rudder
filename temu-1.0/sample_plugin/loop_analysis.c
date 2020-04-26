#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>
#include <malloc.h>

#include "loop_analysis.h"
#include "h_atoi.h"

extern char monitored_proc[128];

loop_entry_list_t ida_loop_list;


void ida_loop_entry_delete(loop_entry_t * loop)
{
    int i = 0;
    bb_entry_t * entry = NULL;

    for(i = 0; i < loop->bb_count; i = i + 1)
    {
	entry = loop->bb_head;
	loop->bb_head = (loop->bb_head)->next;
	
	free(entry);
    }// end of for{i}

    loop->bb_count = 0;
    loop->bb_head  = NULL;
    loop->bb_end   = NULL;
}// end of ida_loop_entry_delete( )


void ida_loop_list_init( )
{
    ida_loop_list.head  = NULL;
    ida_loop_list.end   = NULL;
    ida_loop_list.count = 0;
}// end of ida_loop_list_init( )

void ida_loop_list_delete( )
{
    int i = 0;
    loop_entry_t * entry = ida_loop_list.head;

    for(i = 0; i < ida_loop_list.count; i = i + 1)
    {
	entry = ida_loop_list.head;
	ida_loop_list.head = entry->next;	
	
	ida_loop_entry_delete(entry);
    }// end of for{i}
}// end of ida_loop_list_delete( )


// read loop structures by parsing result file from IDA analysis
void init_loop_analysis( )
{
    int  loop_fd = -1;
    char str_loopfile[256];
    char buffer[1024];
    int  count   = 0;

    int  looplevel_idx = -1;
    int  bb_count_idx  = -1;
    int  bb_start_idx  = -1;
    int  bb_end_idx    = -1;

    uint32_t value = 0;

    count = sprintf( str_loopfile,
		     "%s_loop_summary"
		     monitored_proc
	   	   );
    str_loopfile[count] = '\0';

    umask(0);
    loop_fd = open( str_loopfile,
		    O_RDWR
		  );
    if(loop_fd < 0)
    {
	return; 
    }// end of if(loop_fd)


    do
    {
	count = read( loop_fd,
		      buffer,
		      1024
		    );
	looplevel_idx = strstr( buffer,
				"loop---level="
			      );
	if(looplevel_idx != -1)
	{
	    	    
	}// end of if(looplevel_idx)	
    }while(count > 0);


    if(loop_fd >= 0)
    {
	close(loop_fd);
    }// end of if(loop_fd)

}// end of init_loop_analysis( )


// return loop level and structure of a specific vaddr
int Check_LoopHdr_by_va( uint32_t 	vaddr,
		         loop_entry_t * lentry
		       )
{
    int i = 0;
    int j = 0;
    loop_entry_t * entry = ida_loop_list.head;

    for( ; entry != NULL; entry = entry->next )
    {
	if( (entry->bb_head)->start_addr == vaddr )
	{
	    lentry = entry;
	    return lentry->loop_level;
	}// end of if(entry)
    }// end of for{ }

    return -1;
}// end of Check_LoopHdr_by_va( )
