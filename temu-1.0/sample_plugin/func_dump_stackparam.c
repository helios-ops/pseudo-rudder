#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>

#include "h_atoi.h"
#include "../TEMU_main.h"

void func_dump_stackparams( uint32_t   func_addr,
			    uint32_t   callsite_id,
			    uint8_t  * buf,
			    uint32_t   length,
			    uint64_t   tcbmap
			  )
{
    int  fd    = -1;
    char name[1000];
    int  count = 0;

    count = sprintf( name,
		     "./callstack_dump/func_%x_snapshot_%x",
		     func_addr,
		     callsite_id
		   );
    name[count] = '\0';

    umask(0);
    fd = open( name,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );
    if(fd == -1)
    {
	term_printf("error creating stackparam dumpfile !\n");	    
	return;
    }// end of if( )

    count = sprintf( name,
		     "_%d_",
		     length
		   );
    name[count] = '\0';

    write( fd,
	   name,
	   count	   
	 );
    
    count = write( fd,
		   buf,
		   length
		 );

    write( fd,
	   &tcbmap,
	   8
	 );

    write( fd,
	   &tcbmap,
	   8
	 );

    buf[0] = '\0';
    write( fd,
	   buf,
	   1
	 );

    close(fd);
}// end of func_dump_stackparams( )


// NOTE: this is temply a simplified version. FUTURE WORK WOULD INCLUDE MAKING IT COMPLETE !
void func_load_stackparams( uint32_t   func_addr,
			    uint32_t   callsite_id,
			    uint8_t ** ret_buf,
			    uint32_t * length,
			    uint64_t * tcbmap
			  )
{
    int i      = 0;
    int fd     = 0;
    char name[1000];
    char buf[1024];
    int count  = 0;

    char * index1 = NULL;
    char * index2 = NULL;

    count = sprintf( name,
		     "./callstack_dump/func_%x_snapshot_%x",
		     func_addr,
		     callsite_id
		   );
    name[count] = '\0';

    umask(0);
    fd = open( name,
	       O_RDWR
	     );
    
    count = read( fd,
		  buf,
		  1024
	        );

    index1 = strstr( (buf + 1),
		     "_"
		   );

    count = index1 - buf;
    *index1 = '\0';

    count = h_atoint(buf + 1);
        
    *ret_buf = (uint8_t *)malloc(sizeof(uint8_t) * count);
    for(i = 0; i < count; i = i + 1)
    {
	(*ret_buf)[i] = index1[i + 1];
    }// end of for{i}

    *length = count;
    *tcbmap = *( (uint64_t *)(index1 + 1 + count) );

    close(fd);
}// end of func_load_stackparams( )
















