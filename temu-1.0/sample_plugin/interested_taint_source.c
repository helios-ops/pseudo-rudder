#include <inttypes.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "h_atoi.h"

#include "H_test_config.h"
  

/* we should notify to temu that these files were the interested potential 
   taint source for our target program.
 */

void H_intersted_file_init_2_temu( char *** str_names,
				   int  *   str_count
			         )
{   
    int    i	   = 0;
    int    file_fd = -1;
    char   buffer[1024];
    int    total_count = 0;
    int    count       = 0;
    char * start_idx   = 0;
    char * end_idx     = 0;

    umask(0);
    file_fd = open( "./interested_taint_source/file_source",
		    O_RDWR
		  );
    if(file_fd > 0)
    {
	total_count = read( file_fd,
		            buffer,
		            1024		    
		          );
	start_idx = strstr( buffer,
			    ";"			   
			  );
	end_idx = start_idx;

	*start_idx = '\0';	
	count = h_atoint(buffer);

	*str_count = count;
	
	*str_names = (char **)malloc(sizeof(char *) * count);
	do
	{
	    start_idx = end_idx;
	    end_idx   = strstr( start_idx + 1,
				";"
			      );
	    *end_idx = '\0';
	    
	    (*str_names)[i] = (char *)malloc( sizeof(char) * ((int)(end_idx - start_idx) - 1) + 1);
	    strcpy( (*str_names)[i],
		    start_idx + 1		    
		  );
	    // (*str_names)[i][(int)(end_idx - start_idx) - 1] = '\0';

	    i = i + 1;
	}while(i < count);
		
        close(file_fd);
    }// end of if(file_fd)
}// end of H_intersted_file_init_2_temu( )


void H_intersted_file_free( char ** str_names,
			    int     str_count
			  )
{
    for(int i = 0; i < str_count; i = i + 1)
    {
	free(str_names[i]);
    }// end of for{int i}
   
    free(str_names);
}// end of H_intersted_file_free( )



