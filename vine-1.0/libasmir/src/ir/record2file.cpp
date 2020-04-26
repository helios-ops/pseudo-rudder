#include <sys/stat.h>
// #include <apue.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "H_STP_stub.h"
#include "record2file.h"

/* err_id: 
    0 --- sym-addr write out-of-range 
    1 --- sym-addr write invalid access
    2 --- sym-addr write stack-eip overwritten

    3 --- sym-addr read out-of-range
    4 --- sym-addr read invalid access	       

    5 --- divide by 0
*/
// record total counts for each errors found during IR-SYMEXE.
// TODO: possibly some extension need to be made here ...
#ifndef IRSYMEXE_ERROR_CATEGORY_COUNT
    #define IRSYMEXE_ERROR_CATEGORY_COUNT 6
#endif
static int IRSYMEXE_errors[IRSYMEXE_ERROR_CATEGORY_COUNT];


// records the count of the total errors found during IR-SYMEXE.
static int IRSYMEXE_error_seq_num = 0;

extern void (*H_error_testcase_generate_4_expr)( HExpr    path_expr,
					         uint32_t category_id,
					         int      local_id
					       );

extern HVC HHui_HVC;

static char ERROR_file_name[1000];


/*
void record_ERROR_2file( char * str_info,
			 int    err_id
		       )
*/
void record_ERROR_2file( HExpr err_expr,
			 int   err_id
		       )
{
    int fd = -1;
    int i  = 0;
    char * str_info = exprString(err_expr);
 
    // first time initialization !
    if(IRSYMEXE_error_seq_num == 0)
    {
	// IRSYMEXE_error_PathConstraint
	//error_path_constraints
	ERROR_file_name[0]  = '.';
	ERROR_file_name[1]  = '/';
	ERROR_file_name[2]  = 'I';
	ERROR_file_name[3]  = 'R';
	ERROR_file_name[4]  = 'S';
	ERROR_file_name[5]  = 'Y';
	ERROR_file_name[6]  = 'M';
	ERROR_file_name[7]  = 'E';
	ERROR_file_name[8]  = 'X';
	ERROR_file_name[9]  = 'E';
	ERROR_file_name[10] = '_';
	ERROR_file_name[11] = 'e';
	ERROR_file_name[12] = 'r';
	ERROR_file_name[13] = 'r';
	ERROR_file_name[14] = 'o';
	ERROR_file_name[15] = 'r';
	ERROR_file_name[16] = '_';
	ERROR_file_name[17] = 'P';
	ERROR_file_name[18] = 'a';
	ERROR_file_name[19] = 't';
	ERROR_file_name[20] = 'h';
	ERROR_file_name[21] = 'C';
	ERROR_file_name[22] = 'o';
	ERROR_file_name[23] = 'n';
	ERROR_file_name[24] = 's';    	
	ERROR_file_name[25] = 't';    
	ERROR_file_name[26] = 'r';    
	ERROR_file_name[27] = 'a';    
	ERROR_file_name[28] = 'i';    
	ERROR_file_name[29] = 'n';    
	ERROR_file_name[30] = 't';    
	ERROR_file_name[31] = '/';    
	ERROR_file_name[32] = 'p';    
	ERROR_file_name[33] = 'c';    
	ERROR_file_name[34] = '_';    
	ERROR_file_name[35] = '\0';    

	for(i = 0; i < IRSYMEXE_ERROR_CATEGORY_COUNT; i = i + 1)
	{
	    IRSYMEXE_errors[i] = 0;
	}// end of for{i}
    }// end of if(IRSYMEXE_error_seq_num)

    IRSYMEXE_error_seq_num  = IRSYMEXE_error_seq_num  + 1;
    IRSYMEXE_errors[err_id] = IRSYMEXE_errors[err_id] + 1;

    int num_len = sprintf( (ERROR_file_name + 35),
			   "%d_%d",
			   err_id,
			   IRSYMEXE_errors[err_id] // IRSYMEXE_error_seq_num
	   		 );
    ERROR_file_name[35 + num_len] = '\0';

    umask(0);
    fd = open( ERROR_file_name,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );

    if(fd != -1)
    {
	write( fd, 
	       str_info,
 	       strlen(str_info)
	     );

	close(fd);
    }// end of if( )
    

    free(str_info);

    // now generate the corresponding testcase for this EXPR !
    H_error_testcase_generate_4_expr( err_expr,
				      err_id,		      // category-id
				      IRSYMEXE_errors[err_id] // local-id
				      // IRSYMEXE_error_seq_num
			       	    );
}// end of record_ERROR_2file( )


/*
// error_testcase
void H_record_error_testcase_4_expr( HExpr    path_expr,
				     uint32_t category_id
			       	   )
{
    char   buffer[1024];
    char * databuf = NULL;
    int    count   = 0;
    int    fd      = 0;

    int      var_count = 0;
    HExpr *  var_array = obtaint_stp_vars_array(&var_count);
    HExpr    tmp_expr1 = NULL;
    HExpr    tmp_expr2 = NULL;
    uint32_t tmp_value = 0;

    int qresult = 0;
    HWholeCounterExample wce = NULL;

    int i = 0;
    
    count = sprintf( buffer,
		     "./error_testcase/testcase_%d_%d",
		     category_id,
		     IRSYMEXE_error_seq_num
		   );
    buffer[count] = '\0';

    fd = open( buffer,
	       (O_CREAT | O_RDWR),
	       (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
	     );
    
    if(fd >= 0)
    {
	if(var_count > 0)
	{
	    databuf = (char *)malloc(sizeof(char) * var_count);

	    tmp_expr1 = vc_notExpr( HHui_HVC,
				    path_expr
				  );
	    vc_push(HHui_HVC);
	    qresult = vc_query( HHui_HVC,
				tmp_expr1
			      );

	    if(qresult == 0)
	    {
		wce = vc_getWholeCounterExample(HHui_HVC);

		for(i = 0; i < var_count; i = i + 1)
		{
		    tmp_expr2  = vc_getTermFromCounterExample( HHui_HVC,
						               var_array[i],
						   	       wce
					         	     );		    	
		    databuf[i] = getBVUnsigned(tmp_expr2);

		    vc_DeleteExpr(tmp_expr2);
		}// end of for{i}
	    }// end of if(qresult)

	    vc_pop(HHui_HVC);	    	    
	    vc_DeleteExpr(tmp_expr1);

	    write( fd,
	           databuf,
	           var_count
	         );

	    free(databuf);
	    
	}// end of if(var_count)

	close(fd);
    }// end of if(fd)


    if(var_array != NULL)
    {
	free(var_array);
    }// end of if(var_array)
}// end of H_testcase_generate_4_expr( )
*/

