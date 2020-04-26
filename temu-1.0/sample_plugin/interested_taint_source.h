#ifndef H_INTERSTED_TAINT_SOURCE_H
    #define H_INTERSTED_TAINT_SOURCE_H

    /* we should notify to temu that these files were the interested potential 
       taint source for our target program.
     */
    void H_intersted_file_init_2_temu( char *** str_names,
				       int  *   str_count
			             );
    
    void H_intersted_file_free( char ** str_names,
			        int     str_count
			      );
#endif
