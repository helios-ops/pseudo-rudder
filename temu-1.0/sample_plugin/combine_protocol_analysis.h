#ifndef H_COMBINE_PROTOCOL_ANALYSIS_H
    #define H_COMBINE_PROTOCOL_ANALYSIS_H

    typedef struct file_protocol
    {
	// HHui-Fixme --- TODO: more elegant handling
	char * filename;
	int  * len_domains;
  	int    len_domain_count;

	struct file_protocol * next;
    }file_protocol_t, *Pfile_protocol_t;

    typedef struct file_protocol_list
    {
	struct file_protocol * head;
	struct file_protocol * end;
	int count;
    }file_protocol_list_t, *Pfile_protocol_list_t;



    typedef struct protocol_analysis_util
    {
	void (*h_protocol_analysis_init)( int     category_id,
					  int     sub_category_id,
			         	  char *  filename,

					  // OUTPUT the total count of the length domain in the target-file
				          int *   h_total_len_count,   

				 	  // OUTPUT the byte_sequence for each len_domain
				          int **  h_total_len_domains
			       		);

	// void (*h_protocol_analysis_free)( );
    }protocol_analysis_util_t, *Pprotocol_analysis_util_t;

    void h_TEMU_build_protocol_analysis_util( );    

    /* category_id:
       0 --- file-source
            sub_category_id: 
	    0 --- midi file
   
     */
    void protocol_analysis_init( int     category_id,
				 int     sub_category_id,
			         char *  filename,

				 // OUTPUT the total count of the length domain in the target-file
			         int *   h_total_len_count,   

				 // OUTPUT the byte_sequence for each len_domain
			         int **  h_total_len_domains
			       );

    void file_protocol_list_init( );

    void file_proto_list_delete( );

#endif
