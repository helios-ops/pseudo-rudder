#ifndef H_HOOKDATA_H

	#define H_HOOKDATA_H

	#include "inttypes.h"
	#include "hc_interface.h"

        #include "FileHandle.h"

	// Readfile( )
	typedef struct H_ReadFile_data
	{
	    uint32_t  esp;
	    HVC *     hvc;

	    uint32_t  handle;	    
	}H_ReadFile_data_t, *PH_ReadFile_data_t;


	typedef struct H_CreateFileA_data
	{
	    uint32_t esp;
	    uint32_t handle;
	    uint32_t filename;
	}H_CreateFileA_data_t, *PH_CreateFileA_data_t;


	// CreateFileMapping( )
	typedef struct H_CreateFileMappingA_data
	{
	    int	     a_or_w; // 0 --- ascii; 1 --- unicode;
	    // int   file_d;
	    file_handle_entry_t * file_entry;
	    int      size;
	    uint32_t fmap_name;
	    uint32_t handle;
	}H_CreateFileMappingA_data_t, *PH_CreateFileMappingA_data_t;


	typedef struct H_MapViewOfFile_data
	{
	    uint32_t handle;
	    HVC  *   hvc;
	    int      fmap_d;
	    struct fileMapping_handle_entry * fileMap_entry;

	    uint32_t dwFileOffsetHigh;
	    uint32_t dwFileOffsetLow;
	    uint32_t dwNumberOfBytesToMap;
	}H_MapViewOfFile_data_t, *PH_MapViewOfFile_data_t;


	// OpenFile( )
	typedef struct H_OpenFile_data
	{
	    uint32_t esp;
	    uint32_t handle;
	}H_OpenFile_data_t, *PH_OpenFile_data_t;


	// SetFilePointer( )
	typedef struct H_SetFilePointer_data
	{
	   int start_pos;
	   int offset;
	   int fd; 
	   Pfile_handle_entry_t file_entry; // file-entry

	   uint32_t handle;
	}H_SetFilePointer_data_t, *PH_SetFilePointer_data_t;

	typedef struct H_recv_data
	{
	    uint32_t  esp;
	    HVC *     hvc;

	    uint32_t  handle;	    
	}H_recv_data_t, *PH_recv_data_t;

	typedef struct H_normal_data
    	{
	    uint32_t  handle;	
	}H_normal_data_t, *PH_normal_data_t;

	typedef struct H_callstack_data
	{
	    uint32_t ebp;
	    uint32_t handle;
	}H_callstack_data_t, *PH_callstack_data_t;

        typedef struct H_function_summary_data
 	{
	    uint32_t handle;
	    void *   func_summary_entry;
	}H_function_summary_data_t, *PH_function_summary_data_t;


#endif

