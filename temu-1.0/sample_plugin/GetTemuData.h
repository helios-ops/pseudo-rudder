#ifndef H_GET_TEMU_DATA_H
	#define H_GET_TEMU_DATA_H

	#include <string.h>
	#include <ctype.h>
	#include <inttypes.h>
	
	#include "H_taint_record.h"

	

	
	
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */ 
/*					 提供给符号执行的服务				  */
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */



	int GetTEMUReg_AccessIDByIndex( int index ) ;

	int GetReg_SizeByIndex(int index);

	int GetReg_Index(string name);

	char * GetRegNameByIndex(int index);

	int GetEFLAG_Bit_Index(string name);

	char * GetEFLAGBitNameByIndex(int index);

	


	// 具体机器状态的获取
	/* ================================================================= */		

	// 读取 TEMU 机器执行中的内存具体值
	void  GetConcreteMemData( uint32_t address, 
				  int 	   len, 
				  void *   buf
				);
	
	void SetConcreteMemData( uint32_t address,
				 int	  len,
				 void *   buf
			       );



	// 读取 TEMU 机器执行中的寄存器具体值
	uint32_t GetConcreteRegData( string reg_name );
	
	void SetConcreteRegData( int reg_idx,
				 void * buf
			       );
	

	// 读取 TEMU 机器执行中的EFLAGS 的 bit 的具体值
	uint32_t GetConcreteEFLAGData( string bitname );

	void SetConcreteEFLAGData( int bit_index,
				   int bit_value
				 );
	/* ================================================================= */

	


	// 符号机器状态的获取
	// 要求用户预先分配缓冲区
	/* ================================================================= */
	uint64_t HH_Query_TemuRegisterTaintStatus( string 	      reg_name,
					           H_taint_record_t * h_reg_records
						 );

	
	uint32_t HH_Query_TemuEFLAGSTaintStatus( string       	    eflag_name,
						 H_taint_record_t * eflag_bit_expr
					       );


	uint64_t HH_Query_TemuMemTaintStatus( uint32_t    	   m_address,
					      int		   m_length,
					      H_taint_record_t *   h_taint_recoird
					    );
	/* ================================================================= */
	// 符号机器状态的获取



	// 符号机器状态的设置
	/* ================================================================= */
	int HH_Set_TemuRegisterByteTaintRecord( string	  	    reg_name,
				 		int		    taint_bitmap,
						H_taint_record_t *  taint_record
					      );


	int HH_Set_TemuEFAGSTaintRecord( string	  	     bit_name,
					 H_taint_record_t *  taint_record
				       );


	// 设置特定内存字节的符号值
	void HH_Set_TemuMemByteTaintRecord( uint32_t  		address,
					    int			size,
				   	    int		 	taint_bitmap,
					    H_taint_record_t *  taint_record
					  );	
	/* ================================================================= */
	// 符号机器状态的设置





	

	
#endif
