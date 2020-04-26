#ifndef H_GET_TEMU_DATA_H
	#define H_GET_TEMU_DATA_H

	#include <string.h>
	#include <ctype.h>
	#include <inttypes.h>
	
	#include "H_taint_record.h"

	

	
	
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */ 
/*					 �ṩ������ִ�еķ���				  */
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */



	int GetTEMUReg_AccessIDByIndex( int index ) ;

	int GetReg_SizeByIndex(int index);

	int GetReg_Index(string name);

	char * GetRegNameByIndex(int index);

	int GetEFLAG_Bit_Index(string name);

	char * GetEFLAGBitNameByIndex(int index);

	


	// �������״̬�Ļ�ȡ
	/* ================================================================= */		

	// ��ȡ TEMU ����ִ���е��ڴ����ֵ
	void  GetConcreteMemData( uint32_t address, 
				  int 	   len, 
				  void *   buf
				);
	
	void SetConcreteMemData( uint32_t address,
				 int	  len,
				 void *   buf
			       );



	// ��ȡ TEMU ����ִ���еļĴ�������ֵ
	uint32_t GetConcreteRegData( string reg_name );
	
	void SetConcreteRegData( int reg_idx,
				 void * buf
			       );
	

	// ��ȡ TEMU ����ִ���е�EFLAGS �� bit �ľ���ֵ
	uint32_t GetConcreteEFLAGData( string bitname );

	void SetConcreteEFLAGData( int bit_index,
				   int bit_value
				 );
	/* ================================================================= */

	


	// ���Ż���״̬�Ļ�ȡ
	// Ҫ���û�Ԥ�ȷ��仺����
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
	// ���Ż���״̬�Ļ�ȡ



	// ���Ż���״̬������
	/* ================================================================= */
	int HH_Set_TemuRegisterByteTaintRecord( string	  	    reg_name,
				 		int		    taint_bitmap,
						H_taint_record_t *  taint_record
					      );


	int HH_Set_TemuEFAGSTaintRecord( string	  	     bit_name,
					 H_taint_record_t *  taint_record
				       );


	// �����ض��ڴ��ֽڵķ���ֵ
	void HH_Set_TemuMemByteTaintRecord( uint32_t  		address,
					    int			size,
				   	    int		 	taint_bitmap,
					    H_taint_record_t *  taint_record
					  );	
	/* ================================================================= */
	// ���Ż���״̬������





	

	
#endif
