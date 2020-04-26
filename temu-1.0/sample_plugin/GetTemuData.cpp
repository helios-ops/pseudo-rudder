#include <ctype.h>
#include <inttypes.h>

#include "H_taint_record.h"

// HHui's STP declaration !
#include "hc_interface.h"
#include <string>

using namespace std;



#include "H_cpu.h"



// TEMU �ĵ�ǰ���۵�״̬�ͷ��Ż���״̬
/* =================================================================================== */

// �Ĵ���
uint8_t       *    HHui_regs_records;
uint64_t      *    HHui_regs_bitmap;

// EFLAGS
uint8_t	      *    HHui_eflags_records;
uint32_t      *    HHui_eflags_bitmap;


// �ڴ�
tpage_entry_t **   HHui_tpage_table;

/* =================================================================================== */
// TEMU   �ĵ�ǰ���۵�״̬�ͷ��Ż���״̬





//  TEMU  ��ǰ�ľ��������״̬
/* =================================================================================== */

// TEMU_cpu_eflags
uint32_t *   HHui_TEMU_EFLAGS; 	

uint32_t *   HHui_TEMU_EIP;

// array of CPU general-purpose registers, such as R_EAX, R_EBX
uint32_t *   HHui_TEMU_CPU_REGS;


/* =================================================================================== */
//  TEMU  ��ǰ�ľ��������״̬





// ���ڷ���TEMU   �������������
int TEMU_CPU_ACCESS_INDICES[ ] = 
{
	eax_reg, ecx_reg, edx_reg, ebx_reg, esp_reg, ebp_reg, esi_reg, edi_reg,
	ax_reg,	cx_reg,   dx_reg,  bx_reg,   sp_reg,   bp_reg,  si_reg,   di_reg,
	al_reg,    cl_reg,    dl_reg,   bl_reg,    ah_reg,   ch_reg,  dh_reg,  bh_reg	
};


// �õ�����TEMU    �Ĵ�����ID
int GetTEMUReg_AccessIDByIndex( int index )
{
	return TEMU_CPU_ACCESS_INDICES[ index ];
	
}// end of GetTEMUReg_AccessIDByIndex( int index )
	


char * TEMU_CPU_REGISTER_NAMES [ ] = 
{
	// General purpose 32-bit registers
	"R_EAX",  
	"R_ECX",
 	"R_EDX", 
  	"R_EBX", 
	"R_ESP", 
	"R_EBP", 
	"R_ESI", 
	"R_EDI",  

	// 16-bit registers (bits 0-15)
	"R_AX", 
	"R_CX", 
	"R_DX", 	
	"R_BX", 
	"R_SP", 
	"R_BP", 	
	"R_SI", 
	"R_DI", 

	// 8-bit registers (bits 0-7)
	"R_AL",
	"R_CL", 	
	"R_DL", 	
	"R_BL", 
	
	// 8-bit registers (bits 8-15)
	"R_AH",
	"R_CH",	
	"R_DH",	
	"R_BH",
	NULL
};

int TEMU_REGISTER_SIZES [ ] = 
{
	// 8 General purpose 32-bit registers
	4, 4, 4, 4, 4, 4, 4, 4,

	// 8 16-bit registers (bits 0-15)
	2, 2, 2, 2, 2, 2, 2, 2,

	// 8 8-bit registers (bits 0-7)
	1, 1, 1, 1, 1, 1, 1, 1,

	// 8-bit registers (bits 8-15)
	1, 1, 1, 1, 1, 1, 1, 1
};


int GetReg_SizeByIndex(int index)
{
	return TEMU_REGISTER_SIZES[index];
}
	
int GetReg_Index(string name)
{
	int i = 0;
	const char * buf = name.c_str( );
	
	while( TEMU_CPU_REGISTER_NAMES [i] != NULL)
	{
		if( strcmp( buf, TEMU_CPU_REGISTER_NAMES [i] ) == 0 )
		{
			return i;
		}// end of if( )

		i = i + 1;
	}// end of while{ }

	return -1;
}// end of GetReg_Index()


char * GetRegNameByIndex(int index)
{
	return TEMU_CPU_REGISTER_NAMES [index] ;
	
}// GetRegNameByIndex(int index)



char * TEMU_CPU_EFLAGS_NAMES [ ] = 
{
	"R_CF",
	"R_PF",  
	"R_AF",
	"R_ZF",
	"R_SF", 
	"R_OF"
};


int GetEFLAG_Bit_Index(string name)
{
	int i = 0;
	const char * buf = name.c_str( );
	
	while( TEMU_CPU_EFLAGS_NAMES [i] != NULL)
	{
		if( strcmp( buf, TEMU_CPU_EFLAGS_NAMES [i] ) == 0 )
		{
			return i;
		}// end of if( )

		i = i + 1;
	}// end of while{ }

	return -1;
}// end of GetReg_Index()



char * GetEFLAGBitNameByIndex(int index)
{
	return TEMU_CPU_EFLAGS_NAMES[index] ;
	
}// GetRegNameByIndex(int index)









// ����ֵ
/* =================================================================================== */
// ��ȡ�ڴ�ľ���ֵ
int (* HH_TEMU_read_mem)(uint32_t vaddr, int len, void *buf);

void (* HH_TEMU_write_mem)(uint32_t vaddr, int len, void *buf);

void (* HH_TEMU_write_register)(int reg_id, void *buf);

// ��ȡ�Ĵ����ľ���ֵ
void (* HH_TEMU_read_register)(int reg_id, void *buf);
/* =================================================================================== */





// �۵�������۵��¼���ݻ�ȡ
/* =================================================================================== */

// �����ڴ���۵�״̬������ȡ��ص��۵���Ϣ��¼��������ص��۵���ͼ
uint64_t (* HH_taintcheck_memory_check)(uint32_t addr, int size,  uint8_t * records);


// �����Ӧ�ļĴ����۵�״̬������ȡ��ص��۵���Ϣ��¼��������ص��۵���ͼ
uint64_t (* HH_taintcheck_register_check)(int reg, int offset, int size, uint8_t * records);



// �����ڴ���۵�״̬������ȡ��ص��۵���Ϣ��¼��������ص��۵���ͼ
uint64_t (* HH_taintcheck_taint_memory)(uint32_t addr, int size, uint64_t taint, uint8_t * records);


// Set �Ĵ����۵�״̬������ȡ��ص��۵���Ϣ��¼��������ص��۵���ͼ
uint64_t (* HH_taintcheck_taint_register)(int reg, int offset, int size, uint64_t taint, uint8_t * records);

/* =================================================================================== */





// �ṩ�� Temu �Ĳ�����õĽӿڣ��õ� Temu ��Ϣ��ȡ��ԭ�Ӻ���
void Set_HH_TEMU_concrete_read( int (* f_read_mem)(uint32_t vaddr, int len, void *buf),
		      		void (* f_read_register)(int reg_id, void *buf),

				void (* f_write_mem)(uint32_t vaddr, int len, void *buf), 
				void (* f_write_register)(int reg_id, void *buf),

				uint64_t (* f_taintcheck_memory_check)(uint32_t addr, int size,  uint8_t * records),
				uint64_t (* f_taintcheck_register_check)(int reg, int offset, int size, uint8_t * records),

				uint64_t (* f_taintcheck_taint_memory)(uint32_t addr, int size, uint64_t taint, uint8_t * records),
				uint64_t (* f_taintcheck_taint_register)(int reg, int offset, int size, uint64_t taint, uint8_t * records)
			      )
{
	HH_TEMU_read_mem 	      = f_read_mem;
	HH_TEMU_read_register         = f_read_register;


	HH_TEMU_write_mem 	      = f_write_mem;
	HH_TEMU_write_register        = f_write_register;


	HH_taintcheck_memory_check    = f_taintcheck_memory_check;
	HH_taintcheck_register_check  = f_taintcheck_register_check;
	

	HH_taintcheck_taint_memory    =	f_taintcheck_taint_memory;
	HH_taintcheck_taint_register  = f_taintcheck_taint_register;

	

}// end of Set_HH_TEMU_read_mem( )





/* ��װ���ⲿ����ṩ����ȫ�ӿڣ�
    ���ڱ�������ȡTemu  ��ص� ��Ϣ�ⲿ����ȫ��Ϣ
  */
void Get_HH_TEMU_Info( uint32_t *  	 TEMU_EFLAGS,    // TEMU_cpu_eflags
		       uint32_t *   	 TEMU_EIP,
		       uint32_t *  	 TEMU_CPU_REGS,  // array of CPU general-purpose registers, such as R_EAX,R_EBX 
		       tpage_entry_t **  tpage_table,

		       uint64_t * 	 regs_bitmap, //!<bitmap for registers
		       uint8_t  *	 regs_records, //!<taint records for registers

		       uint32_t *	 eflags_bitmap, //!<bitmap for eflags
		       uint8_t  * 	 eflags_records//!<taint records for eflags
		     )

{
	HHui_TEMU_EFLAGS    = TEMU_EFLAGS;
	
	HHui_TEMU_EIP	    = TEMU_EIP;

	// array of CPU general-purpose registers, such as R_EAX, R_EBX
	HHui_TEMU_CPU_REGS  = TEMU_CPU_REGS;


	HHui_tpage_table    = tpage_table;

	// Regs
	HHui_regs_records   = regs_records;
	HHui_regs_bitmap    = regs_bitmap;

	// EFLAGS
	HHui_eflags_records = eflags_records;
	HHui_eflags_bitmap  = eflags_bitmap;
	

}// end of Get_HH_TEMU_total_information( )



	

// ����ֵ���
/* =================================================================================== */
// ��ȡTEMU   ����ִ���е��ڴ����ֵ
int  GetConcreteMemData( uint32_t  address, 
			 int 	   len, 
			 void *	   buf
		       )
{
	return HH_TEMU_read_mem( address,
			   	 len,
				 buf
			       );
		
}// end of GetConcreteMemData( ) 


void SetConcreteMemData( uint32_t  address, 
			 int 	   len, 
			 void *	   buf
		       )
{
	HH_TEMU_write_mem( address,
			   len,
			   buf
			 );
}// end of SetConcreteMemData( )




void SetConcreteRegData( int    reg_idx, 
			 void *	buf
		       )
{
	int reg_access_id = GetTEMUReg_AccessIDByIndex( reg_idx );

	HH_TEMU_write_register( reg_access_id,
				buf
			      );
}// end of SetConcreteRegData( )



// ��ȡTEMU   ����ִ���еļĴ�������ֵ
uint32_t GetConcreteRegData(string reg_name)
{
	const char * c_regname = reg_name.c_str( ) ; 
	int 	     reg_size  = -1;
	int	     reg_index = -1;

	uint32_t     reg_value = 0;
	
	
	// 32-bit   ͨ�üĴ���
	/* ---------------------------------------------------------------------- */
	reg_size = 4;
	
	if( strcmp( c_regname,  "R_EAX" ) == 0
	  )

	{
		reg_index = eax_reg;
	}
	else if( strcmp( c_regname,  "R_ECX" ) == 0
		   )
	{
		reg_index = ecx_reg;
	}
	else if( strcmp( c_regname,  "R_EDX" ) == 0
		   )
	{
		reg_index = edx_reg;
	}
	else if( strcmp( c_regname,  "R_EBX" ) == 0
		   )
	{
		reg_index = ebx_reg;
	}
	else if( strcmp( c_regname,  "R_ESP" ) == 0
		   )
	{
		reg_index = esp_reg;
	}
	else if( strcmp( c_regname,  "R_EBP" ) == 0
		   )
	{
		reg_index = ebp_reg;
	}
	else if( strcmp( c_regname,  "R_ESI" ) == 0
		   )
	{
		reg_index = esi_reg;
	}
	else if( strcmp( c_regname,  "R_EDI" ) == 0
		   )
	{
		reg_index = edi_reg;
	}// end of if( )


	if(reg_index != -1)
	{
		goto ATOM_REG_READING;
	}// end of if( )
	/* ---------------------------------------------------------------------- */
	// 32-bit   ͨ�üĴ���



	// 16-bit   ͨ�üĴ���
	/* ---------------------------------------------------------------------- */
	reg_size = 2;
	
	if( strcmp( c_regname,  "R_AX" ) == 0
	  )

	{
		reg_index = ax_reg ;
	}
	else if( strcmp( c_regname,  "R_CX" ) == 0
		   )
	{
		reg_index = cx_reg ;
	}
	else if( strcmp( c_regname,  "R_DX" ) == 0
		   )
	{
		reg_index = dx_reg ;
	}
	else if( strcmp( c_regname,  "R_BX" ) == 0
		   )
	{
		reg_index = bx_reg ;
	}
	else if( strcmp( c_regname,  "R_SP" ) == 0
		   )
	{
		reg_index = sp_reg ;
	}
	else if( strcmp( c_regname,  "R_BP" ) == 0
		   )
	{
		reg_index = bp_reg ;
	}
	else if( strcmp( c_regname,  "R_SI" ) == 0
		   )
	{
		reg_index = si_reg ;
	}
	else if( strcmp( c_regname,  "R_DI" ) == 0
		   )
	{
		reg_index = di_reg ;
	}// end of if( )


	if(reg_index != -1)
	{
		goto ATOM_REG_READING;
	}// end of if( )
	/* ---------------------------------------------------------------------- */
	// 16-bit   ͨ�üĴ���



	// 8-bit   ͨ�üĴ���
	/* ---------------------------------------------------------------------- */	
	reg_size = 1;
	
	if( strcmp( c_regname,  "R_AL" ) == 0
	  )

	{
		reg_index = al_reg;
	}
	else if( strcmp( c_regname,  "R_CL" ) == 0
		   )
	{
		reg_index = cl_reg;
	}
	else if( strcmp( c_regname,  "R_DL" ) == 0
		   )
	{
		reg_index = dl_reg;
	}
	else if( strcmp( c_regname,  "R_BL" ) == 0
		   )
	{
		reg_index = bl_reg;
	}
	else if( strcmp( c_regname,  "R_AH" ) == 0
		   )
	{
		reg_index = ah_reg;
	}
	else if( strcmp( c_regname,  "R_CH" ) == 0
		   )
	{
		reg_index = ch_reg;
	}
	else if( strcmp( c_regname,  "R_DH" ) == 0
		   )
	{
		reg_index = dh_reg;
	}
	else if( strcmp( c_regname,  "R_BH" ) == 0
		   )
	{
		reg_index = bh_reg;	
	}
	// end of if( )	

ATOM_REG_READING:

	//  ��ȡTEMU   �Ĵ�����ֵ
	HH_TEMU_read_register( reg_index,
			       &reg_value
			     );

	return reg_value;
	
}// end of GetConcreteRegData( )


void SetConcreteEFLAGData( int bit_index,
			   int bit_value
			 )
{
	uint32_t mask  = (1 << 32) - (1 << bit_index) ;
	uint32_t value = bit_value << bit_index;
	
	*HHui_TEMU_EFLAGS = *HHui_TEMU_EFLAGS & mask ;
	*HHui_TEMU_EFLAGS = *HHui_TEMU_EFLAGS | value ;

}// end of SetConcreteEFLAGData( )



// ��ȡTEMU   ����ִ���е�EFLAGS   ��bit   �ľ���ֵ
uint32_t GetConcreteEFLAGData( string bitname )
{
	const char * c_bitname	   = bitname.c_str( ) ;

	int 	     reg_bit_index = -1 ;
	uint32_t     reg_bit_mask  = 0 ;

	
	//  EFLAGS  �ĸ������λ
	/* ---------------------------------------------------------------------- */

	/*
		  ret.push_back(new VarDecl("R_CF", r1));
		  ret.push_back(new VarDecl("R_CF", r1));  
		  ret.push_back(new VarDecl("R_PF", r1));  
		  ret.push_back(new VarDecl("R_AF", r1));  
		  ret.push_back(new VarDecl("R_ZF", r1));  
		  ret.push_back(new VarDecl("R_SF", r1));  
		  ret.push_back(new VarDecl("R_OF", r1));  
		  ret.push_back(new VarDecl("R_CC_OP", r32));  
		  ret.push_back(new VarDecl("R_CC_DEP1", r32));  
		  ret.push_back(new VarDecl("R_CC_DEP2", r32));  
		  ret.push_back(new VarDecl("R_CC_NDEP", r32));  
	  */
	if( strcmp( c_bitname,  "R_CF" ) == 0
	  )

	{
		reg_bit_index = 0 ;
	}
	else if( strcmp( c_bitname,  "R_PF" ) == 0
		   )
	{
		reg_bit_index = 2 ;
	}
	else if( strcmp( c_bitname,  "R_AF" ) == 0
		   )
	{
		reg_bit_index = 4 ;
	}
	else if( strcmp( c_bitname,  "R_ZF" ) == 0
		   )
	{
		reg_bit_index = 6 ;
	}
	else if( strcmp( c_bitname,  "R_SF" ) == 0
		   )
	{
		reg_bit_index = 7 ;
	}
	else if( strcmp( c_bitname,  "R_OF" ) == 0
		   )
	{
		reg_bit_index = 11 ;
	}
	else if( strcmp( c_bitname,  "R_CC_OP" ) == 0
		   )
	{
		return -1;
	}
	else if( strcmp( c_bitname,  "R_CC_DEP1" ) == 0
		   )
	{
		return -1;
	}
	else if( strcmp( c_bitname,  "R_CC_DEP2" ) == 0
		   )
	{
		return -1;
	}
	else if( strcmp( c_bitname,  "R_CC_NDEP" ) == 0
		   )
	{
		return -1;
	}
	else if( strcmp( c_bitname,  "R_DFLAG" ) == 0
		   )
	{
		return -1;
	}
	else if( strcmp( c_bitname,  "R_IDFLAG" ) == 0
		   )
	{
		return -1;
	}
	else if( strcmp( c_bitname,  "R_ACFLAG" ) == 0
		   )
	{
		return -1;
	}
	else if( strcmp( c_bitname,  "R_EMWARN" ) == 0
		   )
	{
		return -1;
	}
	/* ---------------------------------------------------------------------- */


	reg_bit_mask = (1 << reg_bit_index);
	
	
	return ( (*HHui_TEMU_EFLAGS) & reg_bit_mask ) ;		
	
	//  EFLAGS  �ĸ������λ		
}// end of GetConcreteEFLAGData( )

/* =================================================================================== */
// ����ֵ���









//  ��װ�ķ��Ż���״̬��ѯ����
/* =================================================================================== */

int HH_Query_TemuRegisterIndexByName( string  reg_name, 
				      int *   reg_size, 
				      int *   reg_offset
				    )
{
	const char * c_regname = reg_name.c_str( ) ;

	/*
	  ret.push_back(new VarDecl("EFLAGS", r32));
  ret.push_back(new VarDecl("R_LDT", r32)); 
  ret.push_back(new VarDecl("R_GDT", r32)); 
  ret.push_back(new VarDecl("R_DFLAG", r32)); 

  ret.push_back(new VarDecl("R_CS", r16)); 
  ret.push_back(new VarDecl("R_DS", r16)); 
  ret.push_back(new VarDecl("R_ES", r16)); 
  ret.push_back(new VarDecl("R_FS", r16)); 
  ret.push_back(new VarDecl("R_GS", r16)); 
  ret.push_back(new VarDecl("R_SS", r16)); 

	  */

	int reg_index = -1;

	*reg_offset   = 0;
	*reg_size     = -1;


	// 32-bit   ͨ�üĴ���
	/* ---------------------------------------------------------------------- */
	*reg_size = 4;
	
	if( strcmp( c_regname,  "R_EAX" ) == 0
	  )

	{
		reg_index = 0 ;
	}
	else if( strcmp( c_regname,  "R_ECX" ) == 0
	       )
	{
		reg_index = 1;
	}
	else if( strcmp( c_regname,  "R_EDX" ) == 0
	       )
	{
		reg_index = 2;
	}
	else if( strcmp( c_regname,  "R_EBX" ) == 0
	       )
	{
		reg_index = 3;
	}
	else if( strcmp( c_regname,  "R_ESP" ) == 0
	       )
	{
		reg_index = 4;
	}
	else if( strcmp( c_regname,  "R_EBP" ) == 0
	       )
	{
		reg_index = 5;
	}
	else if( strcmp( c_regname,  "R_ESI" ) == 0
	       )
	{
		reg_index = 6;
	}
	else if( strcmp( c_regname,  "R_EDI" ) == 0
	       )
	{
		reg_index = 7;
	}// end of if( )


	if(reg_index != -1)
	{
		return reg_index;
	}// end of if( )
	/* ---------------------------------------------------------------------- */
	// 32-bit   ͨ�üĴ���




	// 16-bit   ͨ�üĴ���
	/* ---------------------------------------------------------------------- */
	*reg_size = 2;
	
	if( strcmp( c_regname,  "R_AX" ) == 0
	  )

	{
		reg_index = 0 ;
	}
	else if( strcmp( c_regname,  "R_CX" ) == 0
	       )
	{
		reg_index = 1 ;
	}
	else if( strcmp( c_regname,  "R_DX" ) == 0
	       )
	{
		reg_index = 2 ;
	}
	else if( strcmp( c_regname,  "R_BX" ) == 0
	       )
	{
		reg_index = 3 ;
	}
	else if( strcmp( c_regname,  "R_SP" ) == 0
	       )
	{
		reg_index = 4 ;
	}
	else if( strcmp( c_regname,  "R_BP" ) == 0
	       )
	{
		reg_index = 5 ;
	}
	else if( strcmp( c_regname,  "R_SI" ) == 0
	       )
	{
		reg_index = 6 ;
	}
	else if( strcmp( c_regname,  "R_DI" ) == 0
	       )
	{
		reg_index = 7 ;
	}// end of if( )


	if(reg_index != -1)
	{
		return reg_index;
	}// end of if( )
	/* ---------------------------------------------------------------------- */
	// 16-bit   ͨ�üĴ���



	// 8-bit   ͨ�üĴ���
	/* ---------------------------------------------------------------------- */	
	*reg_size = 1;
	
	if( strcmp( c_regname,  "R_AL" ) == 0
	  )

	{	
		reg_index = 0;
	}
	else if( strcmp( c_regname,  "R_CL" ) == 0
	       )
	{
		reg_index = 1;
	}
	else if( strcmp( c_regname,  "R_DL" ) == 0
	       )
	{
		reg_index = 2;
	}
	else if( strcmp( c_regname,  "R_BL" ) == 0
	       )
	{
		reg_index = 3;
	}
	else if( strcmp( c_regname,  "R_AH" ) == 0
	       )
	{
		reg_index     = 0;
		*reg_offset = 1;
	}
	else if( strcmp( c_regname,  "R_CH" ) == 0
	       )
	{
		reg_index     = 1;
		*reg_offset = 1;
	}
	else if( strcmp( c_regname,  "R_DH" ) == 0
	       )
	{
		reg_index     = 2;
		*reg_offset = 1;
	}
	else if( strcmp( c_regname,  "R_BH" ) == 0
	       )
	{
		reg_index     = 3;
		*reg_offset = 1;		
	}

	return reg_index;

}// end of HH_Query_TemuRegisterIndexByName( )




/*  ͨ�üĴ����ķ��ź���

     h_reg_records  Ҫ�����Ѿ�����õĻ�����
     
     ����ֵ:

     0  	  ----  δ����Ⱦ
     -1 	  ----  δ�ҵ�
     ����----  ��Ӧ����Ⱦ��ͼ
  */
uint64_t HH_Query_TemuRegisterTaintStatus( string	       reg_name,
					   H_taint_record_t *  h_reg_records
					 )
{
	int reg_size    = 0 ;
	int reg_offset = 0 ;
	int reg_index = -1;
	
	if( ( reg_index = HH_Query_TemuRegisterIndexByName( reg_name, 
							    &reg_size, 
							    &reg_offset
						          ) 
	    ) == -1
	  )		
	{
		return -1;
	}// end of if( )
	
	return HH_taintcheck_register_check( reg_index, 
				    	     reg_offset,
					     reg_size,
					     (uint8_t *)h_reg_records
					   );		
	
}// end of HH_Query_TemuRegisterTaintStatus( )





int HH_Query_TemuEFLAGSByName( string  eflag_name )
{
	const char * c_regname     = eflag_name.c_str( ) ;

	int 	     reg_bit_index = -1;
	

	//  EFLAGS  �ĸ������λ
	/* ---------------------------------------------------------------------- */

	/*
		  ret.push_back(new VarDecl("R_CF", r1));
		  ret.push_back(new VarDecl("R_CF", r1));  
		  ret.push_back(new VarDecl("R_PF", r1));  
		  ret.push_back(new VarDecl("R_AF", r1));  
		  ret.push_back(new VarDecl("R_ZF", r1));  
		  ret.push_back(new VarDecl("R_SF", r1));  
		  ret.push_back(new VarDecl("R_OF", r1));  
		  ret.push_back(new VarDecl("R_CC_OP", r32));  
		  ret.push_back(new VarDecl("R_CC_DEP1", r32));  
		  ret.push_back(new VarDecl("R_CC_DEP2", r32));  
		  ret.push_back(new VarDecl("R_CC_NDEP", r32));  
	  */
	if( strcmp( c_regname,  "R_CF" ) == 0
	  )

	{
		reg_bit_index = 0 ;
	}
	else if( strcmp( c_regname,  "R_PF" ) == 0
		   )
	{
		reg_bit_index = 2 ;
	}
	else if( strcmp( c_regname,  "R_AF" ) == 0
	       )
	{
		reg_bit_index = 4 ;
	}
	else if( strcmp( c_regname,  "R_ZF" ) == 0
	       )
	{
		reg_bit_index = 6 ;
	}
	else if( strcmp( c_regname,  "R_SF" ) == 0
	       )
	{
		reg_bit_index = 7 ;
	}
	else if( strcmp( c_regname,  "R_OF" ) == 0
	       )
	{
		reg_bit_index = 11 ;
	}
	else if( strcmp( c_regname,  "R_CC_OP" ) == 0
	       )
	{
		return -1;
	}
	else if( strcmp( c_regname,  "R_CC_DEP1" ) == 0
	       )
	{
		return -1;
	}
	else if( strcmp( c_regname,  "R_CC_DEP2" ) == 0
	       )
	{
		return -1;
	}
	else if( strcmp( c_regname,  "R_CC_NDEP" ) == 0
	       )
	{
		return -1;
	}
	else if( strcmp( c_regname,  "R_DFLAG" ) == 0
	       )
	{
		return -1;
	}
	else if( strcmp( c_regname,  "R_IDFLAG" ) == 0
	       )
	{
		return -1;
	}
	else if( strcmp( c_regname,  "R_ACFLAG" ) == 0
	       )
	{
		return -1;
	}
	else if( strcmp( c_regname,  "R_EMWARN" ) == 0
	       )
	{
		return -1;
	}
	/* ---------------------------------------------------------------------- */
	//  EFLAGS  �ĸ������λ	

	return reg_bit_index;
	
}// end of HH_Query_TemuEFLAGSByName( )



//  EFLAGS �Ĵ���---- Ŀǰֻ���ĵ�����Flag-Bit !
/* 
     ����ֵ:

     0   ----  δ����Ⱦ
     -1  ----  δ�ҵ���Ӧ�ķ���
     ���� ----  ��Ӧ����Ⱦ��ͼ
     
  */
uint32_t HH_Query_TemuEFLAGSTaintStatus( string  	     eflag_name,
					 H_taint_record_t *  eflag_bit_expr_record
				       )
{
	int 	  reg_bit_index = HH_Query_TemuEFLAGSByName(eflag_name);
	uint32_t  e_taint_mask  = 0;
	uint32_t  e_taintbitmap = 0;
	
	if( reg_bit_index == -1 )
	{
		return -1;
	}// end of if( )

	e_taint_mask  = (1 << reg_bit_index) ;
	e_taintbitmap = (*HHui_eflags_bitmap) & e_taint_mask;
	
	if( e_taintbitmap )
	{
		*eflag_bit_expr_record = *( (H_taint_record_t * )( HHui_eflags_records + 
					  	 		   reg_bit_index * sizeof(H_taint_record_t) 
				   	      		     	 )
					  );
	}// end of if( )
	
	return e_taintbitmap;

	
}// end of  HH_Query_TemuEFLAGSTaintStatus( string reg_name, int bit_length)


//  �ڴ�ķ���״̬���
/*

     ����ֵ:

     0   ----  δ����Ⱦ
     ���� ----  ��Ӧ����Ⱦ��ͼ
     
  */
uint64_t HH_Query_TemuMemTaintStatus( uint32_t  	 m_address,
				      int		 m_length,
				      H_taint_record_t * h_taint_recoird
				    )
{
	uint64_t mem_taint_status = -1;

	/* �����ڴ���۵�״̬������ȡ��ص��۵���Ϣ��¼��
	    ������ص��۵���ͼ
	  */
	mem_taint_status = HH_taintcheck_memory_check( m_address, 
						       m_length,  
						       (uint8_t *)h_taint_recoird
						     );
	
	
	return mem_taint_status;
}// end of HH_Query_TemuMemTaintStatus( uint32_t  m_address, int	 m_length)

/* =================================================================================== */
//  ��װ�Ļ���״̬��ѯ����







// �����ż���Ľ��������������
/* =================================================================================== */

int HH_Set_TemuRegisterByteTaintRecord( string	  	    reg_name,	
					int		    taint_bitmap,				
					H_taint_record_t *  taint_record
				      )
{
	int reg_size    = 0;	
	int reg_index   = -1;
	int reg_offset  = 0;

	if( reg_index == -1 )
	{
		reg_index = HH_Query_TemuRegisterIndexByName( reg_name, 
							      &reg_size, 
							      &reg_offset
							    );
	}// end of if( )
	

	// if( ( reg_index == 0 ) || // not tainted
	//    ( reg_index == -1 )	  // reg flag not found
	if( reg_index == -1 )	  
	{
		return reg_index;
	}// end of if( )
	

	HH_taintcheck_taint_register( reg_index,
				      reg_offset,
				      reg_size, // fixed size for specific register
				      taint_bitmap,
				      (uint8_t *)taint_record
				    );



		
	// ��һ�ֽڵ����
	/*
	memcpy( HHui_regs_records + (reg_index * 4 + reg_offset) * sizeof(H_taint_record_t), 
	        taint_record,
	        sizeof(H_taint_record_t)
              );	
	*/

	return reg_index;
	
}// end of HH_Set_TemuRegisterByteTaintRecord( )


// �����ض����� bit ���۵�״̬
int HH_Set_TemuEFAGSTaintRecord( string	  		bit_name,
				 H_taint_record_t *     taint_record
			       )
{
	int reg_bit_index = HH_Query_TemuEFLAGSByName( bit_name );
	if( reg_bit_index == -1 )
	{
		return reg_bit_index;
	}// end of if( )

	*HHui_eflags_bitmap = (*HHui_eflags_bitmap) | (1 << reg_bit_index);


	// ��һ���� bit �����
	memcpy( HHui_eflags_records + reg_bit_index * sizeof(H_taint_record_t), 
	        taint_record,
	        sizeof(H_taint_record_t)
	      );		
	
	return reg_bit_index;
}// end of HH_Set_TemuEFAGSTaintRecord( )



// �����ض��ڴ��ֽڵķ���ֵ
void HH_Set_TemuMemByteTaintRecord( uint32_t  		 address,
				    int			 size,
				    int			 taint_bitmap,
				    H_taint_record_t *   taint_record
				  )
{
	/*
		// �ڴ�
		tpage_entry_t **  HHui_tpage_table;
	  */
	// tpage_entry_t * entry;

	// uint32_t 	offset = address & 63;

	HH_taintcheck_taint_memory( address, 
				    size, 
				    taint_bitmap, 
				    (uint8_t *)taint_record
				  );
	/*
		
	uint32_t		   len 	= 1 ;//( (64 - offset) > size)
	
	
	if( entry = ( (HHui_tpage_table)[address >> 6] )
	  ) 
	{
		memcpy( entry->records + offset * sizeof(H_taint_record_t),
			taint_record,
	           	len * sizeof(H_taint_record_t)
	              );
	}// end of if( )
	*/
	   	
		
}// end of HH_Set_TemuMemByteTaintRecord( )

/* =================================================================================== */
// �����ż���Ľ��������������









