#include <ctype.h>
#include <inttypes.h>

#include "H_taint_record.h"



// HHui's STP declaration !
// #include "hc_interface.h"
#include "H_STP_stub.h"


#include <string>

#include "stmt.h"
#include "i386_reg_init.h"

#include "H_vulscan_config.h"

using namespace std;



#include "H_cpu.h"


extern void (*H_term_printf)( const char * fstr, ... );


// TEMU 的当前的污点状态和符号机器状态
/* =================================================================================== */

// 寄存器
uint8_t       *    HHui_regs_records;
uint64_t      *    HHui_regs_bitmap;

// EFLAGS
uint8_t	      *    HHui_eflags_records;
uint32_t      *    HHui_eflags_bitmap;


// 内存
tpage_entry_t **   HHui_tpage_table;

/* =================================================================================== */
// TEMU   的当前的污点状态和符号机器状态





//  TEMU  当前的具体机器的状态
/* =================================================================================== */

// TEMU_cpu_eflags
uint32_t *   HHui_TEMU_EFLAGS; 	

uint32_t *   HHui_TEMU_EIP;

// array of CPU general-purpose registers, such as R_EAX, R_EBX
uint32_t *   HHui_TEMU_CPU_REGS;


/* =================================================================================== */
//  TEMU  当前的具体机器的状态





// 用于访问TEMU   具体机器的索引
int TEMU_CPU_ACCESS_INDICES[ ] = 
{
	eax_reg, ecx_reg, edx_reg, ebx_reg, esp_reg, ebp_reg, esi_reg, edi_reg,
	ax_reg,	cx_reg,   dx_reg,  bx_reg,   sp_reg,   bp_reg,  si_reg,   di_reg,
	al_reg,    cl_reg,    dl_reg,   bl_reg,    ah_reg,   ch_reg,  dh_reg,  bh_reg	
};


// 得到访问TEMU    寄存器的ID
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
	"R_OF",
	NULL
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









// 具体值
/* =================================================================================== */
// 读取内存的具体值
int (* HH_TEMU_read_mem)(uint32_t vaddr, int len, void *buf);

void (* HH_TEMU_write_mem)(uint32_t vaddr, int len, void *buf);


// 读取寄存器的具体值
void (* HH_TEMU_read_register)( int    reg_idx, 
		     	        int    reg_offset, 
		      	        int    reg_size,
		     	        void * buf
		   	      );

 void (* HH_TEMU_write_register)( int    reg_id, 
				  int 	 reg_offset,
				  int	 reg_size,
				  void * buf
				);

//void (* HH_TEMU_read_register)(int reg_id, void *buf);

/* =================================================================================== */





// 污点检验与污点记录数据获取
/* =================================================================================== */

// 检验内存的污点状态，并提取相关的污点信息记录，返回相关的污点视图
uint64_t (* HH_taintcheck_memory_check)(uint32_t addr, int size,  uint8_t * records);


// 检验对应的寄存器污点状态，并提取相关的污点信息记录，返回相关的污点视图
uint64_t (* HH_taintcheck_register_check)(int reg, int offset, int size, uint8_t * records);



// 检验内存的污点状态，并提取相关的污点信息记录，返回相关的污点视图
uint64_t (* HH_taintcheck_taint_memory)(uint32_t addr, int size, uint64_t taint, uint8_t * records);


// Set 寄存器污点状态，并提取相关的污点信息记录，返回相关的污点视图
uint64_t (* HH_taintcheck_taint_register)(int reg, int offset, int size, uint64_t taint, uint8_t * records);

/* =================================================================================== */




// For SYM-ADDR's resolve !
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
uint32_t * HH_vad_root = 0;
int ( *HH_build_symaddr_invalid_constraint)( HVC        hvc,
				             HExpr      symaddr_expr,
	  	            	             int        access_mode,      /* 1 -- read; 2 -- write; 4 -- execute */
				             uint32_t * vad_root,
				             HExpr *    out_of_range_expr,
				             HExpr *    invalid_access_expr
			      	           );

void (*HH_symaddr_obtain_stack_range_constraint)( HVC     hvc,
						  HExpr   symaddr,
						  HExpr * out_of_range_constraint
						);

void (*HH_symaddr_stack_eip_overwritten_constraint)( HVC     hvc,
						     HExpr   symaddr,
						     HExpr * out_of_range_constraint
						   );
/* ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
// For SYM-ADDR's resolve !


void (*H_error_testcase_generate_4_expr)( HExpr    path_expr,
					  uint32_t category_id,
					  int      local_id
					);

int * H_vulscan_once_enough_err_found = NULL;
/*
  // abstract reading of the symbolic machine states
  taintcheck_check_virtmem, 
  taintcheck_register_check,

  // abstract writing of the symbolic machine states
  taintcheck_taint_virtmem, 
  taintcheck_taint_register	
 */
// 提供给 Temu 的插件调用的接口，得到 Temu 信息读取的原子函数
void Set_HH_TEMU_concrete_read( uint32_t * con_regs,
				uint8_t    con_reg_bitmap,
				
				void *	   con_mem_list,

				int (* f_read_mem)(uint32_t vaddr, int len, void *buf),
		      		void (* f_read_register)(int reg_id, int reg_offset, int reg_size, void *buf),

				void (* f_write_mem)(uint32_t vaddr, int len, void *buf), 
				void (* f_write_register)(int reg_id, int reg_offset, int reg_size, void *buf),

				uint64_t (* f_taintcheck_memory_check)(uint32_t addr, int size,  uint8_t * records),
				uint64_t (* f_taintcheck_register_check)(int reg, int offset, int size, uint8_t * records),

				uint64_t (* f_taintcheck_taint_memory)(uint32_t addr, int size, uint64_t taint, uint8_t * records),
				uint64_t (* f_taintcheck_taint_register)(int reg, int offset, int size, uint64_t taint, uint8_t * records),
				uint32_t * my_HH_vad_root,
				int ( *my_HH_build_symaddr_invalid_constraint)( HVC        hvc,
				       						HExpr      symaddr_expr,
					  	            	                int        access_mode,      
									        /* 1 - read; 2 - write; 4 - execute */
								                uint32_t * vad_root,
				       					        HExpr *    out_of_range_expr,
				 					        HExpr *    invalid_access_expr
			      	           				      ),

				void (*my_symaddr_obtain_stack_range_constraint)( HVC     hvc,
									          HExpr   symaddr,
									          HExpr * out_of_range_constraint
									        ),
				
				void (*my_symaddr_stack_eip_overwritten_constraint)( HVC     hvc,
									             HExpr   symaddr,
									             HExpr * out_of_range_constraint
									           ),

				void (*my_H_error_testcase_generate_4_expr)( HExpr    path_expr,
								             uint32_t category_id,
									     int      local_id
							       	           ),

				// switches for several vulnerability scanning policies.
				/* ============================================================ */
				int * my_H_vulscan_once_enough_err_found
				/* ============================================================ */
			      )
{
	// switches for several vulnerability scanning policies.
	/* ==================================================================== */
    #ifdef H_VULSCAN_ONCE_ENOUGH
	H_vulscan_once_enough_err_found = my_H_vulscan_once_enough_err_found;
    #endif
	/* ==================================================================== */
	
	HH_TEMU_read_mem 	      = f_read_mem;
	HH_TEMU_read_register         = f_read_register;


	HH_TEMU_write_mem 	      = f_write_mem;
	HH_TEMU_write_register        = f_write_register;


	HH_taintcheck_memory_check    = f_taintcheck_memory_check;

	/*
	H_term_printf( "HH_taintcheck_memory_check is 0x%8x\n",
		       HH_taintcheck_memory_check
		     );
	*/

	HH_taintcheck_register_check  = f_taintcheck_register_check;

	HH_taintcheck_taint_memory    =	f_taintcheck_taint_memory;
	HH_taintcheck_taint_register  = f_taintcheck_taint_register;			


	// For SYM-ADDR-CONSTRAINTS' building and resolvation !
        /* ------------------------------------------------------------------------ */
	HH_vad_root = my_HH_vad_root;
	HH_build_symaddr_invalid_constraint = my_HH_build_symaddr_invalid_constraint;

	HH_symaddr_obtain_stack_range_constraint    = my_symaddr_obtain_stack_range_constraint;
	HH_symaddr_stack_eip_overwritten_constraint = my_symaddr_stack_eip_overwritten_constraint;
        /* ------------------------------------------------------------------------ */

	// H_term_printf		      = f_term_printf;

	H_error_testcase_generate_4_expr = my_H_error_testcase_generate_4_expr;
}// end of Set_HH_TEMU_read_mem( )





/* 封装给外部插件提供的完全接口，
    便于本部件获取Temu  相关的 信息外部的完全信息
  */
void Get_HH_TEMU_Info( 
		       uint32_t *  	 TEMU_EFLAGS,    // TEMU_cpu_eflags
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
	/* ----------------------------------------------------------- */
	HHui_eflags_records = eflags_records;
	HHui_eflags_bitmap  = eflags_bitmap;
	/* ----------------------------------------------------------- */
	

}// end of Get_HH_TEMU_total_information( )




void EFLAGS_clean_record(uint32_t index)
{
    H_taint_record_t * record = NULL;

    // only clean-up when tainted.
    if( *HHui_eflags_bitmap & (1 << index) )       
    {
	record = (H_taint_record_t *)( (uint32_t)HHui_eflags_records + sizeof(H_taint_record_t) * index 
				     );
	vc_DeleteExpr(record->h_expr);
    }// end of if(*HH_eflags_bitmap)    
}// end of EFLAGS_clean_record( )

	

// 具体值相关
/* =================================================================================== */
// 读取TEMU   机器执行中的内存具体值
int  GetConcreteMemData( uint32_t  address, 
			 int 	   len, 
			 void *	   buf
		       )
{
	// First look-up those 
	/* --------------------------------------------------------------------------- */
	/* --------------------------------------------------------------------------- */

	/*
	return HH_TEMU_read_mem( address,
			   	 len,
				 buf
			       );
	*/
	HH_TEMU_read_mem( address,
			  len,
			  buf
			);	
		
}// end of GetConcreteMemData( ) 


void SetConcreteMemData( uint32_t  address, 
			 int 	   len, 
			 void *	   buf
		       )
{
	/*
	HH_TEMU_write_mem( address,
			   len,
			   buf
			 );
	*/
	// H_term_printf("HH_taintcheck_taint_memory is called !\n");

	// [ CLEAN ] 
	HH_taintcheck_taint_memory( address,
				    len, 
				    0, 
				    NULL
				  );

}// end of SetConcreteMemData( )




void SetConcreteRegData( int    reg_idx,  // the sequence of pushing into reg-stacks
			 void *	buf
		       )
{
	
    // int reg_access_id = GetTEMUReg_AccessIDByIndex( reg_idx );
    
    /*
    VarDecl * decl = i386_gen_regs.at(reg_idx);

    int       idx  = decl->reg_idx;
    int	      off  = decl->reg_offset;
    int	      size = decl->reg_size;
    */

    int idx  = (reg_idx / 4);
    int off  = (reg_idx % 4);
    int size = 4 - off;

    HH_TEMU_write_register( idx,
			    off,
			    size,
			    buf
			  );

    /*
    H_term_printf( "SetConcreteRegData( ) ---- taint-register --- index=%d, offset=%d, size=%d\n",
		   idx,
		   off,
		   size
	         );
    */

    // [ CLEAN ]
    // write concrete to register, considering the corresponding updates to related taint-bitmap 
    HH_taintcheck_taint_register( idx,  // reg_index,
				  off,  // reg_offset,
				  size, // fixed size for specific register
				  0,    // taint_bitmap,
				  NULL  // (uint8_t *)taint_record
				);

}// end of SetConcreteRegData( )




// 读取TEMU   机器执行中的寄存器具体值
uint32_t GetConcreteRegData(int regidx)
{
    VarDecl * decl = i386_gen_regs.at(regidx);
    
    /*
    H_term_printf( "GetConcreteRegData( ) decl = 0x%8x\n!\n",
		   (uint32_t)decl
		 );
     */

    int       idx  = decl->reg_idx;
    int	      off  = decl->reg_offset;
    int	      size = decl->reg_size;

    uint32_t  data = 0 ;


/*        
    H_term_printf( "GetConcreteRegData( ) decl->reg_idx = 0x%8x, decl->reg_offset = 0x%8x, decl->reg_size = 0x%8x \n!\n",
		   decl->reg_idx,
		   decl->reg_offset,
		   decl->reg_size
		 );
 */


    /*
    H_term_printf( "HH_TEMU_read_register( )'s function address is 0x%8x\n",
		   HH_TEMU_read_register
		 );
     */
    HH_TEMU_read_register( idx, 
		     	   off, 
		      	   size,
		     	   &data
		   	 );
    
/*
    H_term_printf( "data read is 0x%x\n",
		   data
		 );
 */

    return data;

}// end of GetConcreteRegData( )




void SetConcreteEFLAGData( int bit_index,
			   int bit_value
			 )
{
    uint32_t mask  = ~(1 << bit_index) ;
    uint32_t value = bit_value << bit_index;
	
    // clean-up neccessarily those overwritten expr, which won't be referenced.
    // EFLAGS_clean_record(bit_index);

    *HHui_TEMU_EFLAGS = *HHui_TEMU_EFLAGS & mask ;

    *HHui_TEMU_EFLAGS = *HHui_TEMU_EFLAGS | value ;


    /* [ CLEAN ] --- Now update the corresponding EFLAG bit's taint-status ! */
    /* directly influence upon the underlying taint-record structure ! */
    /* ------------------------------------------------------------------------------------------ */
    /*
    HHui_eflags_records = eflags_records;
    HHui_eflags_bitmap  = eflags_bitmap;    
    */

    // clean-up the bitmap !
    *HHui_eflags_bitmap = *HHui_eflags_bitmap & mask ;

    H_term_printf( "tc_EFLAG in IR ---- 0x%x\n",
		   *HHui_eflags_bitmap
		 );
    /* ------------------------------------------------------------------------------------------ */


}// end of SetConcreteEFLAGData( )



// 读取TEMU   机器执行中的EFLAGS   的bit   的具体值
uint32_t GetConcreteEFLAGData( string bitname )
{
	const char * c_bitname	   = bitname.c_str( ) ;

	int 	     reg_bit_index = -1 ;
	uint32_t     reg_bit_mask  = 0 ;

	
	//  EFLAGS  的各个标记位
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
	
	
	return ( ( (*HHui_TEMU_EFLAGS) & reg_bit_mask 
		 ) >> (reg_bit_index) 
	       ) ;
	
	//  EFLAGS  的各个标记位		
}// end of GetConcreteEFLAGData( )

/* =================================================================================== */
// 具体值相关









//  封装的符号机器状态查询函数
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


	// 32-bit   通用寄存器
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
	// 32-bit   通用寄存器




	// 16-bit   通用寄存器
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
	// 16-bit   通用寄存器



	// 8-bit   通用寄存器
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




/*  通用寄存器的符号函数

     h_reg_records  要求是已经分配好的缓冲区
     
     返回值:

     0  	  ----  未被污染

     其它----  对应的污染视图
  */
uint64_t HH_Query_TemuRegisterTaintStatus( string	       reg_name,
					   H_taint_record_t *  h_reg_records
					 )
{
	int reg_size   = 0 ;
	int reg_offset = 0 ;
	int reg_index  = -1;
	
	uint64_t tbmap = 0;

	// look-up the register in the i386-general-registers' stack !
	VarDecl * var_decl = Obtain_i386_regvar_byname(reg_name);
	
	/*
	H_term_printf( "H_Query_TemuRegisterTaintStatus( ) --- reg_name = %s, sizeof(H_taint_record_t) is %d\n",
		       reg_name.c_str( ),
		       sizeof(H_taint_record_t)
		     );
	 */

	if(var_decl != NULL)
	{
	    reg_index  = var_decl->reg_idx;
	    reg_offset = var_decl->reg_offset;
	    reg_size   = var_decl->reg_size;
	    
	    	    

	    tbmap = HH_taintcheck_register_check( reg_index, 
				    	    	  reg_offset,
					   	  reg_size,
					     	  (uint8_t *)h_reg_records
						  //h_reg_records
					   	);		        
	   
	    /*
    	    H_term_printf( "regidx = %d, regoffset = %d, regsize = %d, taint_bitmap = 0x%x\n",
			   reg_index,  //var_decl->reg_idx,
	    		   reg_offset, //var_decl->reg_offset,
			   reg_size,   //var_decl->reg_size,
			   tbmap
			 );
  	     */
	     

	   /*
		    
	   tbmap = HH_taintcheck_register_check( 1, 
				    	    	 0,
					   	 4,
					     	 // (uint8_t *)h_reg_records
						 records
					       );
	    H_term_printf( "R_ECX tc_bitmap is 0x%x\n",
			   tbmap
			 );

	    
       	    H_term_printf( "HH_taintcheck_register_check is 0x%8x\n",
			    HH_taintcheck_register_check
		     	 );
	    */

	    return tbmap;

	}// end of if( )
	/*
	if( ( reg_index = HH_Query_TemuRegisterIndexByName( reg_name, 
							    &reg_size, 
							    &reg_offset
						          ) 
	    ) == -1
	  )		
	{
	    return -1;
	}// end of if( )
	*/
	

	return 0;
	
}// end of HH_Query_TemuRegisterTaintStatus( )





int HH_Query_TemuEFLAGSByName( string  eflag_name )
{
	const char * c_regname     = eflag_name.c_str( ) ;

	int 	     reg_bit_index = -1;
	

	//  EFLAGS  的各个标记位
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
	//  EFLAGS  的各个标记位	

	return reg_bit_index;
	
}// end of HH_Query_TemuEFLAGSByName( )



//  EFLAGS 寄存器---- 目前只关心单个的Flag-Bit !
/* 
     返回值:

     0   ----  未被污染
     -1  ----  未找到对应的符号
     其它 ----  对应的污染视图
     
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
		*eflag_bit_expr_record = *( (H_taint_record_t * )( (uint32_t)HHui_eflags_records + 
					  	 		   reg_bit_index * sizeof(H_taint_record_t) 
				   	      		     	 )
					  );
	}// end of if( )
	
	return e_taintbitmap;

	
}// end of  HH_Query_TemuEFLAGSTaintStatus( string reg_name, int bit_length)


//  内存的符号状态相关
/*

     返回值:

     0   ----  未被污染
     其它 ----  对应的污染视图
     
  */
uint64_t HH_Query_TemuMemTaintStatus( uint32_t  	 m_address,
				      int		 m_length,
				      H_taint_record_t * h_taint_recoird
				    )
{
	uint64_t mem_taint_status = -1;

	/* 检验内存的污点状态，并提取相关的污点信息记录，
	    返回相关的污点视图
	  */

	
	mem_taint_status = HH_taintcheck_memory_check( m_address, 
						       m_length,  
						       (uint8_t *)h_taint_recoird
						     );
/*
	H_term_printf( "HH_taintcheck_memory_check( ) is at address 0x%x, m_address = 0x%x, m_length = %d, tcbmap = 0x%x -",
		       HH_taintcheck_memory_check,
		       m_address,
		       m_length,
		       mem_taint_status
		     );
*/

	return mem_taint_status;
}// end of HH_Query_TemuMemTaintStatus( uint32_t  m_address, int	 m_length)

/* =================================================================================== */
//  封装的机器状态查询函数







// 将符号计算的结果反馈到机器中
/* =================================================================================== */

void HH_symexe_taint_register( int reg_index,
			       int size,
			       H_taint_record_t *  taint_record
			     )
{
    /*
    H_term_printf( "SYM-EXE :  taint reg -------- index = %d, offset =% d, size =% d, records are :\n  ",
		   (reg_index / 4),
		   (reg_index % 4),
		   size
	         );

    for(int i=0; i<size; i=i+1)
    {
	H_term_printf( "[i] = %s , \n",
		       exprString(  ( (H_taint_record_t *)( (uint32_t)taint_record + sizeof(H_taint_record_t) * i
						          ) 
				    )->h_expr
			         )
		     );
	 
    }// end of for{ }

    */

    HH_taintcheck_taint_register( (reg_index / 4),
				  (reg_index % 4),
			          size, // fixed size for specific register
			          ( (1<<size) - 1 ),
			          (uint8_t *)taint_record
			        );    

}// end of HH_symexe_taint_register( )



int HH_Set_TemuRegisterByteTaintRecord( string	  	    reg_name,	
					int		    taint_bitmap,
					H_taint_record_t *  taint_record
				      )
{
	int reg_size    = 0;	
	int reg_index   = -1;
	int reg_offset  = 0;

	VarDecl * reg_decl = Obtain_i386_regvar_byname(reg_name);

/*
  int  reg_idx;
  int  reg_offset;
  int  reg_size;
*/
	if(reg_decl != NULL)
        {
	    reg_index  = reg_decl->reg_idx;
	    reg_offset = reg_decl->reg_offset;
	    reg_size   = reg_decl->reg_size;


	    HH_taintcheck_taint_register( reg_index,
					  reg_offset,
				          reg_size, // fixed size for specific register
				          taint_bitmap,
				          (uint8_t *)taint_record
				        );
	    return 1;

        }// end of if( )





		
	// 单一字节的情况
	/*
	memcpy( HHui_regs_records + (reg_index * 4 + reg_offset) * sizeof(H_taint_record_t), 
	        taint_record,
	        sizeof(H_taint_record_t)
              );	
	*/

	return 0 ;
	// return reg_index;
	
}// end of HH_Set_TemuRegisterByteTaintRecord( )


// 设置特定符号 bit 的污点状态
/*
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


	// 单一符号 bit 的情况
	memcpy( HHui_eflags_records + reg_bit_index * sizeof(H_taint_record_t), 
	        taint_record,
	        sizeof(H_taint_record_t)
	      );		
	
	return reg_bit_index;
}// end of HH_Set_TemuEFAGSTaintRecord( )
*/

int HH_Set_TemuEFAGSTaintRecord( int 		    index,  // Now input the real index !
				 H_taint_record_t * taint_record
			       )
{
    // clean-up those overwritten expr, which won't be referenced.
    // EFLAGS_clean_record(index);

    *HHui_eflags_bitmap = (*HHui_eflags_bitmap) | (1 << index);

    H_term_printf( "tainting EFLAG bit 0x%x, *HHui_eflags_bitmap = 0x%x",
		   index,
		   *HHui_eflags_bitmap
		 );
    

    memcpy( ((uint8_t *)HHui_eflags_records) + ( index * sizeof(H_taint_record_t) ), 
	    (uint8_t *)taint_record,
	    sizeof(H_taint_record_t)
	  );


}// end of HH_Set_TemuEFAGSTaintRecord( )




// 设置特定内存字节的符号值
void HH_Set_TemuMemByteTaintRecord( uint32_t  		 address,
				    uint32_t		 size,
				    uint64_t		 taint_bitmap,
				    H_taint_record_t *   taint_record
				  )
{
	/*
		// 内存
		tpage_entry_t **  HHui_tpage_table;
	  */
	// tpage_entry_t * entry;

	// uint32_t 	offset = address & 63;

/*
	H_term_printf( "taint_record is at addr 0x%x\n",
		       taint_record
		     );


	H_term_printf( " HHui caller ---- HHui_encap_taintcheck_taint_virtmem(( ) is at address 0x%x, h_records=0x%x \n",
		       HH_taintcheck_taint_memory,
		       taint_record
	             );
*/

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



HExpr obtain_expr_from_TEMU_virtmem( uint32_t vaddr,
				     int      size,
				     HVC      hvc
				   )
{
    uint32_t mask    = 0;
    uint32_t value   = 0; 
    uint32_t tmp_val = 0;

    HExpr rst_expr = NULL;
    HExpr tmp_expr = NULL;
    H_taint_record_t * records = (H_taint_record_t *)malloc(sizeof(H_taint_record_t) * size);

    uint64_t tc_bmap = HH_Query_TemuMemTaintStatus( vaddr,
						    (uint32_t)size,
				      		    records
				    		  );
    GetConcreteMemData( vaddr,
			size,
			&value
		      );

    // if( !( (uint32_t)tc_bmap != 0) )
    if( (tc_bmap & tc_bmap) == (uint64_t)0 )
    {	
	rst_expr = vc_bvConstExprFromInt( hvc,
					  (size*8),
					  value
					);
/*
        H_term_printf( "pure concrete value [0x%x] = 0x%x\n",
		       vaddr,
		       value
		     );
 */
	return rst_expr;
    }// end of if( )

    for(int i=0; i<size; i=i+1)
    {	
	if( ( tc_bmap & (1 << i) 
	    ) == 0 
	  )
        {
	    mask     = (1 << (1+i)) - (1 << i);
	    tmp_val  = ( mask & value ) >> i;
	    tmp_expr = vc_bvConstExprFromInt( hvc,
					      8,
					      (uint8_t)tmp_val
					    );
	}
	else
	{
	    tmp_expr = ( (H_taint_record_t *)records + i)->h_expr;
	}// end of if( )
	
	if(i == 0)
	{
	    rst_expr = tmp_expr;
	}
	else
	{
	    rst_expr = vc_bvConcatExpr( hvc,
					tmp_expr, // left
					rst_expr  // right
				      );
	}// end of if(i)
    }// end of for{i}

    return rst_expr;
}// end of obtain_expr_from_TEMU_virtmem( )


void (*temu_dbg_dump_expr)( HExpr  expr,
			    char * filename,
			    char * tc_filename,
			    int    category
			  );

void (*H_predicate_change)( HVC   hvc,
		       	    HExpr pred_expr,
			    HExpr prev_total_expr,
			    HExpr total_expr
		     	  );

// provide to 'IR_SymExe.so' the dbg-utils for diagnoses during runtime.
void get_temu_dbgutil( void (*my_dbg_dump_expr)( HExpr  expr,
						 char * filename,
						 char * tc_filename,
						 int    category
					       ),

		       void (*my_predicate_change)( HVC   hvc,
					      	    HExpr pred_expr,
				       	      	    HExpr prev_total_expr,
				       	      	    HExpr total_expr
		     	    			  )
		     )
{
    temu_dbg_dump_expr = my_dbg_dump_expr;

    H_predicate_change = my_predicate_change;
}// end of get_temu_dbgutil( )


/* =================================================================================== */
// 将符号计算的结果反馈到机器中









