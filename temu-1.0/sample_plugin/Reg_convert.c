#include "H_cpu.h"
#include "../shared/hooks/reg_ids.h"


/*

// 8-bit registers
#define al_reg 116
#define cl_reg 117
#define dl_reg 118
#define bl_reg 119
#define ah_reg 120
#define ch_reg 121
#define dh_reg 122
#define bh_reg 123

// 16-bit registers
#define ax_reg 124
#define cx_reg 125
#define dx_reg 126
#define bx_reg 127
#define sp_reg 128
#define bp_reg 129
#define si_reg 130
#define di_reg 131

// 32-bit registers
#define eax_reg 132
#define ecx_reg 133
#define edx_reg 134
#define ebx_reg 135
#define esp_reg 136
#define ebp_reg 137
#define esi_reg 138
#define edi_reg 139

 */


uint32_t Reg_Convertor_Tbl[8][4] = { 
				       {al_reg, ah_reg, ax_reg, eax_reg},
				       {cl_reg, ch_reg, cx_reg, ecx_reg},
				       {dl_reg, dh_reg, dx_reg, edx_reg},
				       {bl_reg, bh_reg, bx_reg, ebx_reg},

				       {0     , 0,	 sp_reg, esp_reg},
				       {0     , 0,	 bp_reg, ebp_reg},
				       {0     , 0,	 si_reg, esi_reg},
				       {0     , 0,	 di_reg, edi_reg},
			           };



uint32_t Convert_taint_reg_to_TEMU_reg( int reg, 
					int width
				      )
{
    /*
    term_printf( "reg index = %d --- size = %d\n",
		 reg,
		 width
	       );
     */
    int index   = (reg / 4);
    int offset  = (reg % 4);

    if( (index >= 8) || (width >= 5)
      )
    {
	return (1 << 32) - 1;
    }// end of if( )


    if(width == 2)    
    {
	offset = 2;
    }
    else if(width == 4)
    {
	offset = 3;
    }// end of if( )


    return Reg_Convertor_Tbl[index][offset];

}// end of Convert_taint_reg_to_TEMU_reg(int index)



char * GetRegNameFromId( int reg_id )
{
    return reg_name_from_id(reg_id);
}// end of GetRegNameFromId( int reg_id )
