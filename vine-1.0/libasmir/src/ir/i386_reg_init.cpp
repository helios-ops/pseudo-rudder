#include "stmt.h"
#include <vector>


vector<VarDecl *>  i386_gen_regs;


vector<VarDecl *>  i386_EFLAGS_bits;
uint32_t	   i386_EFLAGS;



// this forms the general registers' stack and EFLAGS bits' stack for i386
void i386_reg_init( )
{
    reg_t r32 = REG_32;
    reg_t r16 = REG_16;
    reg_t r8  = REG_8;
    reg_t r1  = REG_1;

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

    /*
		( string  myname, 
		  int     myvar_type,    // 0 --- general reg; 1 --- EFLAG bit; 2 --- temp variable
		  reg_t   mytype,
	  	  int	  myreg_idx,
	   	  int 	  myreg_offset,
		  int	  myreg_size
	 	)
     */

    // for EFLAGS, the 6th parametre indicating the reg_size would be nonsense, as they are generally 1-bit long !
    // Status bit flags

    /* --------------------------------------------------------------------------- */    						          
    i386_EFLAGS_bits.push_back( new VarDecl( "R_CF", 
					     1, 
					     r1, 
					     0,  // the 4th parametre is the bit's index in real i386 EFLAGS !
					     0, 
					     0
					   )
			      );
    i386_EFLAGS_bits.push_back(new VarDecl("R_PF", 1, r1, 2, 0, 0));  
    i386_EFLAGS_bits.push_back(new VarDecl("R_AF", 1, r1, 4, 0, 0));  
    i386_EFLAGS_bits.push_back(new VarDecl("R_ZF", 1, r1, 6, 0, 0));  
    i386_EFLAGS_bits.push_back(new VarDecl("R_SF", 1, r1, 7, 0, 0));  
    i386_EFLAGS_bits.push_back(new VarDecl("R_OF", 1, r1, 11, 0, 0));  
    /* --------------------------------------------------------------------------- */



    // General purpose 32-bit registers
    /* EAX, ECX, EDX, EBX, ESP, SBP, ESI, EDI */
    /* --------------------------------------------------------------------------- */
    i386_gen_regs.push_back(new VarDecl("R_EAX", 0, r32, 0, 0, 4));  
    i386_gen_regs.push_back(new VarDecl("R_ECX", 0, r32, 1, 0, 4));  
    i386_gen_regs.push_back(new VarDecl("R_EDX", 0, r32, 2, 0, 4));  
    i386_gen_regs.push_back(new VarDecl("R_EBX", 0, r32, 3, 0, 4));  
    i386_gen_regs.push_back(new VarDecl("R_ESP", 0, r32, 4, 0, 4));  
    i386_gen_regs.push_back(new VarDecl("R_EBP", 0, r32, 5, 0, 4));  
    i386_gen_regs.push_back(new VarDecl("R_ESI", 0, r32, 6, 0, 4));  
    i386_gen_regs.push_back(new VarDecl("R_EDI", 0, r32, 7, 0, 4));  
    /* --------------------------------------------------------------------------- */


    // 16-bit registers (bits 0-15)
    /* --------------------------------------------------------------------------- */
    i386_gen_regs.push_back(new VarDecl("R_AX", 0, r16, 0, 0, 2));  
    i386_gen_regs.push_back(new VarDecl("R_CX", 0, r16, 1, 0, 2));  
    i386_gen_regs.push_back(new VarDecl("R_DX", 0, r16, 2, 0, 2));  
    i386_gen_regs.push_back(new VarDecl("R_BX", 0, r16, 3, 0, 2));  
    i386_gen_regs.push_back(new VarDecl("R_SP", 0, r16, 4, 0, 2));
    i386_gen_regs.push_back(new VarDecl("R_BP", 0, r16, 5, 0, 2));  
    i386_gen_regs.push_back(new VarDecl("R_SI", 0, r16, 6, 0, 2));  
    i386_gen_regs.push_back(new VarDecl("R_DI", 0, r16, 7, 0, 2));  
    /* --------------------------------------------------------------------------- */


    // 8-bit registers (bits 0-7)
    /* --------------------------------------------------------------------------- */
    i386_gen_regs.push_back(new VarDecl("R_AL", 0, r8, 0, 0, 1));  
    i386_gen_regs.push_back(new VarDecl("R_CL", 0, r8, 1, 0, 1));  
    i386_gen_regs.push_back(new VarDecl("R_DL", 0, r8, 2, 0, 1)); 
    i386_gen_regs.push_back(new VarDecl("R_BL", 0, r8, 3, 0, 1));   
    /* --------------------------------------------------------------------------- */


    // 8-bit registers (bits 8-15)
    /* --------------------------------------------------------------------------- */
    i386_gen_regs.push_back(new VarDecl("R_AH", 0, r8, 0, 1, 1));  
    i386_gen_regs.push_back(new VarDecl("R_CH", 0, r8, 1, 1, 1));  
    i386_gen_regs.push_back(new VarDecl("R_DH", 0, r8, 2, 1, 1));  
    i386_gen_regs.push_back(new VarDecl("R_BH", 0, r8, 3, 1, 1));  
    /* --------------------------------------------------------------------------- */

}// end of i386_reg_init( )




VarDecl * Obtain_i386_regvar_byname(string name)
{
    VarDecl * decl = NULL;

    int size = i386_gen_regs.size( );
    int i    = 0;

    /*
    H_term_printf( " Obtain_i386_regvar_byname( ) : reg name is %s",
		   name.c_str( )
		 );
     */
    for(i=0; i<size; i=i+1)
    {
	decl = i386_gen_regs.at(i);

	if(strcmp( name.c_str( ), (decl->name).c_str( )
		 ) == 0
          )
	{
	    break;
	}// end of if( )

    }// end of for{ }

    if(i >= size)
    {
	return NULL;
    }// end of if( )
           
    return decl;

}// end of Obtain_i386_regvar_byname( )



VarDecl * Obtain_i386_EFLAGS_bit_var_byname(string name)
{
    VarDecl * decl = NULL;

    int size = i386_EFLAGS_bits.size( );
    int i    = 0;

    /*
    H_term_printf( " Obtain_i386_EFLAGS_bit_var_byname( ) : reg name is %s",
		   name.c_str( )
		 );
     */

    for(i=0; i<size; i=i+1)
    {
	decl = i386_EFLAGS_bits.at(i);

	if(strcmp( name.c_str( ), (decl->name).c_str( )
		 ) == 0
          )
	{
	    break;
	}// end of if( )

    }// end of for{ }

    if(i >= size)
    {
	return NULL;
    }// end of if( )
           
    return decl;

}// end of Obtain_i386_EFLAGS_bit_var_byname( )












