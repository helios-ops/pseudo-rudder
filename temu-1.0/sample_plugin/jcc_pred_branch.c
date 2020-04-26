#include <stdlib.h>
#include <inttypes.h>
#include "../TEMU_main.h"


static int HHui_eflag_bit_indices[7] = { 0,  // CF
				         2,  // PF
					 4,  // AF
					 6,  // ZF
					 7,  // SF
					 10, // DF
					 11  // OF
				       };


#define HH_CF_INDEX 0
#define HH_PF_INDEX 1
#define HH_AF_INDEX 2
#define HH_ZF_INDEX 3
#define HH_SF_INDEX 4
#define HH_DF_INDEX 5
#define HH_OF_INDEX 6


// analyze the instruction eliminating the 1st byte !
void concrete_jcc_branch_analyze_0xF( uint8_t  * insn_bytes,
				      uint32_t   insn_addr,
				      int	 insn_len,
			              int      * predicate,
				      uint32_t * tbranch,
				      uint16_t * pred_bits 
				    )
{
    uint32_t eflags  = *TEMU_cpu_eflags;
    uint32_t rel_off = 0;

    *predicate = -1;

    /* ------------------------------------------------------------------------------------------- */
    switch(insn_bytes[0])
    {
	case (uint8_t)0x80: // JO rel16 or JO rel32 --- OF=1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] )
			 ) >> HHui_eflag_bit_indices[HH_OF_INDEX];
	 
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
	case (uint8_t)0x81: // JNO rel16 or JNO rel32 --- OF=0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_OF_INDEX];

	    *predicate = 1 - *predicate;
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
	case (uint8_t)0x82: // JB rel16 or JB rel32 --- CF=1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] )
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    break;
	}
	case (uint8_t)0x83: // JAE rel16 or JAE rel32 --- CF=0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *predicate = 1 - *predicate;
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    break;
	}
	case (uint8_t)0x84: // JE rel16 or JE rel32 --- ZF=1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] )			
			 ) >> HHui_eflag_bit_indices[HH_ZF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );

	    break;
	}
	case (uint8_t)0x85: // JNZ rel16 or JNZ rel32 -- ZF=0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_ZF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );

	    if(*predicate == 0)
	    {
	        *predicate = 1 ;
	    }
	    else
	    {
		*predicate = 0;
  	    }// end of if( )

	    break;
	}
	case (uint8_t)0x86: // JBE rel16 or JBE rel32 --- CF=1 or ZF=1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *predicate = *predicate || ( (  eflags &  ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] 
						      ) 
					 )>>HHui_eflag_bit_indices[HH_ZF_INDEX]
				       );

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    
	    break;
	}
	case (uint8_t)0x87: // JNBE rel16 or JNBE rel32 --- CF=0 and ZF=0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *predicate = *predicate || ( (  eflags &  ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] 
						      ) 
					 )>>HHui_eflag_bit_indices[HH_ZF_INDEX]
				       );
	    // *predicate = !*predicate ;
	    if(*predicate == 0)
	    {
		*predicate = 1;
	    }
	    else
	    {
		*predicate = 0;
	    }// end of if(*predicate)

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    
	    break;
	}
	case (uint8_t)0x88: // JS rel16 or JS rel32 --- SF=1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] )
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    break;
	}
	case (uint8_t)0x89: // JNS rel16 or JNS rel32 --- SF=0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX])
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];
	    *predicate = 1 - *predicate;

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );	    
	    break;
	}
	case (uint8_t)0x8A: // JP rel16 or JP rel32 --- PF=1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_PF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX] );	    
	    break;
	}
	case (uint8_t)0x8B: // JNP rel16 or JNP rel32 --- PF=0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX])
			 ) >> HHui_eflag_bit_indices[HH_PF_INDEX];
	    *predicate = 1 - *predicate;

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX] );

	    break;
	}
	case (uint8_t)0x8C: // JNGE rel16 or JNGE rel32 --- SF≠ OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    *predicate = ( *predicate != ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
			 		   ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
				         )
			 );
	    if(*predicate != 0)
	    {
		*predicate = 1;
	    }// end of if(*predicate)

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
	case (uint8_t)0x8D: // JNL rel16 or JNL rel32 --- SF = OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    *predicate = ( *predicate == ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
			 		   ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
				         )
			 );
	    if(*predicate != 0)
	    {
		*predicate = 1;
	    }// end of if(*predicate)

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
	case (uint8_t)0x8E: // JNG rel32 or JNG rel16 --- ZF=1 or SF≠ OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_ZF_INDEX];

	    *predicate = (*predicate == 1);

	    *predicate = ( ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			     ) >> HHui_eflag_bit_indices[HH_SF_INDEX]
			   ) != 
			   ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
			     ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
			   )
			 ) || *predicate;

	    if(*predicate != 0)
	    {
		*predicate = 1;
	    }// end of if(*predicate)

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
	case (uint8_t)0x8F: // JNLE rel16 or JNLE rel32 --- ZF=0 and SF=OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];
	    
	    *predicate = ( *predicate == ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
					   ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
				         )
			 );

	    *predicate = *predicate && ( ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX]) 
					   ) >> HHui_eflag_bit_indices[HH_ZF_INDEX]
				         ) == 0
				       );
	    if(*predicate != 0)
	    {
		*predicate = 1;
	    }// end of if(*predicate)
	    /* 
	    *predicate = *predicate && ( ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] ) 
					   ) >> HHui_eflag_bit_indices[HH_ZF_INDEX]
				         ) == 
					 ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] ) 
					   ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
				         )
			 );
	     */
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
    }// end of switch{insn_bytes[0]}
    /* ------------------------------------------------------------------------------------------- */


    // calculate the relative-offset of the true-branch destination
    /* ------------------------------------------------------------------------------------------- */
    // eliminate the OPcode
    switch(insn_len - 1)
    {
	case 2:
	{
            rel_off  = *( (int16_t *)(insn_bytes + 1) );
	    *tbranch = (uint32_t)( (signed long)insn_addr + (signed long)(insn_len + 1) + (int16_t)rel_off );
	    break;
	}
	case 4:
	{
	    rel_off  = *( (int32_t *)(insn_bytes + 1) );
	    *tbranch = (uint32_t)( (signed long)insn_addr + (signed long)(insn_len + 1) + (int32_t)rel_off );
	    break;
	}
    }// end of switch{insn_len}

    // *tbranch = (uint32_t)( (signed long)insn_addr + (signed long)insn_len + (signed long)rel_off );    
    /* ------------------------------------------------------------------------------------------- */
    // calculate the relative-offset of the true-branch destination

}// end of concrete_jcc_branch_analyze_0xF( )


void concrete_jcc_branch_analyze( uint8_t  * insn_bytes,
				  uint32_t   insn_addr,
				  int	     insn_len,
			          int	   * predicate,
				  uint32_t * tbranch,
				  uint16_t * pred_bits 
		  	        )
{
    uint32_t eflags  = *TEMU_cpu_eflags;
    uint32_t rel_off = 0;

    *predicate = -1;

    if(insn_bytes[0] == 0xF3) 	    // REP
    {
	*predicate = eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	if(*predicate != 0 )
	{
	    *predicate = 1;
	}// end of if( )

	*tbranch = insn_addr;
	*pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );

	return;
    }
    else if(insn_bytes[0] == 0xF2)  // REPNE
    {
	*predicate = eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	if(*predicate == 0 )
	{
	    *predicate = 1;
	}
// HHui patched at March 7th, 2012
/* -------------------------------------------------- */
        else
        {
	    *predicate = 0;
	}// end of if(*predicate)
/* -------------------------------------------------- */

	*tbranch = insn_addr;
	*pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );

	return;
    }// end of if( )

    /* --------------------------------------------------------------------------------------------------------------------------- */
    if(insn_bytes[0] == 0x0F)
    {
	// eliminate the 1st byte !
	return concrete_jcc_branch_analyze_0xF( (insn_bytes + 1),
				     		insn_addr,
				      		(insn_len - 1),
					        predicate,
					        tbranch,
					        pred_bits 
					      );
    }// end of if(insn_bytes[0])

    /* --------------------------------------------------------------------------------------------------------------------------- */


    switch(insn_bytes[0])
    {
	case 0x70: // JO --- OF = 1
        {
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] )
			 ) >> HHui_eflag_bit_indices[HH_OF_INDEX];
	    // rel_off = (uint32_t)(insn_bytes[1]);
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
	case 0x71: // JNO --- OF = 0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_OF_INDEX];

	    *predicate = 1 - *predicate;
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );
	    // rel_off = (uint32_t)(insn_bytes[1]);
	    break;
	}
	case 0x72: // JB --- CF = 1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] )
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    // rel_off = (uint32_t)(insn_bytes[1]);
	    break;
	}
	case 0x73: // JAE --- CF = 0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *predicate = 1 - *predicate;
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    // rel_off = (uint32_t)(insn_bytes[1]);
	    break;
	}
	case 0x74: // JZ --- ZF = 1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] )
			 ) >> HHui_eflag_bit_indices[HH_ZF_INDEX];
	    // rel_off = (uint32_t)(insn_bytes[1]);
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    break;
	}
	case 0x75: // JNZ --- ZF = 0
        {
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] ) 
			 ); //  >> HHui_eflag_bit_indices[HH_ZF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );

	    // *predicate = !*predicate;
	    if(*predicate == 0)
	    {
	        *predicate = 1 ;
	    }
	    else
	    {
		*predicate = 0;
  	    }// end of if( )

/*
	    term_printf( "ZF = 0x%x\n", 
		       );
 */
	    // rel_off = (uint32_t)(insn_bytes[1]);
	    break;
	}
	case 0x76: // JBE --- CF = 1 or ZF = 1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *predicate = *predicate || ( (  eflags &  ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] 
						      ) 
					 )>>HHui_eflag_bit_indices[HH_ZF_INDEX]
				       );

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    
	    break;
	}
	case 0x77: // JA --- CF = 0 and ZF = 0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] ) 
			 ) >> HHui_eflag_bit_indices[HH_CF_INDEX];

	    *predicate = *predicate || ( (  eflags &  ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] 
						      ) 
					 )>>HHui_eflag_bit_indices[HH_ZF_INDEX]
				       );

	    *predicate = !*predicate ;


	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_CF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    break;
	}
	case 0x78: // JS --- SF = 1
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] )
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    break;
	}
	case 0x79: // JNS --- SF = 0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX])
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    // *predicate = !*predicate;
	    if(*predicate == 0)
	    {
		*predicate = 1;
	    }
	    else
	    {
		*predicate = 0;
	    }// end of if(*predicate)

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    break;
	}
	case 0x7A: // JP --- PF =1
        {
	    *predicate = eflags & ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX]);

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX] );
	    break;
	}
	case 0x7B: // JPO --- PF = 0
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX])
			 ) >> HHui_eflag_bit_indices[HH_PF_INDEX];

	    // *predicate = !*predicate;
	    if(*predicate == 0)
	    {
		*predicate = 1;
	    }
	    else
	    {
		*predicate = 0;
	    }// end of if(*predicate)

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_PF_INDEX] );
	    break;
	}
	case 0x7C: // JNGE --- SF != OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    *predicate = ( *predicate != ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
			 		   ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
				         )
			 );

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );
	    break;
	}
	case 0x7D: // JNL --- SF = OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    *predicate = ( *predicate == ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
			 		   ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
				         )
			 );

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );
	    break;
	}
	case 0x7E: // JNG --- ZF = 1 or SF != OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_ZF_INDEX];

	    *predicate = (*predicate == 1);

	    *predicate = ( ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			     ) >> HHui_eflag_bit_indices[HH_SF_INDEX]
			   ) != 
			   ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
			     ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
			   )
			 ) || *predicate;


	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
	case 0x7F: // JNLE --- ZF = 0 and SF = OF
	{
	    *predicate = ( eflags & ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX]) 
			 ) >> HHui_eflag_bit_indices[HH_SF_INDEX];

	    *predicate = *predicate == ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX]) 
					 ) >> HHui_eflag_bit_indices[HH_OF_INDEX]
				       );

	    *predicate = *predicate && ( ( ( eflags & ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX]) 
					   ) >> HHui_eflag_bit_indices[HH_ZF_INDEX]
				         ) == 0
				       );

	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_ZF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_SF_INDEX] );
	    *pred_bits = *pred_bits | ( 1 << HHui_eflag_bit_indices[HH_OF_INDEX] );

	    break;
	}
    }// end of switch( )


RETURNING_POINT:

    // rel_off = (uint32_t)(insn_bytes[1]);
    if( (insn_bytes[0] >= 0x70) &&
	(insn_bytes[0] <= 0x7F)
      )
    {
	
	/*
	rel_off  = (uint32_t)(insn_bytes[1]);
	if(rel_off >= 0x80)
	{
	    *tbranch = (uint32_t)( insn_addr + insn_len + 0xFFFFFF00 + rel_off ) ;
	}
	else
	{
	    *tbranch = (uint32_t)( insn_addr + insn_len + rel_off ) ;
	}// end of if( )
	*/
	switch(insn_len - 1)
	{
	    case 1:
	    {
		rel_off  = (int8_t)(insn_bytes[1]);
		break;
	    }
	    case 2:
	    {
		rel_off  = (int32_t)( *( (int16_t *)(insn_bytes + 1)
				        )
				     );
		break;
	    }
	}// end of switch(insn_len - 1)

	*tbranch = (uint32_t)( (signed long)insn_addr + (signed long)insn_len + (int32_t)rel_off );
    }// end of if( (insn_bytes[0]...)
            

}// end of concrete_jcc_branch_analyze( )
