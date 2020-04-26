#ifndef H_REG_CONVERT_H
	#define H_REG_CONVERT_H
	
	uint32_t Convert_taint_reg_to_TEMU_reg( int reg, 
						int width
					      );

	char * GetRegNameFromId(int reg_id);

#endif
