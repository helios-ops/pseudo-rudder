#include <inttypes.h>
#include <string.h>
#include "../TEMU_main.h"

// de-facto no good function, ought to be deleted !
int h_atoint(char * str)
{
    int data = 0;
    for(int i = 0; str[i] != '\0'; i = i + 1)
    {
	if(str[i] > 0x39)
	{
	    if(str[i] >= 0x61)
	    {
		data = data * 10 + str[i] - 0x61;
	    }
	    else
	    {
		data = data * 10 + str[i] - 0x41;
	    }// end of if(str[i])
	}
	else
	{
	    data = data * 10 + str[i] - 0x30;
	}// end of if(str[i])
    }// end of for{i}

    // term_printf("%s --- %d ; ",str, data);

    return data;
}// end of h_atoint( )


uint32_t h_atohex(char * str)
{
    uint32_t data = 0;
    for(int i = 0; str[i] != '\0'; i = i + 1)
    {
	if((unsigned int)str[i] > 0x39)
	{
	    if((unsigned int)str[i] >= 0x61)
	    {
		// a-z
		data = data * 16 + (str[i] - 0x61) + 10;
	    }
	    else
	    {
		// A-Z
		data = data * 16 + (str[i] - 0x41) + 10;
	    }// end of if(str[i])
	}
	else
	{
	    // 0-9
	    data = data * 16 + str[i] - 0x30;
	}// end of if(str[i])
	
    }// end of for{i}

    return data;
}// end of h_atohex( )
