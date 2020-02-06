#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int  main()
{
	int s[40] = {0};
	s[32] = 0;  s[0] = 0x99;  s[1] = 0xB0;  s[2] = 0x87;  s[3] = 0x9E;  s[4] = 0x70;  s[5] = 0xE8;  s[6] = 0x41;  s[7] = 0x44;  s[8] = 5;  s[9] = 4;  s[10] = 0x8B;  s[11] = 0x9A;  s[12] = 0x74;  s[13] = 0xBC;  s[14] = 0x55;  s[15] = 0x58;  s[16] = 0xB5;  s[17] = 0x61;  s[18] = 0x8E;  s[19] = 0x36;  s[20] = 0xAC;  s[21] = 9;  s[22] = 0x59;  s[23] = 0xE5;  s[24] = 0x61;  s[25] = 0xDD;  s[26] = 0x3E;  s[27] = 0x3F;  s[28] = 0xB9;  s[29] = 0x15;  s[30] = 0xED;  s[31] = 0xD5;
	
	int i = 0, j = 0;
	for(i = 0; i <= 3; i++)
	{
		for(j = 32; j > 0; j--)
		{
			int x = 0;
			while(1)
			{
				int v3 = (s[j-1] | x) & 0xff;
				if ( ((v3 & ~(x & s[j-1])) & 0xff) == s[j])
				{
					s[j] = x;
					break;
				}
				x += 1;
			}
		}
	}
	for(i = 0; i < 33; i++)
	{
		int x = 0;
		while(1)
		{
			if( ((((x >> 6) | (4 * x)) ^ i) & 0xFF) == s[i] )
			{
				printf("%c", x);
				break;
			}
			x += 1;
		}
	}
}
