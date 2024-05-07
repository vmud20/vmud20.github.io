


#include<string.h>












#include<stddef.h>






















#include<errno.h>





#include<unistd.h>















#define ISHOTKEY(event)	((ISKEYBOARD(event) || ISMOUSE(event)) && event!=ESCKEY && !(event>=LEFTCTRLKEY && event<=LEFTSHIFTKEY) && !(event>=UNKNOWNKEY && event<=GRLESSKEY))
#define ISKEYBOARD(event)	(event >=' ' && event <=320)
#define ISKEYMODIFIER(event)	((event >= LEFTCTRLKEY && event <= LEFTSHIFTKEY) || event == OSKEY)
#define ISMOUSE(event)	(event >= LEFTMOUSE && event <= MOUSEROTATE)
#define ISTEXTINPUT(event)	(event >=' ' && event <=255)
#define ISTIMER(event)	(event >= TIMER && event <= TIMERF)
#define ISTWEAK(event)	(event >= EVT_TWEAK_L && event <= EVT_GESTURE)
#define LEFTALTKEY 		213
#define PADASTERKEY 	160
#define PADPLUSKEY 		164

#define BC_GHOST_CURSORS 1000
#define BIG_CURSOR 		1
#define SMALL_CURSOR 	0
#define SYSCURSOR 1


