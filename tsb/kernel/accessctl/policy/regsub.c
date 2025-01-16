/*
 * regsub
 * @(#)regsub.c	1.3 of 2 April 86
 *
 *	Copyright (c) 1986 by University of Toronto.
 *	Written by Henry Spencer.  Not derived from licensed software.
 *
 *	Permission is granted to anyone to use this software for any
 *	purpose on any computer system, and to redistribute it freely,
 *	subject to the following restrictions:
 *
 *	1. The author is not responsible for the consequences of use of
 *		this software, no matter how awful, even if they arise
 *		from defects in it.
 *
 *	2. The origin of this software must not be misrepresented, either
 *		by explicit claim or by omission.
 *
 *	3. Altered versions must be plainly marked as such, and must not
 *		be misrepresented as being the original software.
 *
 *
 * This code was modified by Ethan Sommer to work within the kernel
 * (it now uses kmalloc etc..)
 *
 */  
#include "regexp.h"
#include "regmagic.h"
#include <linux/string.h>
     
#ifndef CHARBITS
#define	UCHARAT(p)	((int)*(unsigned char *)(p))
#else	/*  */
#define	UCHARAT(p)	((int)*(p)&CHARBITS)
#endif	
    

    
/*
 - regsub - perform substitutions after a regexp match
 */ 
