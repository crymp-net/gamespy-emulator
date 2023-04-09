#pragma once
#ifndef __enctypex__
#define __enctypex__
/*
GS enctypeX servers list decoder/encoder 0.1.3b
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

This is the algorithm used by ANY new and old game which contacts the Gamespy master server.
It has been written for being used in gslist so there are no explanations or comments here,
if you want to understand something take a look to gslist.c

    Copyright 2008-2012 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include "../iobuf.h"


typedef struct {
    unsigned char   encxkey[261];   // static key
    int             offset;         // everything decrypted till now (total)
    int             start;          // where starts the buffer (so how much big is the header), this is the only one you need to zero
} enctypex_data_t;

static int enctypex_func5(unsigned char *encxkey, int cnt, unsigned char *id, int idlen, int *n1, int *n2) {
    int     i,
            tmp,
            mask = 1;

    if(!cnt) return(0);
    if(cnt > 1) {
        do {
            mask = (mask << 1) + 1;
        } while(mask < cnt);
    }

    i = 0;
    do {
        *n1 = encxkey[*n1 & 0xff] + id[*n2];
        (*n2)++;
        if(*n2 >= idlen) {
            *n2 = 0;
            *n1 += idlen;
        }
        tmp = *n1 & mask;
        if(++i > 11) tmp %= cnt;
    } while(tmp > cnt);

    return(tmp);
}

void enctypex_func4(unsigned char *encxkey, unsigned char *id, int idlen) {
    int             i,
                    n1 = 0,
                    n2 = 0;
    unsigned char   t1,
                    t2;

    if(idlen < 1) return;

    for(i = 0; i < 256; i++) encxkey[i] = i;

    for(i = 255; i >= 0; i--) {
        t1 = enctypex_func5(encxkey, i, id, idlen, &n1, &n2);
        t2 = encxkey[i];
        encxkey[i] = encxkey[t1];
        encxkey[t1] = t2;
    }

    encxkey[256] = encxkey[1];
    encxkey[257] = encxkey[3];
    encxkey[258] = encxkey[5];
    encxkey[259] = encxkey[7];
    encxkey[260] = encxkey[n1 & 0xff];
}

static int enctypex_func7e(unsigned char *encxkey, unsigned char d) {
    unsigned char   a,
                    b,
                    c;

    a = encxkey[256];
    b = encxkey[257];
    c = encxkey[a];
    encxkey[256] = a + 1;
    encxkey[257] = b + c;
    a = encxkey[260];
    b = encxkey[257];
    b = encxkey[b];
    c = encxkey[a];
    encxkey[a] = b;
    a = encxkey[259];
    b = encxkey[257];
    a = encxkey[a];
    encxkey[b] = a;
    a = encxkey[256];
    b = encxkey[259];
    a = encxkey[a];
    encxkey[b] = a;
    a = encxkey[256];
    encxkey[a] = c;
    b = encxkey[258];
    a = encxkey[c];
    c = encxkey[259];
    b += a;
    encxkey[258] = b;
    a = b;
    c = encxkey[c];
    b = encxkey[257];
    b = encxkey[b];
    a = encxkey[a];
    c += b;
    b = encxkey[260];
    b = encxkey[b];
    c += b;
    b = encxkey[c];
    c = encxkey[256];
    c = encxkey[c];
    a += c;
    c = encxkey[b];
    b = encxkey[a];
    c ^= b ^ d;
    encxkey[260] = c;   // encrypt
    encxkey[259] = d;   // encrypt
    return(c);
}

static int enctypex_func6e(unsigned char *encxkey, IOBuf& data) {
    size_t     i;

    for(i = 0; i < data.capacity(); i++) {
        data[i] = enctypex_func7e(encxkey, data[i]);
    }
    return (int)data.capacity();
}

static void enctypex_funcx(unsigned char *encxkey, unsigned char *key, unsigned char *encxvalidate, IOBuf& data) {
    int     i,
            keylen;

    keylen = strlen((char*)key);
    for(i = 0; i < (int)data.capacity(); i++) {
        encxvalidate[(key[i % keylen] * i) & 7] ^= encxvalidate[i & 7] ^ data[i];
    }
    enctypex_func4(encxkey, encxvalidate, 8);
}

#endif