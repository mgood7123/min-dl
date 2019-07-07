/* Author: mgood7123 (Matthew James Good) http://github.com/mgood7123 */
#pragma once

/*

#if !defined(_INTTYPES_H_)
#define _INTTYPES_H_

#  define __PRI_8_LENGTH_MODIFIER__ "hh"
#  define __PRI_64_LENGTH_MODIFIER__ "ll"
#  define __SCN_64_LENGTH_MODIFIER__ "ll"
#  define __PRI_MAX_LENGTH_MODIFIER__ "j"
#  define __SCN_MAX_LENGTH_MODIFIER__ "j"

#  define PRId8         __PRI_8_LENGTH_MODIFIER__ "d"
#  define PRIi8         __PRI_8_LENGTH_MODIFIER__ "i"
#  define PRIo8         __PRI_8_LENGTH_MODIFIER__ "o"
#  define PRIu8         __PRI_8_LENGTH_MODIFIER__ "u"
#  define PRIx8         __PRI_8_LENGTH_MODIFIER__ "x"
#  define PRIX8         __PRI_8_LENGTH_MODIFIER__ "X"

#  define PRId16        "hd"
#  define PRIi16        "hi"
#  define PRIo16        "ho"
#  define PRIu16        "hu"
#  define PRIx16        "hx"
#  define PRIX16        "hX"

#  define PRId32        "d"
#  define PRIi32        "i"
#  define PRIo32        "o"
#  define PRIu32        "u"
#  define PRIx32        "x"
#  define PRIX32        "X"

#  define PRId64        __PRI_64_LENGTH_MODIFIER__ "d"
#  define PRIi64        __PRI_64_LENGTH_MODIFIER__ "i"
#  define PRIo64        __PRI_64_LENGTH_MODIFIER__ "o"
#  define PRIu64        __PRI_64_LENGTH_MODIFIER__ "u"
#  define PRIx64        __PRI_64_LENGTH_MODIFIER__ "x"
#  define PRIX64        __PRI_64_LENGTH_MODIFIER__ "X"

#  define PRIdLEAST8    PRId8
#  define PRIiLEAST8    PRIi8
#  define PRIoLEAST8    PRIo8
#  define PRIuLEAST8    PRIu8
#  define PRIxLEAST8    PRIx8
#  define PRIXLEAST8    PRIX8

#  define PRIdLEAST16   PRId16
#  define PRIiLEAST16   PRIi16
#  define PRIoLEAST16   PRIo16
#  define PRIuLEAST16   PRIu16
#  define PRIxLEAST16   PRIx16
#  define PRIXLEAST16   PRIX16

#  define PRIdLEAST32   PRId32
#  define PRIiLEAST32   PRIi32
#  define PRIoLEAST32   PRIo32
#  define PRIuLEAST32   PRIu32
#  define PRIxLEAST32   PRIx32
#  define PRIXLEAST32   PRIX32

#  define PRIdLEAST64   PRId64
#  define PRIiLEAST64   PRIi64
#  define PRIoLEAST64   PRIo64
#  define PRIuLEAST64   PRIu64
#  define PRIxLEAST64   PRIx64
#  define PRIXLEAST64   PRIX64

#  define PRIdFAST8     PRId8
#  define PRIiFAST8     PRIi8
#  define PRIoFAST8     PRIo8
#  define PRIuFAST8     PRIu8
#  define PRIxFAST8     PRIx8
#  define PRIXFAST8     PRIX8

#  define PRIdFAST16    PRId16
#  define PRIiFAST16    PRIi16
#  define PRIoFAST16    PRIo16
#  define PRIuFAST16    PRIu16
#  define PRIxFAST16    PRIx16
#  define PRIXFAST16    PRIX16

#  define PRIdFAST32    PRId32
#  define PRIiFAST32    PRIi32
#  define PRIoFAST32    PRIo32
#  define PRIuFAST32    PRIu32
#  define PRIxFAST32    PRIx32
#  define PRIXFAST32    PRIX32

#  define PRIdFAST64    PRId64
#  define PRIiFAST64    PRIi64
#  define PRIoFAST64    PRIo64
#  define PRIuFAST64    PRIu64
#  define PRIxFAST64    PRIx64
#  define PRIXFAST64    PRIX64

// int32_t is 'int', but intptr_t is 'long'.
#  define PRIdPTR       "ld"
#  define PRIiPTR       "li"
#  define PRIoPTR       "lo"
#  define PRIuPTR       "lu"
#  define PRIxPTR       "lx"
#  define PRIXPTR       "lX"

#  define PRIdMAX        __PRI_MAX_LENGTH_MODIFIER__ "d"
#  define PRIiMAX        __PRI_MAX_LENGTH_MODIFIER__ "i"
#  define PRIoMAX        __PRI_MAX_LENGTH_MODIFIER__ "o"
#  define PRIuMAX        __PRI_MAX_LENGTH_MODIFIER__ "u"
#  define PRIxMAX        __PRI_MAX_LENGTH_MODIFIER__ "x"
#  define PRIXMAX        __PRI_MAX_LENGTH_MODIFIER__ "X"

#  define SCNd8         __PRI_8_LENGTH_MODIFIER__ "d"
#  define SCNi8         __PRI_8_LENGTH_MODIFIER__ "i"
#  define SCNo8         __PRI_8_LENGTH_MODIFIER__ "o"
#  define SCNu8         __PRI_8_LENGTH_MODIFIER__ "u"
#  define SCNx8         __PRI_8_LENGTH_MODIFIER__ "x"

#  define SCNd16        "hd"
#  define SCNi16        "hi"
#  define SCNo16        "ho"
#  define SCNu16        "hu"
#  define SCNx16        "hx"

#  define SCNd32        "d"
#  define SCNi32        "i"
#  define SCNo32        "o"
#  define SCNu32        "u"
#  define SCNx32        "x"

#  define SCNd64        __SCN_64_LENGTH_MODIFIER__ "d"
#  define SCNi64        __SCN_64_LENGTH_MODIFIER__ "i"
#  define SCNo64        __SCN_64_LENGTH_MODIFIER__ "o"
#  define SCNu64        __SCN_64_LENGTH_MODIFIER__ "u"
#  define SCNx64        __SCN_64_LENGTH_MODIFIER__ "x"

#  define SCNdLEAST8    SCNd8
#  define SCNiLEAST8    SCNi8
#  define SCNoLEAST8    SCNo8
#  define SCNuLEAST8    SCNu8
#  define SCNxLEAST8    SCNx8

#  define SCNdLEAST16   SCNd16
#  define SCNiLEAST16   SCNi16
#  define SCNoLEAST16   SCNo16
#  define SCNuLEAST16   SCNu16
#  define SCNxLEAST16   SCNx16

#  define SCNdLEAST32   SCNd32
#  define SCNiLEAST32   SCNi32
#  define SCNoLEAST32   SCNo32
#  define SCNuLEAST32   SCNu32
#  define SCNxLEAST32   SCNx32

#  define SCNdLEAST64   SCNd64
#  define SCNiLEAST64   SCNi64
#  define SCNoLEAST64   SCNo64
#  define SCNuLEAST64   SCNu64
#  define SCNxLEAST64   SCNx64

#  define SCNdFAST8     SCNd8
#  define SCNiFAST8     SCNi8
#  define SCNoFAST8     SCNo8
#  define SCNuFAST8     SCNu8
#  define SCNxFAST8     SCNx8

#  define SCNdFAST16    SCNd16
#  define SCNiFAST16    SCNi16
#  define SCNoFAST16    SCNo16
#  define SCNuFAST16    SCNu16
#  define SCNxFAST16    SCNx16

#  define SCNdFAST32    SCNd32
#  define SCNiFAST32    SCNi32
#  define SCNoFAST32    SCNo32
#  define SCNuFAST32    SCNu32
#  define SCNxFAST32    SCNx32

#  define SCNdFAST64    SCNd64
#  define SCNiFAST64    SCNi64
#  define SCNoFAST64    SCNo64
#  define SCNuFAST64    SCNu64
#  define SCNxFAST64    SCNx64

#  define SCNdPTR       "ld"
#  define SCNiPTR       "li"
#  define SCNoPTR       "lo"
#  define SCNuPTR       "lu"
#  define SCNxPTR       "lx"

#  define SCNdMAX       __SCN_MAX_LENGTH_MODIFIER__ "d"
#  define SCNiMAX       __SCN_MAX_LENGTH_MODIFIER__ "i"
#  define SCNoMAX       __SCN_MAX_LENGTH_MODIFIER__ "o"
#  define SCNuMAX       __SCN_MAX_LENGTH_MODIFIER__ "u"
#  define SCNxMAX       __SCN_MAX_LENGTH_MODIFIER__ "x"
*/
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#define PRINTF_END_WITH_NEW_LINE true
#define PRINTF_END_WITHOUT_NEW_LINE false

#define fpi64(PRINTING_FUNCTION, x, end_with_new_line) PRINTING_FUNCTION("%s = %" PRId64 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pi64(x) fpi64(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpui64(PRINTING_FUNCTION, x, end_with_new_line) PRINTING_FUNCTION("%s = %" PRIu64 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pui64(x) fpui64(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpi32(PRINTING_FUNCTION, x, end_with_new_line) PRINTING_FUNCTION("%s = %" PRId32 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pi32(x) fpi32(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpui32(PRINTING_FUNCTION, x, end_with_new_line) PRINTING_FUNCTION("%s = %" PRIu32 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pui32(x) fpui32(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpi16(PRINTING_FUNCTION, x, end_with_new_line) PRINTING_FUNCTION("%s = %" PRId16 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pi16(x) fpi16(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpui16(PRINTING_FUNCTION, x, end_with_new_line) PRINTING_FUNCTION("%s = %" PRIu16 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pui16(x) fpui16(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpi8(PRINTING_FUNCTION, x, end_with_new_line)  PRINTING_FUNCTION("%s = %" PRId8 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pi8(x)  fpi8(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpui8(PRINTING_FUNCTION, x, end_with_new_line)  PRINTING_FUNCTION("%s = %" PRIu8 "%s", #x, x, end_with_new_line==true?"\n":"");
#define pui8(x)  fpui8(printf, x, PRINTF_END_WITH_NEW_LINE)

#define fpb(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %s%s", #x, x==true?"true":"false", end_with_new_line==true?"\n":"");
#define pb(x)      fpb(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpc(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %c%s", #x, x, end_with_new_line==true?"\n":"");
#define pc(x)      fpc(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fps(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %s%s", #x, x, end_with_new_line==true?"\n":"");
#define ps(x)      fps(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpus(PRINTING_FUNCTION, x, end_with_new_line)     fps(PRINTING_FUNCTION, x, end_with_new_line)
#define pus(x)     fpus(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpi(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %d%s", #x, x, end_with_new_line==true?"\n":"");
#define pi(x)      fpi(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpui(PRINTING_FUNCTION, x, end_with_new_line)     PRINTING_FUNCTION("%s = %u%s", #x, (unsigned int) x, end_with_new_line==true?"\n":"");
#define pui(x)     fpui(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpuc(PRINTING_FUNCTION, x, end_with_new_line)     PRINTING_FUNCTION("%s = %u%s", #x, (unsigned char) x, end_with_new_line==true?"\n":"");
#define puc(x)     fpuc(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpu(PRINTING_FUNCTION, x, end_with_new_line)      fpui(PRINTING_FUNCTION, x, end_with_new_line)
#define pu(x)      fpu(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpd(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %f%s", #x, x, end_with_new_line==true?"\n":"");
#define pd(x)      fpd(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpud(PRINTING_FUNCTION, x, end_with_new_line)     fpd(PRINTING_FUNCTION, x, end_with_new_line)
#define pud(x)     fpud(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpl(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %li%s", #x, x, end_with_new_line==true?"\n":"");
#define pl(x)      fpl(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpli(PRINTING_FUNCTION, x, end_with_new_line)     fpl(PRINTING_FUNCTION, x, end_with_new_line)
#define pli(x)     fpli(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpul(PRINTING_FUNCTION, x, end_with_new_line)     PRINTING_FUNCTION("%s = %lu%s", #x, x, end_with_new_line==true?"\n":"");
#define pul(x)     fpul(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpuli(PRINTING_FUNCTION, x, end_with_new_line)    fpul(PRINTING_FUNCTION, x, end_with_new_line)
#define puli(x)    fpuli(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpll(PRINTING_FUNCTION, x, end_with_new_line)     PRINTING_FUNCTION("%s = %lli%s", #x, x, end_with_new_line==true?"\n":"");
#define pll(x)     fpll(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fplli(PRINTING_FUNCTION, x, end_with_new_line)    fpll(PRINTING_FUNCTION, x, end_with_new_line)
#define plli(x)    fplli(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpull(PRINTING_FUNCTION, x, end_with_new_line)    PRINTING_FUNCTION("%s = %llu%s", #x, x, end_with_new_line==true?"\n":"");
#define pull(x)    fpull(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpulli(PRINTING_FUNCTION, x, end_with_new_line)   fpull(PRINTING_FUNCTION, x, end_with_new_line)
#define pulli(x)   fpulli(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpsize_t(PRINTING_FUNCTION, x, end_with_new_line) PRINTING_FUNCTION("%s = %zu%s", #x, x, end_with_new_line==true?"\n":"");
#define psize_t(x) fpsize_t(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpz(PRINTING_FUNCTION, x, end_with_new_line)      fpsize_t(PRINTING_FUNCTION, x, end_with_new_line)
#define pz(x)      fpz(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpp(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %p%s", #x, x, end_with_new_line==true?"\n":"");
#define pp(x)      fpp(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fppx(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %" PRIX64 "%s", #x, x, end_with_new_line==true?"\n":"");
#define ppx(x)      fppx(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpx(PRINTING_FUNCTION, x, end_with_new_line)      PRINTING_FUNCTION("%s = %02x%s", #x, x, end_with_new_line==true?"\n":"");
#define px(x)      fpx(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fp(PRINTING_FUNCTION, x, end_with_new_line)       PRINTING_FUNCTION(#x);
#define p(x)       fp(printf, x, PRINTF_END_WITH_NEW_LINE)
#define fpsi(PRINTING_FUNCTION, x, i, end_with_new_line) { \
	char * array = malloc(i+1); \
    for (int z = 0; z < i; z++) array[z] = x[z]; \
	array[i] = 0; \
	array[i+1] = 0; \
    PRINTING_FUNCTION("%s = %s%s", #x, array, end_with_new_line==true?"\n":""); \
    free(array); \
}
#define psi(x, i) fpsi(printf, x, PRINTF_END_WITH_NEW_LINE)
