#ifndef DEMON_DSTDIO_H
#define DEMON_DSTDIO_H

#include <Demon.h>

#define MemCopy         __builtin_memcpy

static __inline__ VOID
MemSetBytes(
    PVOID Destination,
    BYTE  Value,
    SIZE_T Length
)
{
    __stosb( ( PUCHAR ) Destination, Value, Length );
}

#define MemSet( d, v, l )   MemSetBytes( ( d ), ( BYTE ) ( v ), ( SIZE_T ) ( l ) )
#define MemZero( p, l )     MemSetBytes( ( p ), 0, ( SIZE_T ) ( l ) )
#define NO_INLINE       __attribute__ ((noinline))

INT     StringCompareA( LPCSTR String1, LPCSTR String2 );
INT     StringCompareW( LPWSTR String1, LPWSTR String2 );
INT     StringCompareIW( LPWSTR String1, LPWSTR String2 );
INT     StringNCompareW( LPWSTR String1, LPWSTR String2, INT Length );
INT     StringNCompareIW( LPWSTR String1, LPWSTR String2, INT Length );
PCHAR   StringCopyA( PCHAR String1, PCHAR String2 );
PWCHAR  StringCopyW(PWCHAR String1, PWCHAR String2);
SIZE_T  StringLengthA( LPCSTR String );
SIZE_T  StringLengthW( LPCWSTR String );
PCHAR   StringConcatA(PCHAR String, PCHAR String2);
PWCHAR  StringConcatW(PWCHAR String, PWCHAR String2);
PCHAR   StringTokenA(PCHAR String, CONST PCHAR Delim);
LPWSTR  WcsStr( PWCHAR String, PWCHAR String2 );
LPWSTR  WcsIStr( PWCHAR String, PWCHAR String2 );
BOOL    EndsWithIW( LPWSTR String, LPWSTR Ending );
INT     MemCompare( PVOID s1, PVOID s2, INT len );
UINT64  GetSystemFileTime( );
BYTE    HideChar( BYTE C );

SIZE_T  WCharStringToCharString( PCHAR Destination, PWCHAR Source, SIZE_T MaximumAllowed );
SIZE_T  CharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed );

#endif
