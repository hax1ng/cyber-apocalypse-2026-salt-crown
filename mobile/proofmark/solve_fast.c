#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#endif
static inline uint32_t mix(uint32_t x) {
    x = (x ^ (x >> 16)) * UINT32_C(0x85ebca6b);
    x = (x ^ (x >> 13)) * UINT32_C(0xc2b2ae35);
    return x ^ (x >> 16);
}
static inline uint32_t rol32(uint32_t x, unsigned n) { return (x<<n)|(x>>(32-n)); }
uint32_t reseal(int32_t a,int32_t b,int32_t c,int32_t bite) {
    uint32_t w[4]={(uint32_t)a,(uint32_t)b,(uint32_t)c,(uint32_t)bite};
    const uint8_t *p=(const uint8_t*)w;
    uint32_t x=UINT32_C(0x53437277);
    for(int i=0;i<16;i++) { x ^= p[i]; x=rol32(x,5); x += UINT32_C(0x9e3779b9); x=mix(x); }
    x=mix(x ^ UINT32_C(0xd1b54a33));
    if (a>=0&&a<=24&&b>=0&&b<=24&&c>=0&&c<=24&&bite==a+2*b+3*c) return x;
    return mix(x ^ UINT32_C(0xa5a5a5a5)) ^ UINT32_C(0x0badf00d);
}
const uint8_t ct[28]={0x2a,0x53,0xdb,0x7b,0xa3,0x5d,0x34,0xf5,0x5f,0x59,0x74,0x5e,0x00,0x43,0x88,0x1c,0xa1,0x13,0x6f,0xb7,0xf8,0xd7,0x3f,0x79,0xc1,0xb0,0xaf,0x1a};
void decrypt(uint32_t h,char out[29]) {
    uint32_t x=h;
    for(int i=0;i<1200000;i++) x=mix(x+UINT32_C(0xc2b2ae35));
    x=mix(x^UINT32_C(0x85ebca6b));
    for(int i=0;i<28;i++){x=mix(x+UINT32_C(0xc2b2ae35));out[i]=(char)(ct[i]^(x>>24));}
    out[28]=0;
}
int main(){
 printf("target hallmark: %08x\n",reseal(83,67,55,462));
 #pragma omp parallel for collapse(3)
 for(int a=0;a<=24;a+=6)for(int b=0;b<=20;b+=5)for(int c=0;c<=24;c+=4){
   uint32_t h=reseal(a,b,c,a+2*b+3*c); char out[29]; decrypt(h,out);
   if(!memcmp(out,"HTB{",4)) {
    #pragma omp critical
    printf("state=(%d,%d,%d,%d) hallmark=%08x certificate=%s\n",a,b,c,a+2*b+3*c,h,out);
   }
 }
}
