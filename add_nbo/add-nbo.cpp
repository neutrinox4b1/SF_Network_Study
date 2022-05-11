#include<stdint.h>
#include<stdio.h>


uint32_t htonl(uint32_t n)
{
    return (n<<24) | ((n & 0x0000ff00) << 8) | ((n & 0x00ff0000) >> 8) | (n >> 24);
}


int main(int argc, char* argv[])
{
    FILE* file_a = fopen(argv[1],"rb");
    FILE* file_b = fopen(argv[2],"rb");

    uint32_t a,b;

    fread(&a, 4,1, file_a);
    fread(&b, 4,1, file_b);

    uint32_t r, ra, rb;
    ra = htonl(a);
    rb = htonl(b);
    r = ra+rb;

    printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n",ra, ra, rb, rb, r, r);

    fclose(file_a);
    fclose(file_b);

    return 0;
}