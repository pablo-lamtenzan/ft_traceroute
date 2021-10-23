# include <sys/types.h>

void* ft_memset(void* s, int c, size_t n)
{
    char* dest = (char*)s;

    for (size_t i = 0 ; i < n ; i++)
        dest[i] = c;

    return dest;
}
