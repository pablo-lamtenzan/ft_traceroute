

# include <traceroure.h>
# include <ftlibc.h>

# include <sys/socket.h>
# include <errno.h>

error_t gethostinfo_i32_4(void* inaddr_ptr,  uint8_t* const destdns, uint8_t* const destip)
{ return gethostinfo_str4(inet_ntoa(*(struct in_addr*)inaddr_ptr), destdns, destip); }

/**
 * 	@brief set in the global context information
 * 	about the given @p hostname.
 * 	* The dns (if has) is stored on .dest_dns array
 * 	* The ip is stored on .dest_ip array
*/
error_t gethostinfo_str4(const char* hostname, uint8_t* const destdns, uint8_t* const destip)
{
    error_t st = SUCCESS;

    struct addrinfo* res = NULL;

    ///TODO: For the moment i gonna just handle ICMP protocol
    struct addrinfo hints = {
        .ai_flags = AI_CANONNAME,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_RAW,
        .ai_protocol = IPPROTO_ICMP
    };

    if (getaddrinfo(hostname, 0, &hints, &res) != 0)
    {
        PRINT_ERROR(MSG_ERROR_UNKNOWN_HOSTNAME, hostname);
        st = ERR_DESTADDR;
        goto error;
    }

    ft_memcpy(destdns, res->ai_canonname, ft_strlen(res->ai_canonname));

		if (res->ai_family != AF_INET)
    {
        PRINT_ERROR(__progname ": %s\n", "not IPV4");
        st = ERR_SOCKFAM;
        goto error;
    }

	const struct in_addr* const sin_addr = &((struct sockaddr_in*)res->ai_addr)->sin_addr; 

	*(struct sockaddr_in*)&gctx.dest_sockaddr = (struct sockaddr_in){
        .sin_addr.s_addr = sin_addr->s_addr,
        .sin_family = AF_INET,
    };

	if (inet_ntop(res->ai_family, (const void*)sin_addr,
    destip, ARR_SIZE(gctx.dest_ip)) == 0)
    {
        st = ERR_SYSCALL;
        PRINT_ERROR(MSG_ERROR_SYSCALL, "inet_ntop", errno);
    }

error:
    freeaddrinfo(res);
    return st;
}

error_t gethostinfo_i32_6(void* in6addr_ptr, uint8_t* const destdns, uint8_t* const destip)
{
    (void)in6addr_ptr;
    (void)destdns;
    (void)destip;
}
// set dns & id in global struct for a given hostname
error_t gethostinfo_str6(const char* hostname, uint8_t* const destdns, uint8_t* const destip)
{
    (void)hostname;
    (void)destdns;
    (void)destip;
}