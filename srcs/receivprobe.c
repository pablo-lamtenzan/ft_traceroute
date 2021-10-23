
# include <traceroure.h>
# include <errno.h>

error_t receive_probe(uint8_t* const dest, size_t destlen, ssize_t* const recvbytes)
{
    error_t st = SUCCESS;

 	struct msghdr mhdr = (struct msghdr){
        .msg_name = OPT_HAS(OPT_IPV6) ? (void*)(struct sockaddr_in6[]){} : (void*)(struct sockaddr_in[]){},
        .msg_namelen = OPT_HAS(OPT_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in),
        .msg_iov = (struct iovec[]){{
            .iov_base = dest,
            .iov_len = destlen
        }},
        .msg_iovlen = 1,
        .msg_control = (uint8_t[0X200]){},
        .msg_controllen = ARRAYSIZE((uint8_t[0X200]){}),
        .msg_flags = 0
    };

	if ((*recvbytes = recvmsg(gctx.sockfd, &mhdr, 0)) < 0)
	{
		if (errno == EINTR)
			st = CONTINUE;
		else
		{
			st = ERR_SYSCALL;
			PRINT_ERROR(MSG_ERROR_SYSCALL, "recvmsg", errno);
		}
	}

	return st;
}
