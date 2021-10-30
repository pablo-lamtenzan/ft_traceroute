
# include <traceroute.h>
# include <errno.h>
# include <stdbool.h>

# define PRINT_TIMEOUT(symbol) (printf(" %c ", symbol))

error_type receive_probe(uint8_t* const dest, size_t destlen, ssize_t* const recvbytes)
{
    error_type	st = SUCCESS;

    fd_set fdr;
    FD_ZERO(&fdr);
    FD_SET(gctx.sockfd, &fdr);

    struct timeval waittime = (struct timeval){
        .tv_sec = 1,
        .tv_usec = 666667
    };

    for ( ; ; )
    {
        if (select(gctx.sockfd + 1, &fdr, 0, 0, &waittime) < 0)
        {
            PRINT_ERROR(MSG_ERROR_SYSCALL, "select", errno);
            st = ERR_SYSCALL;
            goto error;
        }

        if (FD_ISSET(gctx.sockfd, &fdr))
        {
            if ((*recvbytes = recvfrom(gctx.sockfd, dest, destlen, 0, (struct sockaddr_in*)&gctx.recv_sockaddr, (socklen_t[]){sizeof(struct sockaddr_in)})) < 0)
            {
                if (errno == EINTR)
                    continue ;
                else
                {
                    st = ERR_SYSCALL;
                    PRINT_ERROR(MSG_ERROR_SYSCALL, "recvfrom", errno);
                    
                }
            }

			if (gettimeofday(&gctx.recvtime, NULL) != 0)
			{
				PRINT_ERROR(MSG_ERROR_SYSCALL, "gettimeofday", errno);
				st = ERR_SYSCALL;
				goto error;
			}
			goto error;
        }
        else
        {
            gctx.probescount++;
            gctx.is_timeout = true;
            goto error;
        }
    }

error:
    FD_CLR(gctx.sockfd, &fdr);
	return st;
}
