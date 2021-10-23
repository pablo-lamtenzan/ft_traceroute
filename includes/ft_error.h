
# pragma once

# include <gcc_dependent.h>
# include <stdio.h>

typedef enum	fterror
{
	SUCCESS,
	ERR_OPT,
	ERR_SYSCALL,
	ERR_DESTADDR,
	ERR_SOCKFAM,
	ERR_USERPRIV,
	CONTINUE
}				error_t;

# define PRINT_ERROR(format, args...) dprintf(2, format, args)

# define MSG_ERROR_SYSCALL __progname ": syscall %s failed for some reason (code: %d)" "\n"
# define MSG_ERROR_PACKETLEN_SZ __progname ": too big packetlen %lu specified" "\n"
# define MSG_ERROR_UNKNOWN_HOSTNAME __progname ": %s: Name or service not known" "\n"
