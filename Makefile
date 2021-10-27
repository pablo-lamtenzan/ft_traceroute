NAME		=		ft_traceroute
OBJDIR		=		bin_objs
CC			=		/usr/bin/gcc
RM			=		/bin/rm

include				srcs.mk

CFLAGS		=		-Wall -Wextra -Werror
IFLAGS		=		-I$(INCDIR)

OBJS		=		$(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))

all:				$(NAME)

$(NAME):			$(OBJS)
	@echo LINK $@
	$(CC) $(OBJS) $(CFLAGS) -o $@

$(OBJDIR):
	mkdir -p $@

$(OBJDIR)/%.o:		$(SRCDIR)/%.c $(HDRS) $(OBJDIR)
	@mkdir -p '$(@D)'
	@echo CC $<
	@$(CC) $(CFLAGS) $(IFLAGS) -c -o $@ $<

clean:
	@echo RM $(OBJDIR)
	@$(RM) -rf $(OBJDIR)

fclean:				clean
	@echo RM $(NAME)
	@$(RM) -f $(NAME)

re:					fclean all

.PHONY:				clean fclean

$(VERBOSE).SILENT:
