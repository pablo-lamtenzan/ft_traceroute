long						ft_atol(const char *str)
{
	int					i;
	unsigned long	    nb;
	int					sing;
	char				*s;

	sing = 1;
	nb = 0;
	i = 0;
	s = (char *)str;
	if (s[i] == '-' || s[i] == '+')
	{
		if (s[i] == '-')
			sing = -sing;
		i++;
	}
	while (s[i] >= '0' && s[i] <= '9')
		nb = nb * 10 + s[i++] - '0';
	if ((sing > 0 && nb <= 9223372036854775807L) ||
			(sing < 0 && nb <= 9223372036854775808UL))
		return (sing * (long)nb);
	return (sing < 0 ? 0 : -1);
}
