#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>

#define DEFAULT_SRAND_VAL 8675728858075378228ull

struct nf_confuse_param {
	__u64  srand;
};

enum {
	O_SRAND = 0,
};

static void CONFUSE_help(void)
{
	printf(
"CONFUSE target options:\n"
" --srand u64		set srand number for confuse algorithm\n");
}

static const struct xt_option_entry CONFUSE_opts[] = {
	{.name = "srand", .id = O_SRAND, .type = XTTYPE_UINT64},
	XTOPT_TABLEEND,
};

static void CONFUSE_init(struct xt_entry_target *t)
{
	struct nf_confuse_param *param = (struct nf_confuse_param *)t->data;
	param->srand = DEFAULT_SRAND_VAL;
}

static void CONFUSE_parse(struct xt_option_call *cb)
{
	struct nf_confuse_param *param = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_SRAND:
		param->srand = cb->val.u64;
		break;
	}
}

static void
CONFUSE_print(const void *ip, const struct xt_entry_target *target,
				int numeric)
{
	const struct nf_confuse_param *param = (const void *)target->data;

	printf(" confuse");
	if (param->srand != DEFAULT_SRAND_VAL) {
		printf(" srand:%llu", param->srand);
	}
}

static void
CONFUSE_save(const void *ip, const struct xt_entry_target *target)
{
	const struct nf_confuse_param *param = (const void *)target->data;
	
	if (param->srand != DEFAULT_SRAND_VAL) {
		printf("--srand %llu", param->srand);
	}
}

static int CONFUSE_xlate(struct xt_xlate *xl,
				const struct xt_xlate_tg_params *params)
{
	const struct nf_confuse_param *param =
		(const void *)params->target->data;

	xt_xlate_add(xl, "confuse");

	if (param->srand != DEFAULT_SRAND_VAL) {
		xt_xlate_add(xl, " srand:%llu", param->srand);
	}

	return 1;
}

static struct xtables_target confuse_tg_reg = {
	.name		= "CONFUSE",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV4,
	.size		= XT_ALIGN(sizeof(struct nf_confuse_param)),
	.userspacesize	= XT_ALIGN(sizeof(struct nf_confuse_param)),
	.help		= CONFUSE_help,
	.init		= CONFUSE_init,
	.x6_parse	= CONFUSE_parse,
	.print		= CONFUSE_print,
	.save		= CONFUSE_save,
	.x6_options	= CONFUSE_opts,
	.xlate		= CONFUSE_xlate,
};

void _init(void)
{
	xtables_register_target(&confuse_tg_reg);
}
