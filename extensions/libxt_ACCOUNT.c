/* Shared library add-on to iptables to add ACCOUNT(ing) support.
   Author: Intra2net AG <opensource@intra2net.com>
*/

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <getopt.h>
#include <stddef.h>
#include <xtables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include "xt_ACCOUNT.h"

static struct option opts[] = {
    { .name = "addr",        .has_arg = 1, .flag = 0, .val = 'a' },
    { .name = "tname",       .has_arg = 1, .flag = 0, .val = 't' },
    { .name = 0 }
};

/* Compat glue for iptables 1.4.0 */
#ifndef XTABLES_VERSION
#define XTABLES_VERSION IPTABLES_VERSION
#endif

/* Function which prints out usage message. */
static void help(void)
{
    printf(
"ACCOUNT v%s options:\n"
" --%s ip/netmask\t\tBase network IP and netmask used for this table\n"
" --%s name\t\t\tTable name for the userspace library\n",
XTABLES_VERSION, opts[0].name, opts[1].name);
}

/* Initialize the target. */
static void
init(struct xt_entry_target *t)
{
    struct ipt_acc_info *accountinfo = (struct ipt_acc_info *)t->data;

    accountinfo->table_nr = -1;
}

#define IPT_ACCOUNT_OPT_ADDR 0x01
#define IPT_ACCOUNT_OPT_TABLE 0x02

/* Function which parses command options; returns true if it
   ate an option */

static int parse(int c, char **argv, int invert, unsigned int *flags,
                     const void *entry, struct xt_entry_target **target)
{
    struct ipt_acc_info *accountinfo = (struct ipt_acc_info *)(*target)->data;
    struct in_addr *addrs = NULL, mask;
    unsigned int naddrs = 0;

    switch (c) {
    case 'a':
        if (*flags & IPT_ACCOUNT_OPT_ADDR)
                xtables_error(PARAMETER_PROBLEM, "Can't specify --%s twice",
                            opts[0].name);

        if (xtables_check_inverse(optarg, &invert, NULL, 0))
                xtables_error(PARAMETER_PROBLEM, "Unexpected `!' after --%s",
                            opts[0].name);

#ifdef XTABLES_VERSION_CODE
        xtables_ipparse_any(optarg, &addrs, &mask, &naddrs);
#else
        parse_hostnetworkmask(optarg, &addrs, &mask, &naddrs);
#endif

        if (naddrs > 1)
                xtables_error(PARAMETER_PROBLEM, "multiple IP addresses not allowed");

        accountinfo->net_ip = addrs[0].s_addr;
        accountinfo->net_mask = mask.s_addr;

        *flags |= IPT_ACCOUNT_OPT_ADDR;
        break;

    case 't':
            if (*flags & IPT_ACCOUNT_OPT_TABLE)
                    xtables_error(PARAMETER_PROBLEM,
                                "Can't specify --%s twice", opts[1].name);

            if (xtables_check_inverse(optarg, &invert, NULL, 0))
                    xtables_error(PARAMETER_PROBLEM,
                                "Unexpected `!' after --%s", opts[1].name);

            if (strlen(optarg) > ACCOUNT_TABLE_NAME_LEN - 1)
                    xtables_error(PARAMETER_PROBLEM,
                                "Maximum table name length %u for --%s",
                                ACCOUNT_TABLE_NAME_LEN - 1, opts[1].name);

            strcpy(accountinfo->table_name, optarg);
            *flags |= IPT_ACCOUNT_OPT_TABLE;
            break;

    default:
            return 0;
    }
    return 1;
}

/* Final check; nothing. */
static void final_check(unsigned int flags)
{
    if (!(flags&IPT_ACCOUNT_OPT_ADDR) || !(flags&IPT_ACCOUNT_OPT_TABLE))
        xtables_error(PARAMETER_PROBLEM, "ACCOUNT: needs --%s and --%s",
                    opts[0].name, opts[1].name);
}

static const char *print_helper_ip(struct in_addr a)
{
#ifdef XTABLES_VERSION_CODE
    return xtables_ipaddr_to_numeric(&a);
#else
    return addr_to_dotted(&a);
#endif
}

static const char *print_helper_mask(struct in_addr a)
{
#ifdef XTABLES_VERSION_CODE
    return xtables_ipmask_to_numeric(&a);
#else
    return mask_to_dotted(&a);
#endif
}

static void print_it(const void *ip,
                     const struct xt_entry_target *target, char do_prefix)
{
    const struct ipt_acc_info *accountinfo
        = (const struct ipt_acc_info *)target->data;
    struct in_addr a;

    if (!do_prefix)
        printf("ACCOUNT ");

    // Network information
    if (do_prefix)
        printf("--");
    printf("%s ", opts[0].name);

    a.s_addr = accountinfo->net_ip;
    printf("%s", print_helper_ip(a));
    a.s_addr = accountinfo->net_mask;
    printf("%s", print_helper_mask(a));

    printf(" ");
    if (do_prefix)
        printf("--");

    printf("%s %s", opts[1].name, accountinfo->table_name);
}


static void
print(const void *ip,
      const struct xt_entry_target *target,
      int numeric)
{
    print_it (ip, target, 0);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void
save(const void *ip, const struct xt_entry_target *target)
{
    print_it(ip, target, 1);
}

static
struct xtables_target account
= {
    .next          = NULL,
    .name          = "ACCOUNT",
    .family        = AF_INET,
    .version       = XTABLES_VERSION,
    .size          = XT_ALIGN(sizeof(struct ipt_acc_info)),
    .userspacesize = offsetof(struct ipt_acc_info, table_nr),
    .help          = &help,
    .init          = &init,
    .parse         = &parse,
    .final_check   = &final_check,
    .print         = &print,
    .save          = &save,
    .extra_opts    = opts
};

void _init(void)
{
    xtables_register_target(&account);
}
