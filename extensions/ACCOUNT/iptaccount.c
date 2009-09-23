/***************************************************************************
 *   Copyright (C) 2004-2006 by Intra2net AG                               *
 *   opensource@intra2net.com                                              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License           *
 *   version 2.1 as published by the Free Software Foundation;             *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include <libxt_ACCOUNT_cl.h>

char exit_now = 0;
static void sig_term(int signr)
{
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    exit_now=1;
}

char *addr_to_dotted(unsigned int);
char *addr_to_dotted(unsigned int addr)
{
    static char buf[17];
    const unsigned char *bytep;

    bytep = (const unsigned char *) &addr;
    snprintf(buf, 16, "%u.%u.%u.%u", bytep[0], bytep[1], bytep[2], bytep[3]);
    buf[16] = 0;
    return buf;
}

static void show_usage(void)
{
    printf ("Unknown command line option. Try: [-u] [-h] [-a] [-f] [-c] [-s] [-l name]\n");
    printf("[-u] show kernel handle usage\n");
    printf("[-h] free all kernel handles (experts only!)\n\n");
    printf("[-a] list all table names\n");
    printf("[-l name] show data in table <name>\n");
    printf("[-f] flush data after showing\n");
    printf("[-c] loop every second (abort with CTRL+C)\n");
    printf("[-s] CSV output (for spreadsheet import)\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    struct ipt_ACCOUNT_context ctx;
    struct ipt_acc_handle_ip *entry;
    int i;
    char optchar, doHandleUsage=0, doHandleFree=0, doTableNames=0,
                  doFlush=0, doContinue=0, doCSV=0;

    char *table_name = NULL;
    const char *name;

    printf("\nlibxt_ACCOUNT_cl userspace accounting tool v%s\n\n",
	LIBXT_ACCOUNT_VERSION);

    if (argc == 1)
    {
        show_usage();
        exit(0);
    }

    while ((optchar = getopt (argc, argv, "uhacfsl:")) != -1)
    {
        switch (optchar)
        {
            case 'u':
                doHandleUsage=1;
                break;
            case 'h':
                doHandleFree=1;
                break;
            case 'a':
                doTableNames=1;
                break;
            case 'f':
                doFlush=1;
                break;
            case 'c':
                doContinue=1;
                break;
            case 's':
                doCSV=1;
                break;
            case 'l':
                table_name = (char *)strdup(optarg);
                break;
            case '?':
            default:
                show_usage();
                exit (0);
                break;
        }
    }

    // install exit handler
    if (signal(SIGTERM, sig_term) == SIG_ERR)
    {
        printf("can't install signal handler for SIGTERM\n");
        exit (-1);
    }
    if (signal(SIGINT, sig_term) == SIG_ERR)
    {
        printf("can't install signal handler for SIGINT\n");
        exit (-1);
    }
    if (signal(SIGQUIT, sig_term) == SIG_ERR)
    {
        printf("can't install signal handler for SIGQUIT\n");
        exit (-1);
    }

    if(ipt_ACCOUNT_init(&ctx))
    {
        printf("Init failed: %s\n", ctx.error_str);
        exit (-1);
    }

    // Get handle usage?
    if (doHandleUsage)
    {
        int rtn = ipt_ACCOUNT_get_handle_usage(&ctx);
        if (rtn < 0)
        {
            printf("get_handle_usage failed: %s\n", ctx.error_str);
            exit (-1);
        }

        printf("Current kernel handle usage: %d\n", ctx.handle.itemcount);
    }

    if (doHandleFree)
    {
        int rtn = ipt_ACCOUNT_free_all_handles(&ctx);
        if (rtn < 0)
        {
            printf("handle_free_all failed: %s\n", ctx.error_str);
            exit (-1);
        }

        printf("Freed all handles in kernel space\n");
    }

    if (doTableNames)
    {
        int rtn = ipt_ACCOUNT_get_table_names(&ctx);
        if (rtn < 0)
        {
            printf("get_table_names failed: %s\n", ctx.error_str);
            exit (-1);
        }
        while ((name = ipt_ACCOUNT_get_next_name(&ctx)) != 0)
            printf("Found table: %s\n", name);
    }

    if (table_name)
    {
        // Read out data
        if (doCSV)
            printf("IP;SRC packets;SRC bytes;DST packets;DST bytes\n");
        else
            printf("Showing table: %s\n", table_name);

        i = 0;
        while (!exit_now)
        {
            // Get entries from table test
            if (ipt_ACCOUNT_read_entries(&ctx, table_name, !doFlush))
            {
                printf("Read failed: %s\n", ctx.error_str);
                ipt_ACCOUNT_deinit(&ctx);
                exit (-1);
            }

            if (!doCSV)
                printf("Run #%d - %u %s found\n", i, ctx.handle.itemcount,
                       ctx.handle.itemcount == 1 ? "item" : "items");

            // Output and free entries
            while ((entry = ipt_ACCOUNT_get_next_entry(&ctx)) != NULL)
            {
                if (doCSV)
                    printf("%s;%u;%u;%u;%u\n",
                        addr_to_dotted(entry->ip), entry->src_packets, entry->src_bytes,
                                    entry->dst_packets, entry->dst_bytes);
                else
                    printf("IP: %s SRC packets: %u bytes: %u DST packets: %u bytes: %u\n",
                        addr_to_dotted(entry->ip), entry->src_packets, entry->src_bytes,
                                    entry->dst_packets, entry->dst_bytes);
            }

            if (doContinue)
            {
                sleep(1);
                i++;
            } else
                exit_now = 1;
        }
    }

    printf("Finished.\n");
    ipt_ACCOUNT_deinit(&ctx);
    exit (0);
}
