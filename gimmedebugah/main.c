/*
 *   ____ _                          ____       _                       _     _
 *  / ___(_)_ __ ___  _ __ ___   ___|  _ \  ___| |__  _   _  __ _  __ _| |__ | |
 * | |  _| | '_ ` _ \| '_ ` _ \ / _ \ | | |/ _ \ '_ \| | | |/ _` |/ _` | '_ \| |
 * | |_| | | | | | | | | | | | |  __/ |_| |  __/ |_) | |_| | (_| | (_| | | | |_|
 *  \____|_|_| |_| |_|_| |_| |_|\___|____/ \___|_.__/ \__,_|\__, |\__,_|_| |_(_)
 *                                                          |___/
 * GimmeDebugah, a Info.plist injector.
 *
 * Copyright (c) fG!, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <getopt.h>
#include <ctype.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <stddef.h>
#include <assert.h>
#include <errno.h>
#include "utlist.h"

#define VERSION "0.1"
#define EXTENSION ".patched"

#if DEBUG
#define LOG_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG_DEBUG(...) do {} while (0)
#endif

struct target_info
{
    uint32_t free_space;    // total available free space
    uint32_t free_offset;   // file offset where free space starts
    uint32_t start_offset;  // where each target starts if target is a FAT archive, else is always 0
    uint32_t new_cmds_size; // size of the new commands - sizeof(struct segment_command*) + sizeof(struct section*)
    uint32_t header_size;   // original mach-o header size sizeof(struct mach_header*)
    struct target_info *next;
};

// prototypes
void header(void);
void usage(void);
static int calc_header_space(uint8_t *buffer, uint32_t plist_size, struct target_info **info);
static int calc_header_space_aux(uint8_t *buffer, uint32_t plist_size, struct target_info *info);
static int relocate_original_headers(uint8_t *buffer, struct target_info *info);
static int inject_plist(uint8_t *buffer, uint8_t *plist_buffer, uint32_t plist_size, struct target_info *info);

void
header(void)
{
    
    fprintf(stderr,"  ___ _                 ___      _                   _    _\n");
    fprintf(stderr," / __(_)_ __  _ __  ___|   \\ ___| |__ _  _ __ _ __ _| |_ | |\n");
    fprintf(stderr,"| (_ | | '  \\| '  \\/ -_) |) / -_) '_ \\ || / _` / _` | ' \\|_|\n");
    fprintf(stderr," \\___|_|_|_|_|_|_|_\\___|___/\\___|_.__/\\_,_\\__, \\__,_|_||_(_)\n");
    fprintf(stderr,"                                          |___/ \n");
	fprintf(stderr,"              GimmeDebugah v%s - (c) fG!\n",VERSION);
	fprintf(stderr,"------------------------------------------------------------\n");
}

void
usage(void)
{
    fprintf(stderr, "Usage:\n");
	fprintf(stderr,"gimmedebugah target_binary plist_file\n\n");
	fprintf(stderr,"Where: \n");
	fprintf(stderr,"target_binary - binary to inject Info.plist\n");
    fprintf(stderr,"plist_file    - Info.plist file to inject\n");
	exit(1);
}

/*
 * read the target file into a buffer
 */
static uint32_t
read_file(uint8_t **buffer, FILE *file)
{
    if (fseek(file, 0, SEEK_END))
    {
		fprintf(stderr, "[ERROR] fseek failed!\n");
        perror(NULL);
        exit(1);
    }
    /* XXX: truncate to 32 bits, maybe add some check if file > uint32_t ? */
    uint32_t size = (uint32_t)ftell(file);
    
    if (fseek(file, 0, SEEK_SET))
    {
		printf("[ERROR] fseek failed!\n");
        perror(NULL);
        exit(1);
    }
    
    *buffer = malloc(size);
    if (*buffer == NULL)
    {
        fprintf(stderr, "[ERROR] malloc failed!\n");
        exit(1);
    }
    
    fread(*buffer, size, 1, file);
	if (ferror(file))
	{
		printf("[ERROR] fread failed!\n");
		exit(1);
	}
    return size;
}

/*
 * the main function to find free space
 * supports fat and non-fat targets
 */
static int
calc_header_space(uint8_t *buffer, uint32_t plist_size, struct target_info **info)
{
    uint32_t magic = *(uint32_t*)buffer;
    if (magic == FAT_CIGAM)
    {
        struct fat_header *fh = (struct fat_header*)buffer;
        struct fat_arch *fa = (struct fat_arch*)(buffer + sizeof(struct fat_header));
        for (uint32_t i = 0; i < ntohl(fh->nfat_arch); i++)
        {
            struct target_info *new = malloc(sizeof(struct target_info));
            new->start_offset = ntohl(fa->offset);
            LL_PREPEND(*info, new);
            calc_header_space_aux(buffer+ntohl(fa->offset), plist_size, new);
            fa++;
        }
    }
    else if (magic == MH_MAGIC || magic == MH_MAGIC_64)
    {
        struct target_info *new = malloc(sizeof(struct target_info));
        new->start_offset = 0; // offset always 0 for non-fat binaries
        LL_PREPEND(*info, new);
        calc_header_space_aux(buffer, plist_size, new);
    }
    
    /* verify if it will be possible to inject */
    struct target_info *tmp = NULL;
    LL_FOREACH(*info, tmp)
    {
        if (tmp->free_space == 0) return 1;
    }
    return 0;
}

/*
 * find size and location of free space to inject new commands and header
 */
static int
calc_header_space_aux(uint8_t *buffer, uint32_t plist_size, struct target_info *info)
{
    struct mach_header *mh = (struct mach_header*)buffer;
    uint32_t header_size = 0;
    uint32_t new_cmds_size = 0; // the total size of the new commands to add
    if (mh->magic == MH_MAGIC)
    {
        header_size = sizeof(struct mach_header);
        new_cmds_size = sizeof(struct segment_command) + sizeof(struct section);
    }
    else if (mh->magic == MH_MAGIC_64)
    {
        header_size = sizeof(struct mach_header_64);
        new_cmds_size = sizeof(struct segment_command_64) + sizeof(struct section_64);
    }
    else
    {
        return -1;
    }
    
    struct load_command *load_cmd = (struct load_command*)((char*)buffer + header_size);
    uint32_t lowest_offset = UINT_MAX;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        if (load_cmd->cmd == LC_SEGMENT)
        {
            struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
            struct section *section = (struct section*)((char*)seg_cmd + sizeof(struct segment_command));
            LOG_DEBUG("[DEBUG] Processing %s\n", seg_cmd->segname);
            if (seg_cmd->nsects > 0)
            {
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", section->sectname, section->offset, lowest_offset);
                    if (section->size != 0 && section->offset < lowest_offset)
                    {
                        lowest_offset = section->offset;
                    }
                    section++;
                }
            }
            else
            {
                if (seg_cmd->filesize != 0 && seg_cmd->fileoff < lowest_offset)
                {
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", seg_cmd->segname, seg_cmd->fileoff, lowest_offset);
                    lowest_offset = seg_cmd->fileoff;
                }
            }
        }
        else if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd64 = (struct segment_command_64*)load_cmd;
            struct section_64 *section64 = (struct section_64*)((char*)seg_cmd64 + sizeof(struct segment_command_64));
            LOG_DEBUG("[DEBUG] Processing %s\n", seg_cmd64->segname);
            if (seg_cmd64->nsects > 0)
            {
                for (uint32_t x = 0; x < seg_cmd64->nsects; x++)
                {
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", section64->sectname, section64->offset, lowest_offset);
                    if (section64->size != 0 && section64->offset < lowest_offset)
                    {
                        lowest_offset = section64->offset;
                    }
                    section64++;
                }
            }
            else
            {
                if (seg_cmd64->filesize != 0 && seg_cmd64->fileoff < lowest_offset)
                {
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", seg_cmd64->segname, (uint32_t)seg_cmd64->fileoff, lowest_offset);
                    lowest_offset = (uint32_t)seg_cmd64->fileoff;
                }
            }
        }
        load_cmd = (struct load_command*)((char*)load_cmd + load_cmd->cmdsize);
    }
    
    /* now we can verify if there's enough space */
    uint32_t new_header_size = header_size + mh->sizeofcmds + new_cmds_size + plist_size;
    if (new_header_size > lowest_offset)
    {
        /* not enough space so set it to 0 */
        info->free_space = 0;
        info->free_offset = 0;
    }
    else
    {
        info->free_space  = lowest_offset - (header_size + mh->sizeofcmds);
        info->free_offset = header_size + mh->sizeofcmds;
        info->new_cmds_size = new_cmds_size;
        info->header_size = header_size;
    }
    return 0;
}

/*
 * this function will just move the old commands forward to create space for the new ones
 */
static int
relocate_original_headers(uint8_t *buffer, struct target_info *info)
{
    struct target_info *tmp = NULL;
    LL_FOREACH(info, tmp)
    {
        uint8_t *start = buffer + tmp->start_offset;
        /*
         * the start of the free space is located at header + cmds
         * so we can compute the size and location of the commands we want to move forward
         */
        uint32_t old_cmds_size = tmp->free_offset - tmp->header_size;
        /* move olds commands forward */
        uint8_t *src = start + tmp->header_size;
        uint8_t *dest = start + tmp->header_size + tmp->new_cmds_size;
        memmove(dest, src, old_cmds_size);
        memset(src, 0, tmp->new_cmds_size);
    }
    return 0;
}

/*
 * add the new commands to the header and copy the plist into the free header space
 */
static int
inject_plist(uint8_t *buffer, uint8_t *plist_buffer, uint32_t plist_size, struct target_info *info)
{
    struct target_info *tmp = NULL;
    // new headers
    LL_FOREACH(info, tmp)
    {
        struct mach_header *mh = (struct mach_header*)(buffer + tmp->start_offset);
        if (mh->magic == MH_MAGIC)
        {
            /*
             * space was memset to 0 so all other fields not explicit set stay at 0
             * prepare the segment command
             */
            struct segment_command *newseg = (struct segment_command*)((char*)mh + tmp->header_size);
            newseg->cmd = LC_SEGMENT;
            newseg->cmdsize = sizeof(struct segment_command) + sizeof(struct section);
            strcpy(newseg->segname, "__TEXT");
            newseg->vmaddr = 0x1000;
            newseg->filesize = plist_size;
            newseg->maxprot = VM_PROT_ALL;
            newseg->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
            newseg->nsects = 1;
            /* and the section */
            struct section *newsect = (struct section*)((char*)newseg + sizeof(struct segment_command));
            strcpy(newsect->sectname, "__info_plist");
            strcpy(newsect->segname, "__TEXT");
            newsect->addr = 0x1000;
            newsect->size = plist_size;
            /* calculate the offset for the plist */
            uint32_t new_free_offset = tmp->free_offset + tmp->new_cmds_size;
            /* alignment to 32 bits */
            uint32_t remainder = new_free_offset % sizeof(uint32_t);
            if (remainder != 0) new_free_offset += sizeof(uint32_t) - remainder;
            /* set the plist offset and copy it */
            newsect->offset = new_free_offset;
            uint8_t *start = buffer + tmp->start_offset + new_free_offset;
            memcpy(start, plist_buffer, plist_size);            
            /* and finally fix the mach-o header to include the new segment */
            mh->ncmds += 1;
            mh->sizeofcmds += tmp->new_cmds_size;
        }
        else if (mh->magic == MH_MAGIC_64)
        {
            struct segment_command_64 *newseg64 = (struct segment_command_64*)((char*)mh + tmp->header_size);
            newseg64->cmd = LC_SEGMENT_64;
            newseg64->cmdsize = sizeof(struct segment_command_64) + sizeof(struct section_64);
            strcpy(newseg64->segname, "__TEXT");
            newseg64->vmaddr = 0x100000000;
            newseg64->filesize = plist_size;
            newseg64->maxprot = VM_PROT_ALL;
            newseg64->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
            newseg64->nsects = 1;
            
            struct section_64 *newsect64 = (struct section_64*)((char*)newseg64 + sizeof(struct segment_command_64));
            strcpy(newsect64->sectname, "__info_plist");
            strcpy(newsect64->segname, "__TEXT");            
            newsect64->addr = 0x100000000;
            newsect64->size = plist_size;
            uint32_t new_free_offset = tmp->free_offset + tmp->new_cmds_size;
            uint32_t remainder = new_free_offset % sizeof(uint32_t);
            if (remainder != 0) new_free_offset += sizeof(uint32_t) - remainder;
            newsect64->offset = new_free_offset;
            uint8_t *start = buffer + tmp->start_offset + new_free_offset;
            memcpy(start, plist_buffer, plist_size);
            mh->ncmds += 1;
            mh->sizeofcmds += tmp->new_cmds_size;
        }
    }
    return 0;
}

int main(int argc, const char * argv[])
{
    header();

    const char *target_path = argv[1];
    const char *plist_path = argv[2];

    if (argc < 3) usage();
    
    FILE *target_file = fopen(target_path, "r");
    if (!target_file)
    {
        fprintf(stderr, "[ERROR] Can't open %s.\n", target_path);
        perror(NULL);
        exit(1);        
    }
    FILE *plist_file = fopen(plist_path, "r");
    if (!plist_file)
    {
        fprintf(stderr, "[ERROR] Can't open %s.\n", plist_path);
        perror(NULL);
        exit(1);
    }
    
    uint8_t *target_buf = NULL;
    uint32_t target_size = read_file(&target_buf, target_file);
    fclose(target_file);
    uint32_t magic = *(uint32_t*)target_buf;
    if (magic != FAT_CIGAM && magic != MH_MAGIC && magic != MH_MAGIC_64)
    {
        fprintf(stderr, "[ERROR] Target is not a valid Mach-O file!\n");
        exit(1);
    }
    
    uint8_t *plist_buf = NULL;
    uint32_t plist_size = read_file(&plist_buf, plist_file);
    fclose(plist_file);
    // verify if there's enough space to inject the plist file
    struct target_info *info = NULL;
    if (calc_header_space(target_buf, plist_size, &info))
    {
        fprintf(stderr, "[ERROR] Not enough space available to inject Info.plist!\n");
        exit(1);
    }
    
    /* we have free space so we can do our job! */
    relocate_original_headers(target_buf, info);
    inject_plist(target_buf, plist_buf, plist_size, info);
    /* build output filename */
    size_t output_size = strlen(target_path) + strlen(EXTENSION) + 1;
    char *output_path = malloc(output_size);
    strcpy(output_path, target_path);
    strncat(output_path, EXTENSION, strlen(EXTENSION));
    output_path[output_size-1] = '\0';
    /* and write it */
    FILE *output_file = fopen(output_path, "wb");
    if (fwrite(target_buf, target_size, 1, output_file) != 1)
    {
        fprintf(stderr, "[ERROR] Can't write to %s\n", output_path);
        fclose(output_file);
        exit(1);
    }
    fclose(output_file);
    /* all done */
    printf("Info.plist is injected, now you can re-codesign the target binary %s\n", output_path);
    printf("\"codesign -s identity -f %s\"\n", output_path);
    printf("Bye...\n");
    return 0;
}
