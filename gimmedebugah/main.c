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
 * Some additions by hophacker and Thomas Tempelmann (TT), via forks on github
 * Origin of this version: https://github.com/tempelmann/gimmedebugah
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
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <errno.h>
#include <getopt.h>
#include "utlist.h"

#define VERSION "0.4(tt)"
#define EXTENSION ".patched"
/* add a new section to current __TEXT segment or add a whole new segment/section */
#define NEW_SECTION 0
#define NEW_SEGMENT 1

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
    uint32_t text_offset;   // offset where __TEXT segment starts
    uint32_t data_offset;   // offset where __DATA segment starts
    struct target_info *next;
};

uint8_t default_plist[] =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
"<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
"<plist version=\"1.0\">\n"
"<dict>\n"
"<key>CFBundleDevelopmentRegion</key>\n"
"<string>English</string>\n"
"<key>CFBundleIdentifier</key>\n"
"<string>put.as.gimmedebugah</string>\n"
"<key>CFBundleInfoDictionaryVersion</key>\n"
"<string>6.0</string>\n"
"<key>CFBundleName</key>\n"
"<string>gimmedebugah</string>\n"
"<key>CFBundleVersion</key>\n"
"<string>1.0</string>\n"
"<key>SecTaskAccess</key>\n"
"<array>\n"
"<string>allowed</string>\n"
"<string>debug</string>\n"
"</array>\n"
"</dict>\n"
"</plist>\n";

/* prototypes */
static void calc_header_space_aux(uint8_t *buffer, uint32_t plist_size, struct target_info *info, uint8_t method);

void
header(void)
{
    fprintf(stdout,"  ___ _                 ___      _                   _    _\n");
    fprintf(stdout," / __(_)_ __  _ __  ___|   \\ ___| |__ _  _ __ _ __ _| |_ | |\n");
    fprintf(stdout,"| (_ | | '  \\| '  \\/ -_) |) / -_) '_ \\ || / _` / _` | ' \\|_|\n");
    fprintf(stdout," \\___|_|_|_|_|_|_|_\\___|___/\\___|_.__/\\_,_\\__, \\__,_|_||_(_)\n");
    fprintf(stdout,"                                          |___/ \n");
	fprintf(stdout,"              GimmeDebugah v%s - (c) fG!\n",VERSION);
	fprintf(stdout,"------------------------------------------------------------\n");
}

void
usage(void)
{
    fprintf(stdout,"Usage:\n");
	fprintf(stdout,"gimmedebugah [-m] [-s sect_name] [-p plist_file] target_binary\n\n");
	fprintf(stdout,"Where: \n");
	fprintf(stdout,"target_binary - binary to inject Info.plist\n");
    fprintf(stdout,"Options:\n");
    fprintf(stdout,"-p plist_file - Info.plist file to inject\n");
    fprintf(stdout,"-m            - add a new segment/section instead of just a section\n");
    fprintf(stdout,"-s sect_name  - section name (default: __info_plist)\n");
    fprintf(stdout,"\nNote: if no plist is specified a default one will be used\n");
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
calc_header_space(uint8_t *buffer, uint32_t plist_size, struct target_info **info, uint8_t method)
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
            calc_header_space_aux(buffer+ntohl(fa->offset), plist_size, new, method);
            fa++;
        }
    }
    else if (magic == MH_MAGIC || magic == MH_MAGIC_64)
    {
        struct target_info *new = malloc(sizeof(struct target_info));
        new->start_offset = 0; // offset always 0 for non-fat binaries
        LL_PREPEND(*info, new);
        calc_header_space_aux(buffer, plist_size, new, method);
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
static void
calc_header_space_aux(uint8_t *buffer, uint32_t plist_size, struct target_info *info, uint8_t method)
{
    struct mach_header *mh = (struct mach_header*)buffer;
    uint32_t header_size = 0;
    uint32_t new_cmds_size = 0; // the total size of the new commands to add
    if (mh->magic == MH_MAGIC)
    {
        header_size = sizeof(struct mach_header);
        new_cmds_size = (method == NEW_SEGMENT) ? sizeof(struct segment_command) + sizeof(struct section) : sizeof(struct section);
    }
    else if (mh->magic == MH_MAGIC_64)
    {
        header_size = sizeof(struct mach_header_64);
        new_cmds_size = (method == NEW_SEGMENT) ? sizeof(struct segment_command_64) + sizeof(struct section_64) : sizeof(struct section_64);
    }
    else
    {
        info->free_space = 0;
        return;
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
            if (strncmp(seg_cmd->segname, "__DATA", 16) == 0)
            {
                info->data_offset = (uint32_t)load_cmd - (uint32_t)buffer;
                LOG_DEBUG("[DEBUG] data offset is %x\n", info->data_offset);
            }
            else if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                info->text_offset = (uint32_t)load_cmd - (uint32_t)buffer;
                LOG_DEBUG("[DEBUG] text offset is %x\n", info->text_offset);
            }
            
            if (seg_cmd->nsects > 0)
            {
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    if (section->size != 0 && section->offset < lowest_offset)
                    {
                        /* there are sections with fileoffset = 0 so we need to avoid them */
                        lowest_offset = (section->offset != 0) ? section->offset : lowest_offset;
                    }
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", section->sectname, section->offset, lowest_offset);
                    section++;
                }
            }
            else
            {
                if (seg_cmd->filesize != 0 && seg_cmd->fileoff < lowest_offset)
                {
                    /* there are sections with fileoffset = 0 so we need to avoid them */
                    lowest_offset = (seg_cmd->fileoff != 0) ? seg_cmd->fileoff : lowest_offset;
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", seg_cmd->segname, seg_cmd->fileoff, lowest_offset);
                }
            }
        }
        else if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd64 = (struct segment_command_64*)load_cmd;
            struct section_64 *section64 = (struct section_64*)((char*)seg_cmd64 + sizeof(struct segment_command_64));
            LOG_DEBUG("[DEBUG] Processing %s nsects %d\n", seg_cmd64->segname, seg_cmd64->nsects);
            if (strncmp(seg_cmd64->segname, "__DATA", 16) == 0)
            {
                info->data_offset = (uint32_t)load_cmd - (uint32_t)buffer;
                LOG_DEBUG("[DEBUG] data offset is %x\n", info->data_offset);
            }
            else if (strncmp(seg_cmd64->segname, "__TEXT", 16) == 0)
            {
                info->text_offset = (uint32_t)load_cmd - (uint32_t)buffer;
                LOG_DEBUG("[DEBUG] text offset is %x\n", info->text_offset);
            }

            if (seg_cmd64->nsects > 0)
            {
                for (uint32_t x = 0; x < seg_cmd64->nsects; x++)
                {
                    if (section64->size != 0 && section64->offset < lowest_offset)
                    {
                        /* there are sections with fileoffset = 0 so we need to avoid them */
                        lowest_offset = (section64->offset != 0) ? section64->offset : lowest_offset;
                    }
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", section64->sectname, section64->offset, lowest_offset);
                    section64++;
                }
            }
            else
            {
                if (seg_cmd64->filesize != 0 && seg_cmd64->fileoff < lowest_offset)
                {
                    /* there are sections with fileoffset = 0 so we need to avoid them */
                    lowest_offset = (seg_cmd64->fileoff != 0) ? (uint32_t)seg_cmd64->fileoff : lowest_offset;
                    LOG_DEBUG("[DEBUG] %s offset: 0x%x lowest: 0x%x\n", seg_cmd64->segname, (uint32_t)seg_cmd64->fileoff, lowest_offset);
                }
            }
        }
        load_cmd = (struct load_command*)((char*)load_cmd + load_cmd->cmdsize);
    }

    /* the free space offset starts right after the last current command */
    info->free_offset = header_size + mh->sizeofcmds;
    info->free_space  = lowest_offset - info->free_offset;
    info->new_cmds_size = new_cmds_size;
    info->header_size = header_size;
    
    /* now we can verify if there's enough space */
    uint32_t new_offset = info->free_offset + new_cmds_size + plist_size;
    LOG_DEBUG("[DEBUG] free offset: %x new offset: %x lowest offset: %x\n", header_size + mh->sizeofcmds, new_offset, lowest_offset);
    if (new_offset > lowest_offset)
    {
        /* not enough space so set it to 0 */
        info->free_space = 0;
        info->free_offset = 0;
    }
}

/* alignment to 32 bits, rounded up */
static uint32_t align_plist_offset(uint32_t offset)
{
    uint32_t remainder = offset % sizeof(uint32_t);
    if (remainder != 0)
        return (offset + sizeof(uint32_t) - remainder);
    else
        return offset;
}

/* alignment to 32 bits, rounded down */
static uint32_t align_plist_offset_down(uint32_t offset)
{
    uint32_t remainder = offset % sizeof(uint32_t);
    if (remainder != 0)
        return (offset - remainder);
    else
        return offset;
}

/*
 * this function will just move the old commands forward to create space for the new ones
 */
static int
relocate_original_headers(uint8_t *buffer, struct target_info *info, uint8_t method)
{
    struct target_info *tmp = NULL;
    LL_FOREACH(info, tmp)
    {
        uint8_t *start = buffer + tmp->start_offset;
        if (method == NEW_SEGMENT)
        {
            /*
             * the start of the free space is located at header + cmds
             * so we can compute the size and location of the commands we want to move forward
             */
            uint32_t old_cmds_size = tmp->free_offset - tmp->header_size;
            /* move olds commands forward */
            uint8_t *src = start + tmp->header_size;
            uint8_t *dest = start + tmp->header_size + tmp->new_cmds_size;
            memmove(dest, src, old_cmds_size);
            /* zero old data */
            memset(src, 0, tmp->new_cmds_size);
        }
        else if (method == NEW_SECTION)
        {
            /* offset is relative to start of file so we need to add it to compute the size */
            uint32_t old_cmds_size = tmp->free_offset - tmp->data_offset + tmp->header_size;
            uint8_t *src = start + tmp->data_offset;
            uint8_t *dst = src + tmp->new_cmds_size;
            memmove(dst, src, old_cmds_size);
            memset(src, 0, tmp->new_cmds_size);
        }
    }
    return 0;
}

/*
 * add the new commands to the header and copy the plist into the free header space
 */
static int
inject_plist_segment(const char *sectname, uint8_t *buffer, uint8_t *plist_buffer, uint32_t plist_size, struct target_info *info, uint64_t addr)
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
            strcpy(newsect->sectname, sectname);
            strcpy(newsect->segname, "__TEXT");
            newsect->addr = 0x1000;
            newsect->size = plist_size;
            /* calculate the offset for the plist */
            uint32_t new_free_offset = align_plist_offset(tmp->free_offset + tmp->new_cmds_size);
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
            newseg64->vmaddr = addr;
            newseg64->filesize = plist_size;
            newseg64->maxprot = VM_PROT_ALL;
            newseg64->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
            newseg64->nsects = 1;
            struct section_64 *newsect64 = (struct section_64*)((char*)newseg64 + sizeof(struct segment_command_64));
            strcpy(newsect64->sectname, sectname);
            strcpy(newsect64->segname, "__TEXT");            
            newsect64->addr = addr;
            newsect64->size = plist_size;
            /* calculate the offset for the plist, placing at the top of the available area so that we can still add more below it */
            uint32_t new_free_offset = align_plist_offset_down(tmp->free_offset + tmp->free_space - plist_size);
            newsect64->offset = new_free_offset;
            uint8_t *start = buffer + tmp->start_offset + new_free_offset;
            memcpy(start, plist_buffer, plist_size);
            new_free_offset = align_plist_offset(new_free_offset + plist_size);
            tmp->free_offset = new_free_offset;
            mh->ncmds += 1;
            mh->sizeofcmds += tmp->new_cmds_size;
        }
    }
    return 0;
}

/*
 * add only the new section to the already existing __TEXT segment
 */
static int
inject_plist_section(const char *sectname, uint8_t *buffer, uint8_t *plist_buffer, uint32_t plist_size, struct target_info *info, uint64_t addr)
{
    struct target_info *tmp = NULL;
    LL_FOREACH(info, tmp)
    {
        struct mach_header *mh = (struct mach_header*)(buffer + tmp->start_offset);
        if (mh->magic == MH_MAGIC)
        {
            /* location of __TEXT segment command - we need to fix its size and number of sections */
            struct segment_command *seg_cmd = (struct segment_command*)(buffer + tmp->start_offset + tmp->text_offset);
            /* the location of the new section */
            struct section *newsect = (struct section*)((char*)seg_cmd + seg_cmd->cmdsize);
            /* and add the new section */
            strcpy(newsect->sectname, sectname);
            strcpy(newsect->segname, "__TEXT");
            newsect->addr = 0x1000;
            newsect->size = plist_size;
            /* calculate the offset for the plist */
            uint32_t new_free_offset = align_plist_offset(tmp->free_offset + tmp->new_cmds_size);
            /* set the plist offset and copy it */
            newsect->offset = new_free_offset;
            uint8_t *start = buffer + tmp->start_offset + new_free_offset;
            memcpy(start, plist_buffer, plist_size);
            /* and finally fix all the sizes and number of commands/sections */
            seg_cmd->cmdsize += tmp->new_cmds_size;
            seg_cmd->nsects += 1;
            mh->sizeofcmds += tmp->new_cmds_size;
        }
        else if (mh->magic == MH_MAGIC_64)
        {
            /* location of __TEXT segment command - we need to fix its size */
            struct segment_command_64 *seg_cmd64 = (struct segment_command_64*)(buffer + tmp->start_offset + tmp->text_offset);
            struct section_64 *newsect = (struct section_64*)((char*)seg_cmd64 + seg_cmd64->cmdsize);

            /* and add the new section */            
            strcpy(newsect->sectname, sectname);
            strcpy(newsect->segname, "__TEXT");
            newsect->addr = addr;
            newsect->size = plist_size;
            /* calculate the offset for the plist, placing at the top of the available area so that we can still add more below it */
            uint32_t new_free_offset = align_plist_offset_down(tmp->free_offset + tmp->free_space - plist_size);
            /* set the plist offset and copy it */
            newsect->offset = new_free_offset;
            LOG_DEBUG("[DEBUG] %s offset %x align %x addr %llx\n", sectname, newsect->offset, newsect->align, newsect->addr);
            uint8_t *start = buffer + tmp->start_offset + new_free_offset;
            memcpy(start, plist_buffer, plist_size);
            /* and finally fix all the sizes and number of commands/sections */
            seg_cmd64->cmdsize += tmp->new_cmds_size;
            seg_cmd64->nsects += 1;
            mh->sizeofcmds += tmp->new_cmds_size;
        }
    }
    return 0;
}

int main(int argc, const char * argv[])
{
    header();
    int c;
    uint8_t method = NEW_SECTION; // default is to add the new section
    const char *target_path = NULL;
    const char *plist_path = NULL;
    char *sectname = "__info_plist";
    uint64_t addr = 0x100000000;
   
    opterr = 0;
    while ((c = getopt(argc, (char * const*)argv, "s:p:m")) != -1)
    {
        switch (c) {
            case 'p':
                plist_path = optarg;
                break;
            case 'm':
                method = NEW_SEGMENT;
                break;
            case 's':
                sectname = optarg;
                break;
            case 'h':
            case '?':
                usage();
                break;
            default:
                usage();
                exit(1);
        }
    }

    if (optind < argc)
    {
        target_path = argv[optind];
    }
    else
    {
        usage();
        exit(1);
    }
    
    FILE *target_file = fopen(target_path, "r");
    if (!target_file)
    {
        fprintf(stderr, "[ERROR] Can't open %s.\n", target_path);
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
    uint32_t plist_size = 0;
    if (plist_path == NULL)
    {
        plist_buf = default_plist;
        plist_size = (uint32_t)strlen((const char*)default_plist)+1;
    }
    else
    {
        FILE *plist_file = fopen(plist_path, "r");
        if (!plist_file)
        {
            fprintf(stderr, "[ERROR] Can't open %s.\n", plist_path);
            perror(NULL);
            exit(1);
        }
        plist_size = read_file(&plist_buf, plist_file);
        fclose(plist_file);
    }

    // make sure there's enough space to inject the plist file
    struct target_info *info = NULL;
    if (calc_header_space(target_buf, plist_size, &info, method))
    {
        fprintf(stderr, "[ERROR] Not enough space available to inject plist!\n");
        exit(1);
    }
    
    /* we have free space so we can do our job! */

    relocate_original_headers(target_buf, info, method);
    if (method == NEW_SECTION)
        inject_plist_section(sectname, target_buf, plist_buf, plist_size, info, addr);
    else
        inject_plist_segment(sectname, target_buf, plist_buf, plist_size, info, addr);
    
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
    printf("The plist has been injected. Now you can re-codesign the target binary:\n");
    printf("\"codesign -s identity -f %s\"\n", output_path);
    printf("Bye.\n");
    return 0;
}
