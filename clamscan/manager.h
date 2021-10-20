/*
 *  Copyright (C) 2013-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __MANAGER_H
#define __MANAGER_H

#include "optparser.h"

int scanmanager(const struct optstruct *opts);
cl_error_t pre(int fd, const char *type, void *context);
cl_error_t meta(const char *container_type, unsigned long fsize_container, const char *filename,
                       unsigned long fsize_real, int is_encrypted, unsigned int filepos_container, void *context);
cl_error_t post(int fd, int result, const char *virname, void *context);
void clamscan_virus_found_cb(int fd, const char *virname, void *context);

struct metachain {
    char **chains;
    size_t lastadd;
    size_t lastvir;
    size_t level;
    size_t nchains;
};

struct clamscan_cb_data {
    struct metachain *chain;
    const char *filename;
};

#endif
