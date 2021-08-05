/*
* nvlist.c - Minimal linked list library for name-value pairs
* Copyright (c) 2006-07,2016 Red Hat Inc., Durham, North Carolina.
* All Rights Reserved. 
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*
* Authors:
*   Steve Grubb <sgrubb@redhat.com>
*/

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include "nvlist.h"
#include "interpret.h"
#include "auparse-idata.h"


void nvlist_create(nvlist *l)
{
	if (l) {
		memset(&l->array[0], 0, sizeof(nvnode) * NFIELDS);
		l->cur = 0;
		l->cnt = 0;
	}
}

nvnode *nvlist_next(nvlist *l)
{
	if (l->cur < NFIELDS)
		l->cur++;
	return &l->array[l->cur];
}

void nvlist_append(nvlist *l, nvnode *node)
{
	nvnode *newnode = &l->array[l->cnt];

	newnode->name = node->name;
	newnode->val = node->val;
	newnode->interp_val = NULL;
	newnode->item = l->cnt;
//	newnode->next = NULL;

	// make newnode current
	l->cur = l->cnt;
	l->cnt++;
}

/*
 * Its less code to make a fixup than a new append.
 */
void nvlist_interp_fixup(nvlist *l)
{
	nvnode* node = &l->array[l->cur];
	node->interp_val = node->val;
	node->val = NULL;
}

#include <stdio.h>
nvnode *nvlist_goto_rec(nvlist *l, unsigned int i)
{
	if (i <= l->cnt) {
		l->cur = i;
		return &l->array[l->cur];
	}
	return NULL;
}

/*
 * This function will start at current index and scan for a name
 */
int nvlist_find_name(nvlist *l, const char *name)
{
	unsigned int i = l->cur;
	register nvnode *node;

	if (l->cnt == 0)
		return 0;

	do {
		node = &l->array[i];
		if (node->name && strcmp(node->name, name) == 0) {
			l->cur = i;
			return 1;
		}
		i++;
	} while (i < l->cnt);
	return 0;
}

extern int interp_adjust_type(int rtype, const char *name, const char *val);
int nvlist_get_cur_type(const rnode *r)
{
	const nvlist *l = &r->nv;
	nvnode *node = &l->array[l->cur];
	return auparse_interp_adjust_type(r->type, node->name, node->val);
}

const char *nvlist_interp_cur_val(const rnode *r, auparse_esc_t escape_mode)
{
	const nvlist *l = &r->nv;
	nvnode *node = &l->array[l->cur];
	if (node->interp_val)
		return node->interp_val;
	return do_interpret(r, escape_mode);
}

void nvlist_clear(nvlist* l)
{
	unsigned int i = 0;
	register nvnode* current;

	if (l->cnt == 0)
		return;

	while (i < l->cnt) {
		current = &l->array[i];
		free(current->name);
		free(current->val);
		free(current->interp_val);
		i++;
	}
	l->cur = 0;
	l->cnt = 0;
}
