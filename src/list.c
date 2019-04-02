// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

// DEBUG??
#include <stdio.h>

#include "list.h"

struct list *list_init(void *elem)
{
	struct list *l;

	l = (struct list *)calloc(1, sizeof(struct list));
	if (!l)
		return NULL;

	l->elem = elem;

	return l;
}

void list_destroy(struct list *l, void (*destroy_elem)(void *))
{
	if (!l)
		return;

	list_destroy(l->next, destroy_elem);
	destroy_elem(l->elem);
	free(l);
}

static int
list_vfor_each(struct list *l, int (*process_elem)(void *, va_list arg_ap),
	       va_list ap)
{
	va_list aq;
	int res;

	if (!l)
		return 0;

	va_copy(aq, ap);
	res = process_elem(l->elem, aq);
	va_end(aq);

	if (res)
		return res;

	return list_vfor_each(l->next, process_elem, ap);
}

int list_for_each(struct list *l, int (*process_elem)(void *, va_list arg_ap),
		  ...)
{
	va_list ap;
	int res;

	va_start(ap, process_elem);
	res = list_vfor_each(l, process_elem, ap);
	va_end(ap);

	return res;
}

void *list_get_elem(struct list *l)
{
	if (!l)
		return NULL;

	return l->elem;
}

void list_set_elem(struct list *l, void *elem)
{
	if (!l)
		return;

	l->elem = elem;
}

bool list_is_last(struct list *l)
{
	return !l || !l->next;
}

bool list_is_first(struct list *l)
{
	return !l || !l->prev;
}

bool list_is_empty(struct list *l)
{
	return !l;
}

/* Only count next elements (don't count previous elements, if any) */
size_t list_count(struct list *l)
{
	if (!l)
		return 0;

	return 1 + list_count(l->next);
}

struct list *list_get_next(struct list *l)
{
	if (!l)
		return NULL;

	return l->next;
}

struct list *list_get_prev(struct list *l)
{
	if (!l)
		return NULL;

	return l->prev;
}

struct list *list_get_first(struct list *l)
{
	if (list_is_first(l))
		return l;

	return list_get_first(l->prev);
}

struct list *list_get_last(struct list *l)
{
	if (list_is_last(l))
		return l;

	return list_get_last(l->next);
}

struct list *list_get_nth(struct list *l, ssize_t pos)
{
	if (pos > 0) {
		if (list_is_last(l))
			return NULL;
		return list_get_nth(l->next, pos - 1);
	}

	if (pos < 0) {
		if (list_is_first(l))
			return NULL;
		return list_get_nth(l->prev, pos + 1);
	}

	return l;
}

struct list *list_insert(struct list *l, void *elem, ssize_t pos)
{
	struct list *prev, *next, *newlist;

	prev = list_get_nth(l, pos - 1);

	if (prev) {
		newlist = list_init(elem);
		newlist->next = prev->next;
		newlist->prev = prev;
		if (prev->next)
			prev->next->prev = newlist;
		prev->next = newlist;

		return l;
	}

	next = list_get_nth(l, pos);

	if (next) {
		newlist = list_init(elem);
		newlist->next = next;
		newlist->prev = next->prev;
		if (next->prev)
			next->prev->next = newlist;
		next->prev = newlist;

		return newlist;
	}

	if (pos)
		return NULL;

	newlist = list_init(elem);
	return newlist;
}

struct list *list_append(struct list *l, void *elem)
{
	struct list *oldlast, *newlist;

	oldlast = list_get_last(l);
	if (!oldlast)
		return list_init(elem);

	newlist = list_init(elem);
	if (!newlist)
		return NULL;

	newlist->prev = oldlast;
	oldlast->next = newlist;

	return l;
}

int list_delete(struct list *l, ssize_t pos, void (*destroy_elem)(void *))
{
	struct list *target;

	target = list_get_nth(l, pos);
	if (!target)
		return -1;

	destroy_elem(target->elem);
	if (target->prev)
		target->prev->next = target->next;
	if (target->next)
		target->next->prev = target->prev;
	free(target);

	return 0;
}
