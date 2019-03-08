/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2019 Netronome Systems, Inc. */

#ifndef LIST_H
#define LIST_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

struct list {
	struct list	*prev;
	struct list	*next;
	void		*elem;
};

struct list *list_init(void *elem);
void list_destroy(struct list *l, void (*destroy_elem)(void *));

int list_for_each(struct list *l,
		  int (*process_elem)(void *, va_list arg_ap), ...);

void *list_get_elem(struct list *l);
void list_set_elem(struct list *l, void *elem);

bool list_is_last(struct list *l);
bool list_is_first(struct list *l);
bool list_is_empty(struct list *l);

size_t list_count(struct list *l);

struct list *list_get_next(struct list *l);
struct list *list_get_prev(struct list *l);
struct list *list_get_first(struct list *l);
struct list *list_get_last(struct list *l);
struct list *list_get_nth(struct list *l, ssize_t pos);

/* Insert a new node just before l */
struct list *list_insert(struct list *l, void *elem, ssize_t pos);
/* Append after the last node */
struct list *list_append(struct list *l, void *elem);
int list_delete(struct list *l, ssize_t pos, void (*destroy_elem)(void *));

#endif /* LIST_H */
