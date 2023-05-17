/*
 *  Copyright (c) 2023 NetEase Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


#include "pfs_avl.h"
#include "pfs_impl.h"

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const __typeof__(((type *)0)->member) * __mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member)); })
#endif

RB_PROTOTYPE_STATIC(pfs_avl_tree_head, pfs_avl_node, rb_node, static);

static inline void *
node2data(const pfs_avl_node_t *node, size_t off)
{
	return (void *)((uintptr_t)node - off);
}

static inline pfs_avl_node_t *
data2node(const void *data, size_t off)
{
	return (pfs_avl_node_t *)((uintptr_t)data + off);
}

static int
cmp(struct pfs_avl_tree_head *head, pfs_avl_node *_elem, pfs_avl_node *_tree_node)
{
	pfs_avl_tree_t *t = container_of(head, pfs_avl_tree_t, rb_root);
	void *elem = node2data(_elem, t->avl_offset);
	void *tree_node = node2data(_tree_node, t->avl_offset);
	return t->avl_compar(elem, tree_node);
}

RB_GENERATE_STATIC(pfs_avl_tree_head, pfs_avl_node, rb_node, cmp)

void pfs_avl_create(pfs_avl_tree_t *tree, pfs_avl_compare_fn_t *compar, size_t offset)
{
	RB_INIT(&tree->rb_root);
	tree->avl_compar = compar;
	tree->avl_offset = offset;
	tree->avl_numnodes = 0;
}

void *pfs_avl_find(pfs_avl_tree_t *tree, const void *node, uintptr_t *where)
{
	pfs_avl_node_t *tnode = data2node(node, tree->avl_offset);
	pfs_avl_node_t *tmp = pfs_avl_tree_head_RB_FIND(&tree->rb_root, tnode);
	if (tmp) {
		return node2data(tmp, tree->avl_offset);
	}
	return NULL;
}

int pfs_avl_add(pfs_avl_tree_t *tree, void *node)
{
	pfs_avl_node_t *tnode = data2node(node, tree->avl_offset);
	pfs_avl_node_t *tmp = pfs_avl_tree_head_RB_INSERT(&tree->rb_root, tnode);
	if (tmp) {
		errno = EEXIST;
		return -1;
	}
	tree->avl_numnodes++;
	return 0;
}

void pfs_avl_remove(pfs_avl_tree_t *tree, void *node)
{
	pfs_avl_node_t *tnode = data2node(node, tree->avl_offset);
	pfs_avl_tree_head_RB_REMOVE(&tree->rb_root, tnode);
	tree->avl_numnodes--;
}

void *pfs_avl_first(pfs_avl_tree_t *tree)
{
	pfs_avl_node_t *tnode = RB_MIN(pfs_avl_tree_head, &tree->rb_root);
	if (tnode) {
		return node2data(tnode, tree->avl_offset);
	}
	return NULL;
}

void *pfs_avl_last(pfs_avl_tree_t *tree)
{
	pfs_avl_node_t *tnode = RB_MAX(pfs_avl_tree_head, &tree->rb_root);
	if (tnode) {
		return node2data(tnode, tree->avl_offset);
	}
	return NULL;
}

void *pfs_avl_next(pfs_avl_tree_t *tree, void *data)
{
	pfs_avl_node_t *tnode = data2node(data, tree->avl_offset);
	pfs_avl_node_t *tmp = pfs_avl_tree_head_RB_NEXT(tnode);
	if (tmp) {
		return node2data(tmp, tree->avl_offset);
	}
	return NULL;
}

void *pfs_avl_prev(pfs_avl_tree_t *tree, void *data)
{
	pfs_avl_node_t *tnode = data2node(data, tree->avl_offset);
	pfs_avl_node_t *tmp = pfs_avl_tree_head_RB_PREV(tnode);
	if (tmp) {
		return node2data(tmp, tree->avl_offset);
	}
	return NULL;
}

void
pfs_avl_destroy(pfs_avl_tree_t *tree)
{
	PFS_ASSERT(tree);
	PFS_ASSERT(tree->avl_numnodes == 0);
	PFS_ASSERT(RB_EMPTY(&tree->rb_root));
}
