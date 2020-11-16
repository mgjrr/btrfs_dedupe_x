// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 Fujitsu.  All rights reserved.
 */

#include "ctree.h"
#include "dedupe.h"
#include "btrfs_inode.h"
#include "delayed-ref.h"
#include "qgroup.h"
#include "transaction.h"
#include <linux/bio.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/buffer_head.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/compat.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/falloc.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/btrfs.h>
#include <linux/blkdev.h>
#include <linux/posix_acl_xattr.h>
#include <linux/uio.h>
#include <linux/magic.h>
#include <linux/iversion.h>
#include <asm/unaligned.h>
#include "ctree.h"
#include "disk-io.h"
#include "transaction.h"
#include "btrfs_inode.h"
#include "print-tree.h"
#include "ordered-data.h"
#include "xattr.h"
#include "tree-log.h"
#include "volumes.h"
#include "compression.h"
#include "locking.h"
#include "free-space-cache.h"
#include "inode-map.h"
#include "backref.h"
#include "props.h"
#include "qgroup.h"
#include "dedupe.h"
#include "extent_io.h"
u64 hash_value_calc(u8 * hash)
{
	int i=0;
	u64 ret = 1;
	for(i=0;i<32;++i)
	{
		ret = ((u64)hash[i]*(ret+1)+1)%(19990317);
	}
	return ret;
}

struct inmem_hash {
	struct rb_node bytenr_node;
	u64 bytenr;
	u32 num_bytes;
	struct inmem_hash_entry * hash_arr[3];
};

struct inmem_hash_entry {
	struct rb_node hash_node;
	struct list_head lru_list;

	u64 bytenr;
	u32 num_bytes;

	u8 type; 
	u64 burst_index;
	u8 hash[32];
};

static inline struct inmem_hash *inmem_alloc_hash(u16 algo)
{
	// @ remember to destroy, avoid from memory leak.
	struct inmem_hash_entry * tmp[3];
	struct inmem_hash * hs = kzalloc(sizeof(struct inmem_hash), GFP_NOFS);
	int i;
	for(i = 0;i<3;++i)
	{
		tmp[i] =  kzalloc(sizeof(struct inmem_hash_entry) + btrfs_hash_sizes[algo],GFP_NOFS);
		hs->hash_arr[i] = tmp[i];
	}

	if (WARN_ON(algo >= ARRAY_SIZE(btrfs_hash_sizes)))
		return NULL;
	return hs;
}

/*
 * Copy from current dedupe info to fill dargs.
 * For reconf case, only fill members which is uninitialized.
 */
static void get_dedupe_status(struct btrfs_dedupe_info *dedupe_info,
			      struct btrfs_ioctl_dedupe_args *dargs)
{
	int reconf = (dargs->cmd == BTRFS_DEDUPE_CTL_RECONF);

	dargs->status = 1;

	if (!reconf || (reconf && dargs->blocksize == (u64)-1))
		dargs->blocksize = dedupe_info->blocksize;
	if (!reconf || (reconf && dargs->backend == (u16)-1))
		dargs->backend = dedupe_info->backend;
	if (!reconf || (reconf && dargs->hash_algo == (u16)-1))
		dargs->hash_algo = dedupe_info->hash_algo;

	/*
	 * For re-configure case, if not modifying limit,
	 * therir limit will be set to 0, unlike other fields
	 */
	if (!reconf || !(dargs->limit_nr || dargs->limit_mem)) {
		dargs->limit_nr = dedupe_info->limit_nr;
		dargs->limit_mem = dedupe_info->limit_nr *
			(sizeof(struct inmem_hash) +
			 btrfs_hash_sizes[dedupe_info->hash_algo]);
	}

	/* current_nr doesn't makes sense for reconfig case */
	// if (!reconf)
	// 	dargs->current_nr = dedupe_info->current_nr;
}

void btrfs_dedupe_status(struct btrfs_fs_info *fs_info,
			 struct btrfs_ioctl_dedupe_args *dargs)
{
	struct btrfs_dedupe_info *dedupe_info = fs_info->dedupe_info;

	if (!fs_info->dedupe_enabled || !dedupe_info) {
		dargs->status = 0;
		dargs->blocksize = 0;
		dargs->backend = 0;
		dargs->hash_algo = 0;
		dargs->limit_nr = 0;
		dargs->current_nr = 0;
		memset(dargs->__unused, -1, sizeof(dargs->__unused));
		return;
	}
	mutex_lock(&dedupe_info->lock);
	get_dedupe_status(dedupe_info, dargs);
	mutex_unlock(&dedupe_info->lock);
	memset(dargs->__unused, -1, sizeof(dargs->__unused));
}

static struct btrfs_dedupe_info *
init_dedupe_info(struct btrfs_ioctl_dedupe_args *dargs)
{
	struct btrfs_dedupe_info *dedupe_info;
	int i;
	dedupe_info = kzalloc(sizeof(*dedupe_info), GFP_NOFS);
	if (!dedupe_info)
		return ERR_PTR(-ENOMEM);

	dedupe_info->hash_algo = dargs->hash_algo;
	dedupe_info->backend = dargs->backend;
	dedupe_info->blocksize = dargs->blocksize;
	dedupe_info->limit_nr = dargs->limit_nr;

	/* only support SHA256 yet */
	dedupe_info->dedupe_driver = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(dedupe_info->dedupe_driver)) {
		kfree(dedupe_info);
		return ERR_CAST(dedupe_info->dedupe_driver);
	}
	for(i =0;i<3;++i) 
	{
		dedupe_info->hash_root[i] = RB_ROOT;
		INIT_LIST_HEAD(&dedupe_info->lru_list[i]);
		dedupe_info->current_nr[i] = 0;
	}
	dedupe_info->bytenr_root = RB_ROOT;
	dedupe_info->head_len = 1024;

	mutex_init(&dedupe_info->lock);

	return dedupe_info;
}

/*
 * Helper to check if parameters are valid.
 * The first invalid field will be set to (-1), to info user which parameter
 * is invalid.
 * Except dargs->limit_nr or dargs->limit_mem, in that case, 0 will returned
 * to info user, since user can specify any value to limit, except 0.
 */
static int check_dedupe_parameter(struct btrfs_fs_info *fs_info,
				  struct btrfs_ioctl_dedupe_args *dargs)
{
	struct btrfs_dedupe_info *dedupe_info = fs_info->dedupe_info;

	u64 blocksize;
	u64 limit_nr;
	u64 limit_mem;
	u16 hash_algo;
	u8 backend;

	/*
	 * Set all reserved fields to -1, allow user to detect
	 * unsupported optional parameters.
	 */
	memset(dargs->__unused, -1, sizeof(dargs->__unused));

	/*
	 * For dedupe enabled fs, enable without FORCE flag is not allowed
	 */
	if (dargs->cmd == BTRFS_DEDUPE_CTL_ENABLE && dedupe_info &&
	    !(dargs->flags & BTRFS_DEDUPE_FLAG_FORCE)) {
		dargs->status = 1;
		dargs->flags = (u8)-1;
		return -EINVAL;
	}

	/* Check and copy parameters from existing dedupe info */
	if (dargs->cmd == BTRFS_DEDUPE_CTL_RECONF) {
		if (!dedupe_info) {
			/* Info caller that dedupe is not enabled */
			dargs->status = 0;
			return -EINVAL;
		}
		get_dedupe_status(dedupe_info, dargs);
		/*
		 * All unmodified parameter are already copied out
		 * go through normal validation check.
		 */
	}

	blocksize = dargs->blocksize;
	limit_nr = dargs->limit_nr;
	limit_mem = dargs->limit_mem;
	hash_algo = dargs->hash_algo;
	backend = dargs->backend;

	if (blocksize > BTRFS_DEDUPE_BLOCKSIZE_MAX ||
	    blocksize < BTRFS_DEDUPE_BLOCKSIZE_MIN ||
	    blocksize < fs_info->sectorsize ||
	    !is_power_of_2(blocksize) ||
	    blocksize < PAGE_SIZE) {
		dargs->blocksize = (u64)-1;
		return -EINVAL;
	}
	if (hash_algo >= ARRAY_SIZE(btrfs_hash_sizes)) {
		dargs->hash_algo = (u16)-1;
		return -EINVAL;
	}
	if (backend >= BTRFS_DEDUPE_BACKEND_COUNT) {
		dargs->backend = (u8)-1;
		return -EINVAL;
	}

	/* Backend specific check */
	if (backend == BTRFS_DEDUPE_BACKEND_INMEMORY) {
		/* only one limit is accepted for enable*/
		if (dargs->cmd == BTRFS_DEDUPE_CTL_ENABLE &&
		    dargs->limit_nr && dargs->limit_mem) {
			dargs->limit_nr = 0;
			dargs->limit_mem = 0;
			return -EINVAL;
		}

		if (!limit_nr && !limit_mem)
			dargs->limit_nr = BTRFS_DEDUPE_LIMIT_NR_DEFAULT;
		else {
			u64 tmp = (u64)-1;

			if (limit_mem) {
				tmp = div_u64(limit_mem,
					(sizeof(struct inmem_hash)) +
					btrfs_hash_sizes[hash_algo]);
				/* Too small limit_mem to fill a hash item */
				if (!tmp) {
					dargs->limit_mem = 0;
					dargs->limit_nr = 0;
					return -EINVAL;
				}
			}
			if (!limit_nr)
				limit_nr = (u64)-1;

			dargs->limit_nr = min(tmp, limit_nr);
		}
	}
	if (backend == BTRFS_DEDUPE_BACKEND_ONDISK)
		dargs->limit_nr = 0;

	return 0;
}

/*
 * Enable or re-configure dedupe.
 *
 * Caller must call check_dedupe_parameters first
 */
static int enable_reconfig_dedupe(struct btrfs_fs_info *fs_info,
				  struct btrfs_ioctl_dedupe_args *dargs)
{
	struct btrfs_dedupe_info *dedupe_info = fs_info->dedupe_info;

	if (dedupe_info) {

		/* Check if we are re-enable for different dedupe config */
		if (dedupe_info->blocksize != dargs->blocksize ||
		    dedupe_info->hash_algo != dargs->hash_algo ||
		    dedupe_info->backend != dargs->backend) {
			btrfs_dedupe_disable(fs_info);
			goto enable;
		}

		/* On-fly limit change is OK */
		mutex_lock(&dedupe_info->lock);
		fs_info->dedupe_info->limit_nr = dargs->limit_nr;
		mutex_unlock(&dedupe_info->lock);
		return 0;
	}

enable:
	dedupe_info = init_dedupe_info(dargs);
	if (IS_ERR(dedupe_info))
		return PTR_ERR(dedupe_info);
	fs_info->dedupe_info = dedupe_info;
	/* We must ensure dedupe_bs is modified after dedupe_info */
	smp_wmb();
	fs_info->dedupe_enabled = 1;
	return 0;
}

int btrfs_dedupe_enable(struct btrfs_fs_info *fs_info,
			struct btrfs_ioctl_dedupe_args *dargs)
{
	int ret = 0;
	{
		PDebug("dedupe enabled\n");
	}
	ret = check_dedupe_parameter(fs_info, dargs);
	if (ret < 0)
		return ret;
	return enable_reconfig_dedupe(fs_info, dargs);
}

int btrfs_dedupe_reconfigure(struct btrfs_fs_info *fs_info,
			     struct btrfs_ioctl_dedupe_args *dargs)
{
	/*
	 * btrfs_dedupe_enable will handle everything well,
	 * since dargs contains all info we need to distinguish enable
	 * and reconfigure
	 */
	return btrfs_dedupe_enable(fs_info, dargs);
}

// @ support insert in different tree.
// @ hash holds two message
static int inmem_insert_hash(struct btrfs_dedupe_info *dedupe_info,
			     struct inmem_hash *Hash, int hash_len)
{
	int i,ret = 0;
	for (i =0 ;i<3;++i)
	{
		struct rb_node **p = &(dedupe_info->hash_root[i].rb_node);
		struct rb_node *parent = NULL;
		struct inmem_hash_entry *entry = NULL;
		struct inmem_hash_entry *hash = Hash->hash_arr[i];
		{
			PDebug("Insert into %d tree, bytenr:%d hash:%llu\n",i,hash->bytenr,hash_value_calc(hash->hash));
		}

		while (*p) {
			parent = *p;
			entry = rb_entry(parent, struct inmem_hash_entry, hash_node);
			if (memcmp(hash->hash, entry->hash, hash_len) < 0)
				p = &(*p)->rb_left;
			else if (memcmp(hash->hash, entry->hash, hash_len) > 0)
				p = &(*p)->rb_right;
			else
			{
				ret += 1;
				break;
			}
		}
		rb_link_node(&hash->hash_node, parent, p);
		rb_insert_color(&hash->hash_node, &dedupe_info->hash_root[i]);
		
	}
	// int ret = 0;
	

	// {
	// 	PDebug("Insert into head tree, bytenr:%d numbytes:%d hash:%llu hash_h: %llu\n",hash->bytenr,hash->num_bytes,hash_value_calc(hash->hash),hash_value_calc(hash->hash_h));

	// 	struct rb_node **p = &(dedupe_info->hash_root_h.rb_node);
	// 	struct rb_node *parent = NULL;
	// 	struct inmem_hash *entry = NULL;

	// 	while (*p) {
	// 		parent = *p;
	// 		entry = rb_entry(parent, struct inmem_hash, hash_h_node);
	// 		if (memcmp(hash->hash_h, entry->hash_h, hash_len) < 0)
	// 			p = &(*p)->rb_left;
	// 		else if (memcmp(hash->hash_h, entry->hash_h, hash_len) > 0)
	// 			p = &(*p)->rb_right;
	// 		else
	// 		{
	// 			ret += 2;
	// 			break;
	// 		}
	// 	}
	// 	rb_link_node(&hash->hash_h_node, parent, p);
	// 	rb_insert_color(&hash->hash_h_node, &dedupe_info->hash_root_h);

	// 	{ 
	// 		if(p)
	// 			PDebug("p:%p *p:%p\n",p,*p);
	// 		else
	// 			PDebug("p null.\n");

	// 		if(&hash->hash_h_node)
	// 			PDebug("&hash->hash_h_node:%p\n",&hash->hash_h_node);
	// 		else
	// 			PDebug("&hash->hash_h_node null.\n");
			
	// 		PDebug("Insert result in head tree, hashv: %lld\n",hash_value_calc(hash->hash_h)); }
	// 	// {
	// 	// 	PDebug("Insert into head tree entryP: %p after: %p hash:%llu hash_h: %llu\n",&hash->hash_h_node, *p,hash_value_calc(*p->hash),hash_value_calc(hash->hash_h));
	// 	// }
	// }
	return ret;
}

static int inmem_insert_bytenr(struct rb_root *root,
			       struct inmem_hash *hash)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct inmem_hash *entry = NULL;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct inmem_hash, bytenr_node);
		if (hash->bytenr < entry->bytenr)
			p = &(*p)->rb_left;
		else if (hash->bytenr > entry->bytenr)
			p = &(*p)->rb_right;
		else
			return 1;
	}
	rb_link_node(&hash->bytenr_node, parent, p);
	rb_insert_color(&hash->bytenr_node, root);
	return 0;
}

static void __inmem_del(struct btrfs_dedupe_info *dedupe_info,
			struct inmem_hash *hash)
{
	//@ when?
	int i;
	for(i =0 ;i<3;++i)
	{
		list_del(&hash->hash_arr[i]->lru_list);
		if (!WARN_ON(dedupe_info->current_nr == 0))
			dedupe_info->current_nr[i]--;
		rb_erase(&hash->hash_arr[i]->hash_node, &dedupe_info->hash_root[i]);
	}
	rb_erase(&hash->bytenr_node, &dedupe_info->bytenr_root);
	// @ not kfree.
	kfree(hash);
}

static void __inmem_del_indiv(struct btrfs_dedupe_info *dedupe_info,
			struct inmem_hash_entry *hash,int p)
{
	//@ when?

	list_del(&hash->lru_list);
	if (!WARN_ON(dedupe_info->current_nr == 0))
		dedupe_info->current_nr[p]--;
	rb_erase(&hash->hash_node, &dedupe_info->hash_root[p]);
	// rb_erase(&hash->bytenr_node, &dedupe_info->bytenr_root);
	// @ not kfree.
	kfree(hash);
}
/*
 * Insert a hash into in-memory dedupe tree
 * Will remove exceeding last recent use hash.
 *
 * If the hash mathced with existing one, we won't insert it, to
 * save memory
 */
static int inmem_add(struct btrfs_dedupe_info *dedupe_info,
		     struct btrfs_dedupe_hash *hash)
{
	int ret = 0;
	int i =0;
	u16 algo = dedupe_info->hash_algo;
	struct inmem_hash *ihash;

	ihash = inmem_alloc_hash(algo);
	if (!ihash)
		return -ENOMEM;

	/* Copy the data out */
	for(i = 0;i<3;++i)
	{
		if(WARN_ON(!hash->hash_arr[i]))
		{
			continue;
		}
		ihash->hash_arr[i]->bytenr = hash->hash_arr[i]->bytenr;
		ihash->hash_arr[i]->num_bytes = hash->hash_arr[i]->num_bytes;
		memcpy(ihash->hash_arr[i]->hash, hash->hash_arr[i]->hash, btrfs_hash_sizes[algo]);
	}

	mutex_lock(&dedupe_info->lock);

	ret = inmem_insert_bytenr(&dedupe_info->bytenr_root, ihash);
	if (ret > 0) {
		WARN_ON(ret>0);
		kfree(ihash);
		ret = 0;
		goto out;
	}

	ret = inmem_insert_hash(dedupe_info, ihash,
				btrfs_hash_sizes[algo]);
	
	WARN_ON(ret>0);
		/*
		 * We only keep one hash in tree to save memory, so if
		 * hash conflicts, free the one to insert.
		 */
	// 	rb_erase(&ihash->bytenr_node, &dedupe_info->bytenr_root);
	// 	kfree(ihash);
	// 	ret = 0;
	// 	goto out;
	// }

	for(i=0;i<3;++i) {
		list_add(&ihash->hash_arr[i]->lru_list, &dedupe_info->lru_list[i]);
		dedupe_info->current_nr[i]++;
		while (dedupe_info->current_nr[i] > dedupe_info->limit_nr) {
			struct inmem_hash_entry *last;

			last = list_entry(dedupe_info->lru_list[i].prev,
					struct inmem_hash_entry, lru_list);
			__inmem_del_indiv(dedupe_info, last,i);
		}
	}



	/* Remove the last dedupe hash if we exceed limit */
	
out:
	mutex_unlock(&dedupe_info->lock);
	return 0;
}

int btrfs_dedupe_add(struct btrfs_fs_info *fs_info,
		     struct btrfs_dedupe_hash *hash)
{
	struct btrfs_dedupe_info *dedupe_info = fs_info->dedupe_info;

	if (!fs_info->dedupe_enabled || !hash)
		return 0;

	if (WARN_ON(dedupe_info == NULL))
		return -EINVAL;

	if (WARN_ON(!btrfs_dedupe_hash_hit(hash)))
		return -EINVAL;

	/* ignore old hash */
	//if (dedupe_info->blocksize != hash->hash_arr[0]->num_bytes)
	//	return 0;
{ PDebug("2");}
	if (dedupe_info->backend == BTRFS_DEDUPE_BACKEND_INMEMORY)
		return inmem_add(dedupe_info, hash);
	return -EINVAL;
}

static struct inmem_hash *
inmem_search_bytenr(struct btrfs_dedupe_info *dedupe_info, u64 bytenr)
{
	struct rb_node **p = &dedupe_info->bytenr_root.rb_node;
	struct rb_node *parent = NULL;
	int i =0 ;
	struct inmem_hash *hash = kzalloc(sizeof(struct inmem_hash), GFP_NOFS);
	struct inmem_hash *entry;
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct inmem_hash, bytenr_node);

		if (bytenr < entry->bytenr)
			p = &(*p)->rb_left;
		else if (bytenr > entry->bytenr)
			p = &(*p)->rb_right;
		else
		{
			for(i =0;i<3;++i)
				hash->hash_arr[i] = entry->hash_arr[i];
			return hash;
		}
	}
	return NULL;
}

/* Delete a hash from in-memory dedupe tree */
static int inmem_del(struct btrfs_dedupe_info *dedupe_info, u64 bytenr)
{
	struct inmem_hash *hash;

	mutex_lock(&dedupe_info->lock);
	hash = inmem_search_bytenr(dedupe_info, bytenr);
	if (!hash) {
		mutex_unlock(&dedupe_info->lock);
		return 0;
	}

	__inmem_del(dedupe_info, hash);
	mutex_unlock(&dedupe_info->lock);
	return 0;
}

/* Remove a dedupe hash from dedupe tree */
int btrfs_dedupe_del(struct btrfs_fs_info *fs_info, u64 bytenr)
{
	struct btrfs_dedupe_info *dedupe_info = fs_info->dedupe_info;

	if (!fs_info->dedupe_enabled)
		return 0;

	if (WARN_ON(dedupe_info == NULL))
		return -EINVAL;

	if (dedupe_info->backend == BTRFS_DEDUPE_BACKEND_INMEMORY)
		return inmem_del(dedupe_info, bytenr);
	return -EINVAL;
}

static void inmem_destroy(struct btrfs_dedupe_info *dedupe_info)
{
	struct inmem_hash_entry *entry, *tmp;
	int i;
	mutex_lock(&dedupe_info->lock);
	for(i=0;i<3;++i)
	{
		list_for_each_entry_safe(entry, tmp, &dedupe_info->lru_list[i], lru_list)
			__inmem_del_indiv(dedupe_info, entry,i);
	}
	mutex_unlock(&dedupe_info->lock);
}

/*
 * Helper function to wait and block all incoming writers
 *
 * Use rw_sem introduced for freeze to wait/block writers.
 * So during the block time, no new write will happen, so we can
 * do something quite safe, espcially helpful for dedupe disable,
 * as it affect buffered write.
 */
static void block_all_writers(struct btrfs_fs_info *fs_info)
{
	struct super_block *sb = fs_info->sb;

	percpu_down_write(sb->s_writers.rw_sem + SB_FREEZE_WRITE - 1);
	down_write(&sb->s_umount);
}

static void unblock_all_writers(struct btrfs_fs_info *fs_info)
{
	struct super_block *sb = fs_info->sb;

	up_write(&sb->s_umount);
	percpu_up_write(sb->s_writers.rw_sem + SB_FREEZE_WRITE - 1);
}

int btrfs_dedupe_cleanup(struct btrfs_fs_info *fs_info)
{
	struct btrfs_dedupe_info *dedupe_info;

	fs_info->dedupe_enabled = 0;
	/* same as disable */
	smp_wmb();
	dedupe_info = fs_info->dedupe_info;
	fs_info->dedupe_info = NULL;

	if (!dedupe_info)
		return 0;

	if (dedupe_info->backend == BTRFS_DEDUPE_BACKEND_INMEMORY)
		inmem_destroy(dedupe_info);

	crypto_free_shash(dedupe_info->dedupe_driver);
	kfree(dedupe_info);
	return 0;
}

int btrfs_dedupe_disable(struct btrfs_fs_info *fs_info)
{
	struct btrfs_dedupe_info *dedupe_info;
	int ret;

	dedupe_info = fs_info->dedupe_info;

	if (!dedupe_info)
		return 0;

	/* Don't allow disable status change in RO mount */
	if (fs_info->sb->s_flags & MS_RDONLY)
		return -EROFS;

	/*
	 * Wait for all unfinished writers and block further writers.
	 * Then sync the whole fs so all current write will go through
	 * dedupe, and all later write won't go through dedupe.
	 */
	block_all_writers(fs_info);
	ret = sync_filesystem(fs_info->sb);
	fs_info->dedupe_enabled = 0;
	fs_info->dedupe_info = NULL;
	unblock_all_writers(fs_info);
	if (ret < 0)
		return ret;

	/* now we are OK to clean up everything */
	if (dedupe_info->backend == BTRFS_DEDUPE_BACKEND_INMEMORY)
		inmem_destroy(dedupe_info);

	crypto_free_shash(dedupe_info->dedupe_driver);
	kfree(dedupe_info);
	return 0;
}

/*
 * Caller must ensure the corresponding ref head is not being run.
 */
int 
inmem_search_hash(struct btrfs_dedupe_info *dedupe_info, struct btrfs_dedupe_hash * Hash)
{
	int i,ret = 0;
	for(i=0;i<3;++i)
	{
		struct rb_node **p = &dedupe_info->hash_root[i].rb_node;
		struct rb_node *parent = NULL;
		struct inmem_hash_entry *entry = NULL;
		struct btrfs_dedupe_hash_entry *hash = Hash->hash_arr[i];
		u16 hash_algo = dedupe_info->hash_algo;
		int hash_len = btrfs_hash_sizes[hash_algo];

		{
			PDebug("Search in %d tree, bytenr:%d hash:%llu\n",i,hash->bytenr,hash_value_calc(hash->hash));
		}
		while (*p) {
			parent = *p;
			entry = rb_entry(parent, struct inmem_hash_entry, hash_node);

			if (memcmp(hash->hash, entry->hash, hash_len) < 0) {
				p = &(*p)->rb_left;
			} else if (memcmp(hash->hash, entry->hash, hash_len) > 0) {
				p = &(*p)->rb_right;
			} else {
				/* Found, need to re-add it to LRU list head */
				{
					PDebug("Found in %d tree, hash:%llu \n",i,hash_value_calc(hash->hash));
				}
				list_del(&entry->lru_list);
				list_add(&entry->lru_list, &dedupe_info->lru_list[i]);
				hash->bytenr = entry->bytenr;
				hash->num_bytes = entry->num_bytes;

				ret=i+1;
				goto ed;
			}
		}
	}
	ed:
	return ret;
}

static int inmem_search(struct btrfs_dedupe_info *dedupe_info,
			struct inode *inode, u64 file_pos,
			struct btrfs_dedupe_hash *hash)
{
	int ret;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_trans_handle *trans;
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_delayed_ref_head *head;
	struct btrfs_delayed_ref_head *insert_head;
	struct btrfs_delayed_data_ref *insert_dref;
	struct btrfs_qgroup_extent_record *insert_qrecord = NULL;
	int found_hash;
	int free_insert = 1;
	int qrecord_inserted = 0;
	u64 ref_root = root->root_key.objectid;
	u64 bytenr;
	u32 num_bytes;

	insert_head = kmem_cache_alloc(btrfs_delayed_ref_head_cachep, GFP_NOFS);
	if (!insert_head)
		return -ENOMEM;
	insert_head->extent_op = NULL;

	insert_dref = kmem_cache_alloc(btrfs_delayed_data_ref_cachep, GFP_NOFS);
	if (!insert_dref) {
		kmem_cache_free(btrfs_delayed_ref_head_cachep, insert_head);
		return -ENOMEM;
	}
	if (test_bit(BTRFS_FS_QUOTA_ENABLED, &root->fs_info->flags) &&
	    is_fstree(ref_root)) {
		insert_qrecord = kmalloc(sizeof(*insert_qrecord), GFP_NOFS);
		if (!insert_qrecord) {
			kmem_cache_free(btrfs_delayed_ref_head_cachep,
					insert_head);
			kmem_cache_free(btrfs_delayed_data_ref_cachep,
					insert_dref);
			return -ENOMEM;
		}
	}

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto free_mem;
	}

again:
	mutex_lock(&dedupe_info->lock);
	{
		// PDebug("Search in full tree, bytenr:%d numbytes:%d hash:%llu hash_h: %llu hash_h's p: %p\n",hash->bytenr,hash->num_bytes,hash_value_calc(hash->hash),hash_value_calc(hash->hash_h),hash->hash_h);
	}

	found_hash = inmem_search_hash(dedupe_info, hash);
	/* If we don't find a duplicated extent, just return. */
	
	//@ add in the only place
	if (!found_hash) {
		{
			// PDebug("Can't found in two tree, bytenr:%d numbytes:%d hash:%llu hash_h: %llu\n",hash->bytenr,hash->num_bytes,hash_value_calc(hash->hash),hash_value_calc(hash->hash_h));
		}
		ret = 0;
		goto out;
	}

	bytenr = hash->hash_arr[found_hash-1]->bytenr;
	num_bytes = hash->hash_arr[found_hash-1]->num_bytes;

	btrfs_init_delayed_ref_head(insert_head, insert_qrecord, bytenr,
			num_bytes, ref_root, 0, BTRFS_ADD_DELAYED_REF, true,
			false);

	btrfs_init_delayed_ref_common(trans->fs_info, &insert_dref->node,
			bytenr, num_bytes, ref_root, BTRFS_ADD_DELAYED_REF,
			BTRFS_EXTENT_DATA_REF_KEY);
	insert_dref->root = ref_root;
	insert_dref->parent = 0;
	insert_dref->objectid = btrfs_ino(BTRFS_I(inode));
	insert_dref->offset = file_pos;

	delayed_refs = &trans->transaction->delayed_refs;

	spin_lock(&delayed_refs->lock);
	head = btrfs_find_delayed_ref_head(&trans->transaction->delayed_refs,
					   bytenr);
	if (!head) {
		/*
		 * We can safely insert a new delayed_ref as long as we
		 * hold delayed_refs->lock.
		 * Only need to use atomic inc_extent_ref()
		 */
		btrfs_add_delayed_data_ref_locked(trans, insert_head,
				insert_qrecord, insert_dref,
				BTRFS_ADD_DELAYED_REF, &qrecord_inserted, NULL,
				NULL);
		spin_unlock(&delayed_refs->lock);

		trace_add_delayed_data_ref(trans->fs_info, &insert_dref->node,
				insert_dref, BTRFS_ADD_DELAYED_REF);

		if (ret > 0)
			kmem_cache_free(btrfs_delayed_data_ref_cachep,
					insert_dref);

		/* add_delayed_data_ref_locked will free unused memory */
		free_insert = 0;
	//	hash->bytenr = bytenr;
		//hash->num_bytes = num_bytes;
		ret = 1;
		goto out;
	}

	/*
	 * We can't lock ref head with dedupe_info->lock hold or we will cause
	 * ABBA dead lock.
	 */
	mutex_unlock(&dedupe_info->lock);
	ret = btrfs_delayed_ref_lock(delayed_refs, head);
	spin_unlock(&delayed_refs->lock);

	if (ret == -EAGAIN)
		goto again;

	mutex_lock(&dedupe_info->lock);
	/* Search again to ensure the hash is still here */
	found_hash = inmem_search_hash(dedupe_info, hash);
	if (!found_hash) {
		ret = 0;
		mutex_unlock(&head->mutex);
		goto out;
	}
	ret = 1;
	// hash->bytenr = bytenr;
	// hash->num_bytes = num_bytes;

	/*
	 * Increase the extent ref right now, to avoid delayed ref run
	 * Or we may increase ref on non-exist extent.
	 */
	btrfs_inc_extent_ref(trans, root, bytenr, num_bytes, 0,
			     ref_root,
			     btrfs_ino(BTRFS_I(inode)), file_pos);
	mutex_unlock(&head->mutex);
out:
	mutex_unlock(&dedupe_info->lock);
	btrfs_end_transaction(trans);

free_mem:
	if (free_insert) {
		kmem_cache_free(btrfs_delayed_ref_head_cachep, insert_head);
		kmem_cache_free(btrfs_delayed_data_ref_cachep, insert_dref);
	}
	if (!qrecord_inserted)
		kfree(insert_qrecord);
	return ret;
}

int btrfs_dedupe_search(struct btrfs_fs_info *fs_info,
			struct inode *inode, u64 file_pos,
			struct btrfs_dedupe_hash *hash)
{
	struct btrfs_dedupe_info *dedupe_info = fs_info->dedupe_info;
	int ret = -EINVAL;

	if (!hash)
		return 0;

	/*
	 * This function doesn't follow fs_info->dedupe_enabled as it will need
	 * to ensure any hashed extent to go through dedupe routine
	 */
	if (WARN_ON(dedupe_info == NULL))
		return -EINVAL;

	if (WARN_ON(btrfs_dedupe_hash_hit(hash)))
		return -EINVAL;

	if (dedupe_info->backend == BTRFS_DEDUPE_BACKEND_INMEMORY)
		ret = inmem_search(dedupe_info, inode, file_pos, hash);

	/* It's possible hash->bytenr/num_bytenr already changed */
	// if (ret == 0) {
	// 	hash->num_bytes = 0;
	// 	hash->bytenr = 0;
	// }
	return ret;
}

int btrfs_dedupe_calc_hash(struct btrfs_fs_info *fs_info,
			   struct inode *inode, u64 start,
			   struct btrfs_dedupe_hash *hash)
{
	int i;
	int ret;
	struct page *p;
	struct shash_desc *shash;
	struct btrfs_dedupe_info *dedupe_info = fs_info->dedupe_info;
	struct crypto_shash *tfm = dedupe_info->dedupe_driver;
	u64 dedupe_bs;
	u64 sectorsize = fs_info->sectorsize;

	shash = kmalloc(sizeof(*shash) + crypto_shash_descsize(tfm), GFP_NOFS);
	if (!shash)
		return -ENOMEM;

	if (!fs_info->dedupe_enabled || !hash)
		return 0;

	if (WARN_ON(dedupe_info == NULL))
		return -EINVAL;

	WARN_ON(!IS_ALIGNED(start, sectorsize));

	dedupe_bs = dedupe_info->blocksize;

	shash->tfm = tfm;
	shash->flags = 0;
	
	ret = crypto_shash_init(shash);
	if (ret)
		return ret;
	// @ for head
	{
		char *d;
		p = find_get_page(inode->i_mapping,
				  (start >> PAGE_SHIFT));
		if (WARN_ON(!p)) 
			return -ENOENT;
		d = kmap(p);
		ret = crypto_shash_update(shash, d, dedupe_info->head_len);
		kunmap(p);
		put_page(p);
		ret = crypto_shash_final(shash, hash->hash_arr[1]->hash);
		if (ret)
			return ret;
		for(i=0;i<32;++i)
		{
			// printk("{%d} ",hash->hash_h[i]);
		}
	}
	for (i = 0; sectorsize * i < dedupe_bs; i++) {
		char *d;
		// @ watch this!
		// @ may have question.
		p = find_get_page(inode->i_mapping,
				  (start >> PAGE_SHIFT) + i);
		if (WARN_ON(!p))
			return -ENOENT;
		d = kmap(p);
		ret = crypto_shash_update(shash, d, sectorsize);
		kunmap(p);
		put_page(p);
		if (ret)
			return ret;
	}
	ret = crypto_shash_final(shash, hash->hash_arr[0]->hash);
	{
		// @ tail,offset error.
		char *d;
		p = find_get_page(inode->i_mapping,
				  (start >> PAGE_SHIFT)+i-1);
		if (WARN_ON(!p)) 
			return -ENOENT;
		d = kmap(p);
		ret = crypto_shash_update(shash, d, dedupe_info->head_len);
		kunmap(p);
		put_page(p);
		ret = crypto_shash_final(shash, hash->hash_arr[2]->hash);
		if (ret)
			return ret;
		for(i=0;i<32;++i)
		{
			// printk("{%d} ",hash->hash_h[i]);
		}
	}
	return ret;
}
void my_readComplete(struct bio * bio)
{
	struct bio_vec *bvec;
	int uptodate = !bio->bi_status;
	u64 offset = 0;
	u64 start;
	u64 end;
	u64 len;
	u64 extent_start = 0;
	u64 extent_len = 0;
	int mirror;
	int ret;
	int i;

	ASSERT(!bio_flagged(bio, BIO_CLONED));
	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;
		char * buf;
		buf = kmap(page);
		PDebug(" new : %c-%c-%c-%c-%c-%c\n",buf[0],buf[1],buf[2],buf[1023],buf[1024],buf[1025]);


	}	
	PDebug("end the complete\n");
}
int my_readPage(struct block_device *device, sector_t sector, int size,
     struct page *page)
{
    int ret;
    struct completion event;
    struct bio *bio = btrfs_bio_alloc(device, sector); 
	bio->bi_opf = REQ_OP_READ;
    bio_add_page(bio, page, size, 0);
    init_completion(&event);
    bio->bi_private = &event;
    bio->bi_end_io = my_readComplete;
    submit_bio(bio);
    wait_for_completion(&event);
	PDebug("io end");
    bio_put(bio);
    return ret;
}