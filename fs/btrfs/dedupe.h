/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2016 Fujitsu.  All rights reserved.
 */

#ifndef BTRFS_DEDUPE_H
#define BTRFS_DEDUPE_H

#include <crypto/hash.h>
#include "btrfs_inode.h"

/* 32 bytes for SHA256 */
static const int btrfs_hash_sizes[] = { 32 };

/*
 * For caller outside of dedupe.c
 *
 * Different dedupe backends should have their own hash structure
 */
struct btrfs_dedupe_hash {
	u64 bytenr;
	u32 num_bytes;


	u8 type; 
	u64 burst_index;
	/* last field is a variable length array of dedupe hash */
	// @ fixed to sha256
	u8 hash[32];
	u8 hash_h[32];
};

struct burst{
	char * ptr;
	u64 len;
};
struct btrfs_dedupe_info {
	/* dedupe blocksize */
	u64 blocksize;
	u16 backend;
	u16 hash_algo;

	struct crypto_shash *dedupe_driver;

	/*
	 * Use mutex to portect both backends
	 * Even for in-memory backends, the rb-tree can be quite large,
	 * so mutex is better for such use case.
	 */
	struct mutex lock;

	/* following members are only used in in-memory backend */
	struct rb_root hash_root;
	struct rb_root bytenr_root;

	struct rb_root hash_root_h;
	struct rb_root bytenr_root_h;
	int head_len;
	struct burst * burst_arr;

	struct list_head lru_list;
	u64 limit_nr;
	u64 current_nr;
};

char * burst_gen(struct page *);

static inline u64 btrfs_dedupe_blocksize(struct btrfs_inode *inode)
{
	struct btrfs_fs_info *fs_info = inode->root->fs_info;

	return fs_info->dedupe_info->blocksize;
}

static inline int inode_need_dedupe(struct inode *inode)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;

	return fs_info->dedupe_enabled;
}

static inline int btrfs_dedupe_hash_hit(struct btrfs_dedupe_hash *hash)
{
	return (hash && hash->bytenr);
}

// static inline int btrfs_dedupe_hash_hit(struct btrfs_dedupe_hash *hash)
// {
// 	return (hash && hash->bytenr);
// }

static inline int btrfs_dedupe_hash_size(u16 algo)
{
	if (WARN_ON(algo >= ARRAY_SIZE(btrfs_hash_sizes)))
		return -EINVAL;
	return sizeof(struct btrfs_dedupe_hash) + btrfs_hash_sizes[algo]+btrfs_hash_sizes[algo];
}

static inline struct btrfs_dedupe_hash *btrfs_dedupe_alloc_hash(u16 algo)
{
	return kzalloc(btrfs_dedupe_hash_size(algo), GFP_NOFS);
}

/*
 * Initial inband dedupe info
 * Called at dedupe enable time.
 *
 * Return 0 for success
 * Return <0 for any error
 * (from unsupported param to tree creation error for some backends)
 */
int btrfs_dedupe_enable(struct btrfs_fs_info *fs_info,
			struct btrfs_ioctl_dedupe_args *dargs);

/*
 * Reconfigure given parameter for dedupe
 * Can only be called when dedupe is already enabled
 *
 * dargs member which don't need to be modified should be left
 * with 0 for limit_nr/limit_offset or -1 for other fields
 *
 * Return 0 for success
 * Return <0 for any error
 * (Same error return value with dedupe_enable)
 */
int btrfs_dedupe_reconfigure(struct btrfs_fs_info *fs_info,
			     struct btrfs_ioctl_dedupe_args *dargs);

/*
 * Get inband dedupe info
 * Since it needs to access different backends' hash size, which
 * is not exported, we need such simple function.
 */
void btrfs_dedupe_status(struct btrfs_fs_info *fs_info,
			 struct btrfs_ioctl_dedupe_args *dargs);

/*
 * Disable dedupe and invalidate all its dedupe data.
 * Called at dedupe disable time.
 *
 * Return 0 for success
 * Return <0 for any error
 * (tree operation error for some backends)
 */
int btrfs_dedupe_disable(struct btrfs_fs_info *fs_info);

/*
 * Cleanup current btrfs_dedupe_info
 * Called in umount time
 */
int btrfs_dedupe_cleanup(struct btrfs_fs_info *fs_info);

/*
 * Calculate hash for dedupe.
 * Caller must ensure [start, start + dedupe_bs) has valid data.
 *
 * Return 0 for success
 * Return <0 for any error
 * (error from hash codes)
 */
int btrfs_dedupe_calc_hash(struct btrfs_fs_info *fs_info,
			   struct inode *inode, u64 start,
			   struct btrfs_dedupe_hash *hash);

int btrfs_dedupe_calc_hash_head(struct btrfs_fs_info *fs_info,
			   struct inode *inode, u64 start,
			   struct btrfs_dedupe_hash *hash);

/*
 * Search for duplicated extents by calculated hash
 * Caller must call btrfs_dedupe_calc_hash() first to get the hash.
 *
 * @inode: the inode for we are writing
 * @file_pos: offset inside the inode
 * As we will increase extent ref immediately after a hash match,
 * we need @file_pos and @inode in this case.
 *
 * Return > 0 for a hash match, and the extent ref will be
 * *INCREASED*, and hash->bytenr/num_bytes will record the existing
 * extent data.
 * Return 0 for a hash miss. Nothing is done
 * Return <0 for any error
 * (tree operation error for some backends)
 */
int btrfs_dedupe_search(struct btrfs_fs_info *fs_info,
			struct inode *inode, u64 file_pos,
			struct btrfs_dedupe_hash *hash);

/*
 * Add a dedupe hash into dedupe info
 * Return 0 for success
 * Return <0 for any error
 * (tree operation error for some backends)
 */
int btrfs_dedupe_add(struct btrfs_fs_info *fs_info,
		     struct btrfs_dedupe_hash *hash);

/*
 * Remove a dedupe hash from dedupe info
 * Return 0 for success
 * Return <0 for any error
 * (tree operation error for some backends)
 *
 * NOTE: if hash deletion error is not handled well, it will lead
 * to corrupted fs, as later dedupe write can points to non-exist or even
 * wrong extent.
 */
int btrfs_dedupe_del(struct btrfs_fs_info *fs_info, u64 bytenr);
#endif
