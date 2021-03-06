/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2016 Fujitsu.  All rights reserved.
 */

#ifndef BTRFS_DEDUPE_H
#define BTRFS_DEDUPE_H

#include <crypto/hash.h>
#include "btrfs_inode.h"
 
// #define PRINT_ARG(x, y) fprintf(stderr, #x": "y"\t", x);
// #define VAR_CHECK(...) do{\
// kprint( ANSI_COLOR_YELLOW "[VAR_CHECK]: %s:%d\t", __FILE__, __LINE__);\
// MAP(PRINT_ARG, __VA_ARGS__); \
// printk("\n" ANSI_COLOR_RESET);}while(0)


/* 32 bytes for SHA256 */
static const int btrfs_hash_sizes[] = { 32 };

/*
 * For caller outside of dedupe.c
 *
 * Different dedupe backends should have their own hash structure
 */

 struct btrfs_dedupe_hash_entry {
	u64 bytenr;
	u32 num_bytes;


	u8 type; 
	u64 burst_index;
	/* last field is a variable length array of dedupe hash */
	// @ fixed to sha256
	u8 hash[32];
};

struct btrfs_dedupe_hash {
	struct btrfs_dedupe_hash_entry * hash_arr[3];
};

struct burst{
	char * diff;
	struct rb_node burst_node;
	u64 offset;
	u64 start;
	u64 end;
};

u64 hash_value_calc(u8 * hash);

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
	struct rb_root hash_root[3];
	struct rb_root bytenr_root;
    struct rb_root bursted_root;
	
	int head_len;
	struct burst * burst_arr;

	struct list_head lru_list[3];
	u64 limit_nr;
	u64 current_nr[3];
};


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
	if(!hash) return 0;
	int ret = 0,i;
	for(i = 0;i<3;++i)
	{
		if(hash->hash_arr[i] && hash->hash_arr[i]->bytenr)
		{
			ret = 1;
			break;
		}
	}
	return ret;
}

// static inline int btrfs_dedupe_hash_hit(struct btrfs_dedupe_hash *hash)
// {
// 	return (hash && hash->bytenr);
// }

static inline int btrfs_dedupe_hash_size(u16 algo)
{
	if (WARN_ON(algo >= ARRAY_SIZE(btrfs_hash_sizes)))
		return -EINVAL;
	return sizeof(struct btrfs_dedupe_hash_entry) + btrfs_hash_sizes[algo];
}

static inline struct btrfs_dedupe_hash *btrfs_dedupe_alloc_hash(u16 algo)
{
	struct btrfs_dedupe_hash * hs = kzalloc(sizeof(struct btrfs_dedupe_hash), GFP_NOFS);
	int i;
	for(i = 0;i<3;++i)
	{
		hs->hash_arr[i] = kzalloc(btrfs_dedupe_hash_size(algo), GFP_NOFS);
	}
	return hs;
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

struct burst * burst_gen(char * origin,char * addin,u64 lth);
int burst_range_gen(struct inode *inode,u64 start,u64 end,u64 bytenr);
// int my_readPage(struct block_device *device, sector_t sector, int size,
    //  struct page *page);
// int __must_check submit_one_bio_X(struct bio *bio, int mirror_num,
				    //    unsigned long bio_flags);
int btrfs_burst_add(struct btrfs_inode *btrfs_inode, struct burst* burst);
int btrfs_burst_search(struct btrfs_inode *btrfs_inode, u64 offset, struct burst** burst);
struct burst_record{
	u64 bytenr;
	struct rb_node br_node;
};
int burst_record_insert(struct btrfs_fs_info *fs_info, u64 bytenr);
#endif
