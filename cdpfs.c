#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "fuse_log.h"
#include <cerrno>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sys/stat.h>
#endif

#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 16)

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <ftw.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>

static int debug;

struct cfs_inode {
	struct cfs_inode *next; /* protected by lo->mutex */
	struct cfs_inode *prev;
	int fd;
	ino_t ino;
	dev_t dev;
	uint64_t refcount;
};

struct cfs_data {
	pthread_mutex_t mutex;
	int debug;
	int passthrough;
	int flock;
	int xattr;
	char *source;
	double timeout;
	int timeout_set;
	struct cfs_inode root; /* protected by mutex */
};

static const struct fuse_opt cfs_opts[] = {
	{ "source=%s",
	  offsetof(struct cfs_data, source), 0},
	{ "passthrough",
	  offsetof(struct cfs_data, passthrough), 1},
	{ "no_passthrough",
	  offsetof(struct cfs_data, passthrough), 0},
	{ "flock",
	  offsetof(struct cfs_data, flock), 1},
	{ "no_flock",
	  offsetof(struct cfs_data, flock), 1},
	{ "xattr",
	  offsetof(struct cfs_data, xattr), 1 },
	{ "no_xattr",
	  offsetof(struct cfs_data, xattr), 0 },
	{ "timeout=%lf",
	  offsetof(struct cfs_data, timeout), 0 },
	{ "timeout=",
	  offsetof(struct cfs_data, timeout_set), 1 },
	  FUSE_OPT_END
};


static inline struct cfs_data *cfs_data(fuse_req_t req) {
	return (struct cfs_data *) fuse_req_userdata(req);
}

static inline struct cfs_inode *cfs_inode(fuse_req_t req, fuse_ino_t ino) {
	if(ino == FUSE_ROOT_ID) {
		return &cfs_data(req)->root;
	} else {
		return (struct cfs_inode *) (uintptr_t) ino;
	}
}

static inline int cfs_fd(fuse_req_t req, fuse_ino_t ino) {
	return cfs_inode(req, ino)->fd;
}

static inline bool cfs_debug(fuse_req_t req) {
	return cfs_data(req)->debug != 0;
}

static struct cfs_inode *cfs_find(struct cfs_data *cfs, struct stat *st) {
  struct cfs_inode *p;
  struct cfs_inode *ret = NULL;

  pthread_mutex_lock(&cfs->mutex);
  for(p = cfs->root.next; p != &cfs->root; p = p->next) {
    if(p->ino == st->st_ino && p->dev == st->st_dev) {
      assert(p->refcount > 0);
      ret = p;
      ret->refcount++;
      break;
    }
  }
  pthread_mutex_unlock(&cfs->mutex);
  return ret;
}

static void cfs_init(void *userdata, struct fuse_conn_info *conn) {
	struct cfs_data *cfs = (struct cfs_data *)userdata;

#ifdef FUSE_CAP_PASSTHROUGH
	if(cfs->passthrough && conn->capable & FUSE_CAP_PASSTHROUGH) {
		conn->want |= FUSE_CAP_PASSTHROUGH;
	} else {
		cfs->passthrough = false;
	}
#else
	cfs->passthrough = false;
#endif

	if(cfs->flock && conn->capable & FUSE_CAP_FLOCK_LOCKS) {
		conn->want |= FUSE_CAP_FLOCK_LOCKS;
	}
	if(conn->capable & FUSE_CAP_SPLICE_WRITE) {
		conn->want |= FUSE_CAP_SPLICE_WRITE;
	}
	if(conn->capable & FUSE_CAP_SPLICE_READ) {
		conn->want |= FUSE_CAP_SPLICE_READ;
	}

#ifdef FUSE_CAP_DIRECT_IO_ALLOW_MMAP
	if(conn->capable & FUSE_CAP_DIRECT_IO_ALLOW_MMAP) {
		conn->want |= FUSE_CAP_DIRECT_IO_ALLOW_MMAP;
	}
#endif
}


static void cfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
	struct cfs_data *cfs = cfs_data(req);
	struct stat attr;

	int fd = fi ? fi->fh : cfs_fd(req, ino);

	int res = fstatat(fd, "", &attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if(res == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	
	fuse_reply_attr(req, &attr, cfs->timeout);
}

static void cfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int valid, struct fuse_file_info *fi) {
	struct cfs_inode *inode = cfs_inode(req, ino);
	int ifd = inode->fd;

	int res;

	if(valid & FUSE_SET_ATTR_MODE) {
		if(fi) {
			res = fchmod(fi->fh, attr->st_mode);
		} else {
			char procname[64];
			snprintf(procname, sizeof(procname), "/proc/self/fd/%i", ifd);
			res = chmod(procname, attr->st_mode);
		}
		if(res == -1) {
			goto out_err;
		}
	}

	if(valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
		uid_t uid = (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : -1;
		gid_t gid = (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : -1;

		res = fchownat(ifd, "", uid, gid, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
		if(res == -1) {
			goto out_err;
		}
	}
	if(valid & (FUSE_SET_ATTR_SIZE)) {
		if(fi) {
			res = ftruncate(fi->fh, attr->st_size);
		} else {
			char procname[64];
			snprintf(procname, sizeof(procname), "/proc/self/fd/%i", ifd);
			res = truncate(procname, attr->st_size);
		}
		if(res == -1) goto out_err;
	}

	if(valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
				struct timespec tv[2];

		tv[0].tv_sec = 0;
		tv[1].tv_sec = 0;
		tv[0].tv_nsec = UTIME_OMIT;
		tv[1].tv_nsec = UTIME_OMIT;

		if (valid & FUSE_SET_ATTR_ATIME_NOW)
			tv[0].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_ATIME)
			tv[0] = attr->st_atim;

		if (valid & FUSE_SET_ATTR_MTIME_NOW)
			tv[1].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_MTIME)
			tv[1] = attr->st_mtim;
		
		if(fi) {
			res = futimens(fi->fh, tv);
		} else {
#ifdef HAVE_UTIMENSAT
		  char procname[64];
		  sprintf(procname, "/proc/self/fd/%i", ifd);
		  res = utimensat(AT_FDCWD, procname, tv, 0);
#else
		  res = -1;
		  errno = EOPNOTSUPP;
#endif
		}
		if(res == -1) {
		  goto out_err;
		}
	}
  return cfs_getattr(req, ino, fi);
out_err:
  fuse_reply_err(req, errno);
}

static int do_lookup(fuse_req_t req, fuse_ino_t parent, 
                     const char *name, struct fuse_entry_param *e) {
  int newfd;
  int res;
  int saverr;
  
  struct cfs_data *cfs = cfs_data(req);
  struct cfs_inode *inode;

  memset(e, 0, sizeof(*e));
  e->attr_timeout = cfs->timeout;
  e->entry_timeout = cfs->timeout;

  newfd = openat(cfs_fd(req, parent), name, O_PATH | O_NOFOLLOW);
  if(newfd == -1) {
    goto out_err;
  }

  res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if(res == -1) {
    goto out_err;
  }

  inode = cfs_find(cfs, &e->attr);
  if(inode) {
    close(newfd);
    newfd = -1;
  } else {
    struct cfs_inode *prev, *next;

    saverr = ENOMEM;
    inode = calloc(1, sizeof(struct cfs_inode));
    if(!inode) {
      goto out_err;
    }
    inode->refcount = 1;
    inode->fd = newfd;
    inode->ino = e->attr.st_ino;
    inode->dev = e->attr.st_dev;

    pthread_mutex_lock(&cfs->mutex);
    prev = &cfs->root;
    next = prev->next;
    next->prev = inode;
    inode->next = next;
    prev->next = inode;
    pthread_mutex_unlock(&cfs->mutex);
  }
  e->ino =(uintptr_t)inode;

  if(cfs_debug(req)) {
    fuse_log(FUSE_LOG_DEBUG, " %lli/%s -> %lli\n", (unsigned long long)parent, name, (unsigned long long)e->ino);
  }

  return 0;

out_err:
  saverr = errno;
  if(newfd != -1) {
    close(newfd);
  }
  return saverr;
}

static void cfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
  struct fuse_entry_param e;
  int err;

  if(cfs_debug(req)) {
    fuse_log(FUSE_LOG_DEBUG, "cfs_lookup(parent=%" PRIu64 ",name=%s)\n",
             parent, name);
  }

  err = do_lookup(req, parent, name, &e);
  if(err) {
    fuse_reply_err(req, err);
  } else {
    fuse_reply_entry(req, &e);
  }
}

static void mknod_symlink(fuse_req_t req, fuse_ino_t parent,
                          const char *name, mode_t mode, dev_t rdev,
                          const char *link) {
  int res;
  struct cfs_inode *inode = cfs_inode(req, parent);
  int saverr = ENOMEM;

  if(S_ISDIR(mode)) {
    res = mkdirat(inode->fd, name, mode);
  } else if(S_ISLNK(mode)) {
    res = symlinkat(link, inode->fd, name);
  } else {
    res = mknodat(inode->fd, name, mode, rdev);
  }
  saverr = errno;
  if(res == -1) {
    goto out;
  }

  struct fuse_entry_param e;
  saverr = do_lookup(req, parent, name, &e);
  if(saverr)
    goto out;

  fuse_reply_entry(req, &e);
  return;
out:
  if(saverr == ENFILE || saverr == EMFILE) {
    fprintf(stderr, "ERROR: reached maximum number of file descriptors");
  }
  fuse_reply_err(req, saverr);
}

static void cfs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode, dev_t rdev) {
    mknod_symlink(req, parent, name, mode, rdev, NULL);
}


static void cfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode) {
    mknod_symlink(req, parent, name, S_IFDIR | mode, 0, NULL);
}


static void cfs_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
                        const char *name) {
    mknod_symlink(req, parent, name, S_IFLNK, 0, link);
}

static void cfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t parent, const char *name) {
  struct cfs_data *fs = cfs_data(req);
  struct cfs_inode *inode = cfs_inode(req, ino);

  struct fuse_entry_param e;
  memset(&e, 0, sizeof(e));
  e.attr_timeout = fs->timeout;
  e.entry_timeout = fs->timeout;

  char procname[64];
  snprintf(procname, sizeof(procname), "/proc/self/fd/%i", inode->fd);
  int res = linkat(AT_FDCWD, procname, cfs_fd(req, parent), name, AT_SYMLINK_FOLLOW);
  if(res == -1) {
    fuse_reply_err(req, errno);
    return;
  }

  res = fstatat(inode->fd, "", &e.attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
  if(res == -1) {
    fuse_reply_err(req, errno);
    return;
  }

  pthread_mutex_lock(&fs->mutex);
  inode->refcount++;
  pthread_mutex_unlock(&fs->mutex);
  e.ino = (uintptr_t)inode;
  
  fuse_reply_entry(req, &e);
  return;
}

static void cfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
  int res = unlinkat(cfs_fd(req, parent), name, AT_REMOVEDIR);
  fuse_reply_err(req, res == -1 ? errno : 0);
}

static void cfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                       fuse_ino_t newparent, const char *newname, unsigned int flags) {
  int res;
  if(flags) {
    fuse_reply_err(req, EINVAL);
    return;
  }

  res = renameat(cfs_fd(req, parent), name,
                 cfs_fd(req, newparent), newname);
  fuse_reply_err(req, res == -1 ? errno : 0);
}

static void cfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
  int res;

  res = unlinkat(cfs_fd(req, parent), name, 0);

  fuse_reply_err(req, res == -1 ? errno : 0);
}

static void unref_inode(struct cfs_data *fs, struct cfs_inode *inode, uint64_t n) {
  if(!inode) {
    return;
  }

  pthread_mutex_lock(&fs->mutex);
  assert(inode->refcount >= n);
  inode->refcount -= n;
  if(!inode->refcount) {
    struct cfs_inode *prev, *next;

		prev = inode->prev;
		next = inode->next;
		next->prev = prev;
		prev->next = next;

    pthread_mutex_unlock(&fs->mutex);
    close(inode->fd);
    free(inode);
  } else {
    pthread_mutex_unlock(&fs->mutex);
  }
}

static void cfs_forget_one(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
  unref_inode(cfs_data(req), cfs_inode(req, ino), nlookup);
}

static void cfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
  cfs_forget_one(req, ino, nlookup);
  fuse_reply_none(req);
}

static void cfs_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets) {
  for(int i = 0; i < count; i++) {
    cfs_forget_one(req, forgets[i].ino, forgets[i].nlookup);
  }
  fuse_reply_none(req);
}

static void cfs_readlink(fuse_req_t req, fuse_ino_t ino) {
  char buf[PATH_MAX + 1];
  int res;

  res = readlinkat(cfs_fd(req, ino), "", buf, sizeof(buf));
  if(res == -1) {
    return fuse_reply_err(req, errno);
  }

  if(res == sizeof(buf)) {
    return fuse_reply_err(req, ENAMETOOLONG);
  }

  buf[res] = '\0';

  fuse_reply_readlink(req, buf);
}

struct cfs_dirp {
  DIR *dp;
  struct dirent *entry;
  off_t offset;
};

static struct cfs_dirp *cfs_dirp(struct fuse_file_info *fi) {
  return (struct cfs_dirp *)(uintptr_t) fi->fh;
}

static void lo_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  struct cfs_data *fs = cfs_data(req);

  int error = ENOMEM;
  int fd;
  struct cfs_dirp *dp = calloc(1, sizeof(struct cfs_dirp));
  if(dp == NULL) {
    goto out_error;
  }
  fd = openat(cfs_fd(req, ino), ".", O_RDONLY);
  if(fd < 0) {
    goto out_errno;
  }

  dp->dp = fdopendir(fd);
  if(dp->dp == NULL) {
    goto out_errno;
  }

  dp->offset = 0;
  fi->fh = (uintptr_t)dp;
  if(fs->timeout) {
    fi->keep_cache = 1;
    fi->cache_readdir = 1;
  }
  fuse_reply_open(req, fi);
  return;

out_errno:
  error = errno;
out_error:
  if(dp) {
    if(fd != -1) {
      close(fd);
    }
    free(dp);
  }
  fuse_reply_err(req, error);
}

static bool is_dot_or_dotdot(const char *name) {
  return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static void do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                       off_t offset, struct fuse_file_info *fi, const int plus) {
  struct cfs_dirp *dp = cfs_dirp(fi);
  struct cfs_inode *inode = cfs_inode(req, ino);

  char *p;
  size_t rem = size;
  int err = 0;
  int count = 0;

  char *buf = calloc(1, size);
  if(!buf) {
    fuse_reply_err(req, ENOMEM);
    return;
  }

  p = buf;
  if(offset != dp->offset) {
    seekdir(dp->dp, offset);
    dp->offset = offset;
  }

  while(1) {
    bool did_lookup = false;
    struct dirent *entry;
    errno = 0;
    entry = readdir(dp->dp);
    if(!entry) {
      if(errno) {
        err = errno;
        goto error;
      }
      break;
    }

    dp->offset = entry->d_off;

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));
    size_t entsize;
    if(plus) {
      if(is_dot_or_dotdot(entry->d_name)) {
        e.attr.st_ino = entry->d_ino;
        e.attr.st_mode = entry->d_type << 12;
      } else {
        err = do_lookup(req, ino, entry->d_name, &e);
        if(err) {
          goto error;
        }
        did_lookup = true;
      }
      entsize = fuse_add_direntry_plus(req, p, rem, entry->d_name, &e, entry->d_off);
    } else {
      e.attr.st_ino = entry->d_ino;
      e.attr.st_mode = entry->d_type << 12;
      entsize = fuse_add_direntry(req, p, rem, entry->d_name, &e.attr, entry->d_off);
    }

    if(entsize > rem) {
      if(did_lookup) {
        cfs_forget_one(req, e.ino, 1);
      }
      break;
    }

    p += entsize;
    rem -= entsize;
    count++;
  }
  err = 0;
error:
  if(err && rem == size) {
    if(err == ENFILE || err == EMFILE) {
      fprintf(stderr, "ERROR: reached max file descriptors");
    }
      fuse_reply_err(req, err);
  } else {
    fuse_reply_buf(req, buf, size - rem);
  }
  free(buf);
}

static void cfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi) {
  do_readdir(req, ino, size, offset, fi, 0);
}

static void cfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi) {
  do_readdir(req, ino, size, offset, fi, 1);
}

static void cfs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
  struct cfs_dirp *dp = cfs_dirp(fi);
  if(dp->dp) {
    closedir(dp->dp);
  }
  free(dp);
}


int main(int argc, char **argv) {
	return 0;
}
