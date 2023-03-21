#include <sys/stat.h>
#include <stdio.h>

#define offsetof(type, field) (int)((size_t) &((type *)0)->field)
#define A(a,b) printf ("%d\t%s\n", offsetof (struct stat, a), b)

int main() {
	struct stat st;
	int a = stat ("/bin/ls", &st);
	A(st_dev, "st_dev");
	A(st_ino, "st_ino");
	A(st_mode, "st_mode");
	A(st_nlink, "st_nlink");
	A(st_uid, "st_uid");
	A(st_gid, "st_gid");
	A(st_rdev, "st_rdev");
	A(st_atime, "st_atime");
	A(st_mtime, "st_mtime");
	A(st_ctime, "st_ctime");
	A(st_size, "st_size");
	A(st_blocks, "st_blocks");
	A(st_blksize, "st_blksize");
	return 0;
}
