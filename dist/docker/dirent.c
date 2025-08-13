#define _DIRENT_HAVE_D_RECLEN 1
#define _DIRENT_HAVE_D_TYPE 1
// #define _DIRENT_HAVE_D_OFF 1
#define _DIRENT_HAVE_D_INO 1

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

#define offsetof(type, field) (int)((size_t) &((type *)0)->field)
#define A(a,b) printf ("%d\t%s\n", offsetof (struct dirent, a), b)

int main() {
	DIR *dir;
	struct dirent *entry;
	struct dirent entry_buffer;
	int result;

	dir = opendir("/bin");
	if (!dir) {
		perror("opendir");
		return EXIT_FAILURE;
	}

	while ((result = readdir_r(dir, &entry_buffer, &entry)) == 0 && entry != NULL) {
		printf("Directory entry: %s\n", entry->d_name);

		// Print the offsets of struct dirent fields
		A(d_name, "d_name");
#ifdef _DIRENT_HAVE_D_RECLEN
		A(d_reclen, "d_reclen");
#endif
#ifdef _DIRENT_HAVE_D_TYPE
		A(d_type, "d_type");
#endif
#ifdef _DIRENT_HAVE_D_OFF
		A(d_off, "d_off");
#endif
#ifdef _DIRENT_HAVE_D_INO
		A(d_ino, "d_ino");
#endif
		break; // Remove this line if you want to continue reading all entries
	}

	if (result != 0) {
		perror("readdir_r");
		closedir(dir);
		return EXIT_FAILURE;
	}

	closedir(dir);
	return EXIT_SUCCESS;
}

