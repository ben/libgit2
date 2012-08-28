#include "clar_libgit2.h"
#include "posix.h"

#include "git2/odb_backend.h"
#include "oidmap.h"
GIT__USE_OIDMAP;


/* In-memory ODB backend */
typedef struct {
	git_odb_backend parent;
	git_oidmap *map;
} inmem_backend;

typedef struct {
	size_t size;
	git_otype type;
	void *obj;
} inmem_table_entry;

static int inmem_read(void **out, size_t *size, git_otype *type,
					struct git_odb_backend *back, const git_oid *oid)
{
	inmem_backend *b = (inmem_backend*)back;
	inmem_table_entry *entry;
	khiter_t pos;

	/* read the object identified by 'oid' and write its contents 
	to 'out'. Return 0 if the read was succesful,
	or an error code otherwise. */

	pos = kh_get(oid, b->map, oid);
	if (pos == kh_end(b->map)) {
		return GIT_ENOTFOUND;
	}
	entry = (inmem_table_entry*)kh_value(b->map, pos);
	*out = git__malloc(entry->size);
	memmove(*out, entry->obj, entry->size);
	if (size) *size = entry->size;
	if (type) *type = entry->type;
	return 0;
}

static int inmem_read_header(size_t *size, git_otype *type,
							 git_odb_backend *back, const git_oid *oid)
{
	inmem_backend *b = (inmem_backend*)back;
	inmem_table_entry *entry;
	khiter_t pos;

	/* read the header of the object identified by 'oid' and fill 
	the 'out->type' and 'out->len' fields without actually 
	loading the whole object in memory. Return 0 if
	the read was succesful, or an error code otherwise. */

	pos = kh_get(oid, b->map, oid);
	if (pos == kh_end(b->map)) {
		return GIT_ENOTFOUND;
	}
	entry = (inmem_table_entry*)kh_value(b->map, pos);
	if (size) *size = entry->size;
	if (type) *type = entry->type;
	return 0;
}

static int inmem_write(git_oid *oid, struct git_odb_backend *back,
							  const void *data, size_t len, git_otype type)
{
	inmem_backend *b = (inmem_backend*)back;
	inmem_table_entry *entry = (inmem_table_entry*)calloc(1, sizeof(inmem_table_entry));

	entry->obj = git__malloc(len);
	memmove(entry->obj, data, len);
	entry->size = len;
	entry->type = type;
	return 0;
}

static int inmem_writestream(git_odb_stream **stream, git_odb_backend *back,
									  size_t len, git_otype type)
{

}

static int inmem_readstream(git_odb_stream **stream, git_odb_backend *back,
									 const git_oid *oid)
{
}

static int inmem_exists(struct git_odb_backend *back, const git_oid *oid)
{
	inmem_backend *b = (inmem_backend*)back;
	khiter_t pos;

	pos = kh_get(oid, b->map, oid);
	return pos == kh_end(b->map) ? false : true;
}

static int inmem_foreach(struct git_odb_backend *back,
						int (*cb)(git_oid *oid, void *data),
						void *data)
{
}

static void inmem_free(struct git_odb_backend *back)
{
	inmem_backend *b = (inmem_backend*)back;
	inmem_table_entry *entry;

	kh_foreach_value(b->map, entry, {
		free(entry->obj);
		free(entry);
	});

	git_oidmap_free(((inmem_backend*)back)->map);
	free(back);
}

git_odb_backend *create_inmem_backend() 
{
	inmem_backend *b = (inmem_backend*)calloc(1, sizeof(inmem_backend));

	b->parent.read = &inmem_read;
	b->parent.read_header = &inmem_read_header;
	b->parent.write = &inmem_write;
	//b->parent.writestream = &inmem_writestream;
	//b->parent.readstream = &inmem_readstream;
	b->parent.exists = &inmem_exists;
	//b->parent.foreach = &inmem_foreach;
	b->parent.free = &inmem_free;

	b->map = git_oidmap_alloc();

	return (git_odb_backend*)b;
}


void clar_on_init(void)
{
	git_threads_init();
}

void clar_on_shutdown(void)
{
	git_threads_shutdown();

	/* TODO: clean up cached sandboxes */
}

void cl_git_mkfile(const char *filename, const char *content)
{
	int fd;

	fd = p_creat(filename, 0666);
	cl_assert(fd != 0);

	if (content) {
		cl_must_pass(p_write(fd, content, strlen(content)));
	} else {
		cl_must_pass(p_write(fd, filename, strlen(filename)));
		cl_must_pass(p_write(fd, "\n", 1));
	}

	cl_must_pass(p_close(fd));
}

void cl_git_write2file(
	const char *filename, const char *new_content, int flags, unsigned int mode)
{
	int fd = p_open(filename, flags, mode);
	cl_assert(fd >= 0);
	if (!new_content)
		new_content = "\n";
	cl_must_pass(p_write(fd, new_content, strlen(new_content)));
	cl_must_pass(p_close(fd));
}

void cl_git_append2file(const char *filename, const char *new_content)
{
	cl_git_write2file(filename, new_content, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

void cl_git_rewritefile(const char *filename, const char *new_content)
{
	cl_git_write2file(filename, new_content, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

#ifdef GIT_WIN32

#include "win32/utf-conv.h"

char *cl_getenv(const char *name)
{
	wchar_t *name_utf16 = gitwin_to_utf16(name);
	DWORD value_len, alloc_len;
	wchar_t *value_utf16;
	char *value_utf8;

	cl_assert(name_utf16);
	alloc_len = GetEnvironmentVariableW(name_utf16, NULL, 0);
	if (alloc_len <= 0)
		return NULL;

	cl_assert(value_utf16 = git__calloc(alloc_len, sizeof(wchar_t)));

	value_len = GetEnvironmentVariableW(name_utf16, value_utf16, alloc_len);
	cl_assert_equal_i(value_len, alloc_len - 1);

	cl_assert(value_utf8 = gitwin_from_utf16(value_utf16));

	git__free(value_utf16);

	return value_utf8;
}

int cl_setenv(const char *name, const char *value)
{
	wchar_t *name_utf16 = gitwin_to_utf16(name);
	wchar_t *value_utf16 = value ? gitwin_to_utf16(value) : NULL;

	cl_assert(name_utf16);
	cl_assert(SetEnvironmentVariableW(name_utf16, value_utf16));

	git__free(name_utf16);
	git__free(value_utf16);

	return 0;

}
#else

#include <stdlib.h>
char *cl_getenv(const char *name)
{
   return getenv(name);
}

int cl_setenv(const char *name, const char *value)
{
	return (value == NULL) ? unsetenv(name) : setenv(name, value, 1);
}
#endif

static const char *_cl_sandbox = NULL;
static git_repository *_cl_repo = NULL;

git_repository *cl_git_sandbox_init_cached(const char *sandbox)
{
	char test_dir[1024] = {0};
	git_odb *odb;

	_cl_sandbox = sandbox;

	/* Rename some things in the sandbox so git will work properly */
	cl_git_pass(p_getcwd(test_dir, 1024));
	cl_git_pass(p_chdir(cl_fixture(sandbox)));
	if (p_access(".gitted", F_OK) == 0)
		cl_git_pass(p_rename(".gitted", ".git"));
	//if (p_access("gitattributes", F_OK) == 0)
	//	cl_git_pass(p_rename("gitattributes", ".gitattributes"));
	//if (p_access("gitignore", F_OK) == 0)
	//	cl_git_pass(p_rename("gitignore", ".gitignore"));

	cl_git_pass(p_chdir(test_dir));
	cl_git_pass(p_mkdir(sandbox, 755));
	cl_git_pass(p_chdir(sandbox));
	cl_git_pass(git_repository_open(&_cl_repo, cl_fixture(sandbox)));
	cl_git_pass(git_repository_set_workdir(_cl_repo, ".", false));

	/* Add the in-memory backend for object changes */
	cl_git_pass(git_repository_odb(&odb, _cl_repo));
	cl_git_pass(git_odb_add_backend(odb, create_inmem_backend(), 3));
	git_odb_free(odb);

	cl_git_pass(p_chdir(".."));
	return _cl_repo;
}

void cl_git_sandbox_cleanup_cached(void)
{
	char test_dir[1024] = {0};

	/* Rename back */
	cl_git_pass(p_getcwd(test_dir, 1024));
	cl_git_pass(p_chdir(cl_fixture(_cl_sandbox)));
	if (p_access(".git", F_OK) == 0)
		cl_git_pass(p_rename(".git", ".gitted"));
	cl_git_pass(p_chdir(test_dir));

	if (_cl_repo) {
		git_repository_free(_cl_repo);
		_cl_repo = NULL;
	}
	if (_cl_sandbox) {
		cl_fixture_cleanup(_cl_sandbox);
		_cl_sandbox = NULL;
	}
}

git_repository *cl_git_sandbox_init(const char *sandbox)
{
	/* Copy the whole sandbox folder from our fixtures to our test sandbox
	 * area.  After this it can be accessed with `./sandbox`
	 */
	cl_fixture_sandbox(sandbox);
	_cl_sandbox = sandbox;

	cl_git_pass(p_chdir(sandbox));

	/* If this is not a bare repo, then rename `sandbox/.gitted` to
	 * `sandbox/.git` which must be done since we cannot store a folder
	 * named `.git` inside the fixtures folder of our libgit2 repo.
	 */
	if (p_access(".gitted", F_OK) == 0)
		cl_git_pass(p_rename(".gitted", ".git"));

	/* If we have `gitattributes`, rename to `.gitattributes`.  This may
	 * be necessary if we don't want the attributes to be applied in the
	 * libgit2 repo, but just during testing.
	 */
	if (p_access("gitattributes", F_OK) == 0)
		cl_git_pass(p_rename("gitattributes", ".gitattributes"));

	/* As with `gitattributes`, we may need `gitignore` just for testing. */
	if (p_access("gitignore", F_OK) == 0)
		cl_git_pass(p_rename("gitignore", ".gitignore"));

	cl_git_pass(p_chdir(".."));

	/* Now open the sandbox repository and make it available for tests */
	cl_git_pass(git_repository_open(&_cl_repo, sandbox));

	return _cl_repo;
}

void cl_git_sandbox_cleanup(void)
{
	if (_cl_repo) {
		git_repository_free(_cl_repo);
		_cl_repo = NULL;
	}
	if (_cl_sandbox) {
		cl_fixture_cleanup(_cl_sandbox);
		_cl_sandbox = NULL;
	}
}

bool cl_toggle_filemode(const char *filename)
{
	struct stat st1, st2;

	cl_must_pass(p_stat(filename, &st1));
	cl_must_pass(p_chmod(filename, st1.st_mode ^ 0100));
	cl_must_pass(p_stat(filename, &st2));

	return (st1.st_mode != st2.st_mode);
}

bool cl_is_chmod_supported(void)
{
	static int _is_supported = -1;

	if (_is_supported < 0) {
		cl_git_mkfile("filemode.t", "Test if filemode can be modified");
		_is_supported = cl_toggle_filemode("filemode.t");
		cl_must_pass(p_unlink("filemode.t"));
	}

	return _is_supported;
}



