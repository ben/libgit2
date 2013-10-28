#ifndef INCLUDE_blame_h__
#define INCLUDE_blame_h__

#include "git2/blame.h"
#include "common.h"
#include "vector.h"
#include "diff.h"
#include "array.h"
#include "git2/oid.h"

/*
 * One blob in a commit that is being suspected
 */
typedef struct git_blame__origin {
	git_refcount rc;
	struct git_blame__origin *previous;
	git_commit *commit;
	git_blob *blob;
	char path[];
} git_blame__origin;

/*
 * Each group of lines is described by a git_blame__entry; it can be split
 * as we pass blame to the parents.  They form a linked list in the
 * scoreboard structure, sorted by the target line number.
 */
typedef struct git_blame__entry {
	struct git_blame__entry *prev;
	struct git_blame__entry *next;

	/* the first line of this group in the final image;
	 * internally all line numbers are 0 based.
	 */
	int lno;

	/* how many lines this group has */
	int num_lines;

	/* the commit that introduced this group into the final image */
	git_blame__origin *suspect;

	/* true if the suspect is truly guilty; false while we have not
	 * checked if the group came from one of its parents.
	 */
	char guilty;

	/* true if the entry has been scanned for copies in the current parent
	 */
	char scanned;

	/* the line number of the first line of this group in the
	 * suspect's file; internally all line numbers are 0 based.
	 */
	int s_lno;

	/* how significant this entry is -- cached to avoid
	 * scanning the lines over and over.
	 */
	unsigned score;

	/* Whether this entry has been tracked to a boundary commit.
	 */
	bool is_boundary;
} git_blame__entry;

struct git_blame {
	const char *path;
	git_repository *repository;
	git_blame_options options;

	git_vector hunks;
	git_vector paths;

	git_blob *final_blob;
	git_array_t(size_t) line_index;

	size_t current_diff_line;
	git_blame_hunk *current_hunk;

	/* Scoreboard fields */
	git_commit *final;
	git_blame__entry *ent;
	int num_lines;
	const char *final_buf;
	git_off_t final_buf_size;
};

git_blame *git_blame__alloc(
	git_repository *repo,
	git_blame_options opts,
	const char *path);

#endif
