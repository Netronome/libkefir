// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2019 Netronome Systems, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>

static void ret0 (__attribute__((unused)) int sig)
{
	return;
}

int compile_cfile_to_bpf(const char *c_file, const char *opt_object_file,
			 const char *opt_ll_file,
			 const char *opt_clang_bin, const char *opt_llc_bin)
{
	const char *clang = opt_clang_bin ? opt_clang_bin : "/usr/bin/clang";
	const char *llc = opt_llc_bin ? opt_llc_bin : "/usr/bin/llc";
	char *objfile, *llfile;
	size_t len;
	pid_t pid;

	if (!c_file)
		return -1;
	len = strlen(c_file);

	if (!opt_object_file || !opt_ll_file) {
		if (len < 3)
			return -1;
		if (strcmp(c_file + len - 2, ".c"))
			return -1;
	}

	if (!opt_object_file) {
		objfile = strdup(c_file);
		if (!objfile)
			return -1;
		*(objfile + len - 1) = 'o';
	} else {
		objfile = (char *)opt_object_file;
	}

	if (!opt_ll_file) {
		llfile = malloc(len + 2);
		if (!llfile)
			goto err_free_objfile;
		strcpy(llfile, c_file);
		sprintf(llfile + len - 1, "ll");
	} else {
		llfile = (char *)opt_ll_file;
	}

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		if (execl(clang, clang, "-O2", "-g", "-emit-llvm",
			  "-o", llfile, "-c", c_file, (char *)NULL))
			goto err_free_filenames;
	}

	/*
	 * We need to wait for the compilation from C to IR to finish: we can
	 * pause() to wait for the SIGCHLD signal sent by the child process
	 * when it terminates, but pause() only resumes on SIGCHLD if it
	 * triggers a callback action. Let's set up a callback that does
	 * nothing.
	 */
	struct sigaction sigact = {
		.sa_handler = ret0
	};
	if (sigaction(SIGCHLD, &sigact, NULL))
		return -1;
	pause();

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		if (execl(llc, llc, "-march=bpf", "-mcpu=probe",
			  "-filetype=obj", "-o", objfile, llfile, (char *)NULL))
			goto err_free_filenames;
	}

	pause();

	if (!opt_ll_file)
		free(llfile);
	if (!opt_object_file)
		free(objfile);

	return 0;

err_free_filenames:
	if (!opt_ll_file)
		free(llfile);
err_free_objfile:
	if (!opt_object_file)
		free(objfile);

	return -1;
}
