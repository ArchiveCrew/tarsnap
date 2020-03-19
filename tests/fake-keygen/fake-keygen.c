#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crypto.h"
#include "keyfile.h"
#include "warnp.h"

int
main(int argc, char **argv)
{
	FILE * keyfile;
	const char * keyfilename;

	WARNP_INIT;

	/* Check command-line. */
	if (argc != 2) {
		warn0("Usage: %s keyfilename", argv[0]);
		goto err0;
	}
	keyfilename = argv[1];

	/* Create key file. */
	if ((keyfile = keyfile_write_open(keyfilename)) == NULL) {
		warnp("Cannot create %s", keyfilename);
		goto err0;
	}

	/* Initialize key cache. */
	if (crypto_keys_init()) {
		warnp("Key cache initialization failed");
		goto err1;
	}

	/* Generate keys. */
	if (crypto_keys_generate(CRYPTO_KEYMASK_USER)) {
		warnp("Error generating keys");
		goto err1;
	}

	/* Close the key file. */
	if (keyfile_write_file(keyfile, 0, CRYPTO_KEYMASK_USER, NULL, 0, 0)) {
		warnp("Error writing key file");
		goto err1;
	}

	/* Clean up. */
	if (fclose(keyfile)) {
		warnp("Error closing key file");
		goto err1;
	}

	/* Success! */
	exit(0);

err1:
	fclose(keyfile);
	unlink(keyfilename);
err0:
	/* Failure! */
	exit(1);
}
