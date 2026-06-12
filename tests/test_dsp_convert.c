/* test_dsp_convert.c -- exercise dsp_convert_to_bin() PI parsing on a real
 * DSD-FME log + a synthetic DSP. Prints the first output lines so we can verify
 * the MOTOTRBO "DMR PI H- ... MI(32)" format is parsed (regression guard) and
 * that ALG/KID/MI tags are attached. Usage: test_dsp_convert <dsp> <log> <out> */
#include <stdio.h>
#include "../include/payload_io.h"

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s dsp log out\n", argv[0]); return 2; }
    char err[256] = {0};
    if (!dsp_convert_to_bin(argv[1], argv[3], argv[2], err, sizeof(err))) {
        fprintf(stderr, "convert failed: %s\n", err); return 1;
    }
    FILE *f = fopen(argv[3], "r");
    if (!f) { fprintf(stderr, "cannot read out\n"); return 1; }
    char line[1024]; int i = 0;
    while (fgets(line, sizeof(line), f) && i < 4) { fputs(line, stdout); i++; }
    fclose(f);
    return 0;
}
