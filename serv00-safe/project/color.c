
#include "saia.h"

void color_reset(void) {
    printf("\033[0m");
}

void color_bold(void) {
    printf("\033[1m");
}

void color_blue(void) {
    printf("\033[38;5;39m");
}

void color_cyan(void) {
    printf("\033[38;5;51m");
}

void color_green(void) {
    printf("\033[38;5;46m");
}

void color_yellow(void) {
    printf("\033[38;5;214m");
}

void color_red(void) {
    printf("\033[38;5;196m");
}

void color_magenta(void) {
    printf("\033[38;5;201m");
}

void color_white(void) {
    printf("\033[97m");
}

void color_dim(void) {
    printf("\033[2m");
}
