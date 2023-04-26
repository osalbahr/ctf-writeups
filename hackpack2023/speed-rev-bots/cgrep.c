#include <stdio.h>
#include <ctype.h>

// find alnum of length exactly 16
// works for level1
int main()
{
    char str[16 + 1];
    int c = 0;
    int ch;
    while (ch = getc(stdin), !feof(stdin)) {
        if (isalnum(ch)) {
            str[c++] = ch;
        } else if (c == 16) {
            str[c] = '\0';
            break;
        } else {
            c = 0;
        }
    }
    puts(str);
}
