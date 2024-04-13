#include <fnmatch.h>
#include <stdio.h>

int main() {
    const char *blacklist_pattern = "/bin/*";
    const char *test_path = "/bin/grep";

    if (fnmatch(blacklist_pattern, test_path, FNM_PATHNAME) == 0) {
        printf("Matched: %s is blocked by pattern %s\n", test_path, blacklist_pattern);
    } else {
        printf("Not Matched: %s is not blocked by pattern %s\n", test_path, blacklist_pattern);
    }

    return 0;
}