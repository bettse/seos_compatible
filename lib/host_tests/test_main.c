#include "munit.h"

extern MunitSuite test_cmac_suite;
extern MunitSuite test_secure_messaging_suite;

int main(int argc, char* argv[]) {
    MunitSuite child_suites[] = {
        {(char*)"/cmac", test_cmac_suite.tests, NULL, 1, MUNIT_SUITE_OPTION_NONE},
        {(char*)"/secure-messaging",
         test_secure_messaging_suite.tests,
         NULL,
         1,
         MUNIT_SUITE_OPTION_NONE},
        {NULL, NULL, NULL, 0, MUNIT_SUITE_OPTION_NONE},
    };
    MunitSuite main_suite = {
        (char*)"",
        NULL,
        child_suites,
        1,
        MUNIT_SUITE_OPTION_NONE,
    };
    return munit_suite_main(&main_suite, NULL, argc, argv);
}
