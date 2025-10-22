#include <check.h>
#include <stdlib.h>

int multiplica(int a, int b);  // Declaración de la función

START_TEST(test_multiplicacion_basica) {
    ck_assert_int_eq(multiplica(4, 5), 20);
    ck_assert_int_eq(multiplica(0, 10), 0);
}
END_TEST

Suite *ejercicio_suite(void) {
    Suite *s = suite_create("Ejercicio1");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_multiplicacion_basica);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    Suite *s = ejercicio_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failures == 0) ? 0 : 1;
}