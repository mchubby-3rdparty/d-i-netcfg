#include "test/srunner.h"

int main(void)
{
	int number_failed;
	SRunner *sr;
	sr = srunner_create(test_inet_mton_suite());
	srunner_add_suite(sr, test_netcfg_parse_cidr_address_suite());
	srunner_add_suite(sr, test_netcfg_network_address_suite());
	srunner_add_suite(sr, test_netcfg_gateway_reachable_suite());
	
	srunner_run_all (sr, CK_NORMAL);
	number_failed = srunner_ntests_failed (sr);
	srunner_free (sr);
	return (number_failed == 0) ? 0 : 1;
}
