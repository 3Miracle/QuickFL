#include <libhcs.h>
#include <time.h>
#include <math.h>


void simple_array_get_value(mpz_t *array, mpz_t ret, int i);


//------------------------------------------------------------------------ array enc && dec

void array_encrypt(char **ret_array, char **array, int length, CpaInstanceHandle *CyInstHandle);