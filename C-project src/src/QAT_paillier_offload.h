//include QAT headers
#include "cpa.h"
#include "icp_sal_user.h"
#include "cpa_sample_utils.h"
#include "cpa_cy_im.h"
#include "cpa_fips_sample.h"
#include "cpa_fips_sample_utils.h"

#include <gmp.h>


#define __SIZE_TYPE__ long unsigned int
typedef __SIZE_TYPE__ size_t;
//#define size_t long unsigned int

char* data_export(const mpz_t* mpz_data, size_t* got_count);
void data_import(char* char_data, mpz_t* mpz_data, size_t count);

CpaFlatBuffer* WarpData(char* a, size_t a_size, int empty);

CpaFlatBuffer* ModExp(char* a, size_t a_size,
	char* b, size_t b_size,
	char* m, size_t m_size,
	CpaInstanceHandle *cyInstHandle);
CpaFlatBuffer* ModInv(char* a, size_t a_size,
	char* m, size_t m_size,
	CpaInstanceHandle *cyInstHandle);

void PowModN(mpz_t *output, const mpz_t *input, const mpz_t *power, const mpz_t *n, CpaInstanceHandle *cyInstHandle);