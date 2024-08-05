//include QAT headers
#include "cpa.h"
#include "icp_sal_user.h"
#include "cpa_sample_utils.h"
#include "cpa_cy_im.h"
#include "cpa_fips_sample.h"
#include "cpa_fips_sample_utils.h"
#include "icp_sal_poll.h"	//icp_sal_CyPollInstance
#include <openssl/async.h>
#include <libhcs.h>

#include <gmp.h>


//#define __SIZE_TYPE__ long unsigned int
typedef __SIZE_TYPE__ size_t;
//#define size_t long unsigned int

#ifdef __cplusplus
extern "C" {
#endif

CpaStatus QATSetting(Cpa16U* numInst_g, CpaInstanceHandle* CyInstHandle);
CpaInstanceHandle *QAT_initial(Cpa16U *numInst);

char* data_export(const mpz_t* mpz_data, size_t* got_count);
void data_import(char* char_data, mpz_t* mpz_data, size_t count);

CpaFlatBuffer* WarpData(char* a, size_t a_size, int empty);

CpaFlatBuffer* ModExp(char* a, size_t a_size,
	char* b, size_t b_size,
	char* m, size_t m_size,
	CpaInstanceHandle *pCyInstHandle);
CpaFlatBuffer* ModInv(char* a, size_t a_size,
	char* m, size_t m_size,
	CpaInstanceHandle *pCyInstHandle);

void PowModN(mpz_t *output, const mpz_t *input, const mpz_t *power, const mpz_t *n, CpaInstanceHandle *pCyInstHandle);

#ifdef __cplusplus
}
#endif