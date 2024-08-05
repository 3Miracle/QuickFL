//include QAT headers
#include "../include/libhcs/pcs_qat_offload.h"
#include <libhcs.h>
#include <openssl/async.h>

#include <sched.h>
# include <stdio.h>
//# include <pthread.h>
# include <unistd.h>
# include <stdint.h>

#include <openssl/crypto.h>
//#include <sys/eventfd.h>
//#include <pcs_event.h>

//#define DEBUG


//Callback function
static void asymCallback(void *pCallbackTag,
	CpaStatus status,
	void *pOpData,
	CpaFlatBuffer *pOut)
{
	//PRINT_DBG("CallBack function\n");
	//printf("CallBack function\n");
	int ret;
	ASYNC_WAIT_CTX *waitctx;
	ASYNC_JOB *job = (ASYNC_JOB *)pCallbackTag;


	if (CPA_STATUS_SUCCESS != status)
	{
		PRINT_ERR("operation not a success, status = %d\n", status);
	}
	switch (ASYNC_start_job(&job, NULL, &ret, NULL,
                    NULL, NULL)) {
            case ASYNC_PAUSE:
				//printf("resume paused\n");
                break;
            case ASYNC_FINISH:
                //printf("finish!\n");
				//--jobs_inprogress;
                //job = NULL;
                break;
            case ASYNC_NO_JOBS:
            case ASYNC_ERR:
                //--jobs_inprogress;
                //job = NULL;
                break;
            }

}

/** 
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      doModExp
 *
 * @description
 *      Do a Modular Exponentiation operaton
 *      target = (base ^ exponent) mod (modulus);
 *
 * @param[in]  pBase             base value
 * @param[in]  pExponent         exponent value, if this value is NULL, an
 *                               exponent of 1 is used.
 * @param[in]  pModulus          modulus value
 * @param[in]  instanceHandle    QA instance handle
 *
 * @param[out] pTarget           result value
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus doModExpAsync(const CpaFlatBuffer *restrict pBase,
	const CpaFlatBuffer *restrict pExponent,
	const CpaFlatBuffer *restrict pModulus,
	CpaFlatBuffer *pTarget,
	const CpaInstanceHandle instanceHandle)
{
	//PRINT_DBG("now is doModExpAsync !\n");
	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa32U maxCyRetries = 0;
	Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
		0,
	};
	CpaCyLnModExpOpData modExpOpData = {
		.modulus = {.dataLenInBytes = pModulus->dataLenInBytes,
					.pData = pModulus->pData},
		.base = {.dataLenInBytes = pBase->dataLenInBytes,
				 .pData = pBase->pData},
		.exponent = {.dataLenInBytes = 0,.pData = NULL} };

	/*if exponent is NULL, set value to 1*/
	if (NULL == pExponent)
	{
		modExpOpData.exponent.pData = osZalloc(1, instanceHandle);
		if (NULL == modExpOpData.exponent.pData)
		{
			PRINT_ERR("internal exponent alloc fail \n");
			status = CPA_STATUS_FAIL;
			goto finish;
		}
		*modExpOpData.exponent.pData = 1;
		modExpOpData.exponent.dataLenInBytes = 1;
	}
	else
	{
		modExpOpData.exponent.pData = pExponent->pData;
		modExpOpData.exponent.dataLenInBytes = pExponent->dataLenInBytes;
	}

	// Get the current coroutine handle
	ASYNC_JOB *currjob = ASYNC_get_current_job();

	do
	{
		status = cpaCyLnModExp(instanceHandle,
			asymCallback, /*callback function*/
			currjob, /*callback tag*/
			&modExpOpData,
			pTarget);
		//if (status == CPA_STATUS_RETRY)
		//{
		//	while (icp_sal_CyPollInstance(instanceHandle, 0) != CPA_STATUS_SUCCESS)
		//		;
		//}

		if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
		{
			if (CPA_STATUS_SUCCESS !=
				cpaCyGetStatusText(instanceHandle, status, statusErrorString))
			{
				PRINT_ERR("Error retrieving status string.\n");
			}
			PRINT_ERR("doModExp Fail -- %s\n", statusErrorString);
			status = CPA_STATUS_FAIL;
			goto finish;
		}
		if (CPA_STATUS_SUCCESS == status)
		{
			break;
		}
		maxCyRetries++;
	} while ((CPA_STATUS_RETRY == status) &&
		10000 != maxCyRetries);	//FIPS_MAX_CY_RETRIES != maxCyRetries);

	/*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
	CHECK_MAX_RETRIES(maxCyRetries, status);

	// Pause the current coroutine
	ASYNC_pause_job();

finish:
	if (NULL == pExponent)
	{
		osFree(&modExpOpData.exponent.pData);
	}
	if (CPA_STATUS_SUCCESS != status)
	{
		return CPA_STATUS_FAIL;
	}
	return CPA_STATUS_SUCCESS;
}

/******************************** START OF the preprocessing of QAT induction ***************************************/

CpaInstanceHandle *QAT_initial(Cpa16U *numInst){
	CpaStatus stat = CPA_STATUS_SUCCESS;
	CpaInstanceHandle *CyInstHandle;

	stat = qaeMemInit();
	if (CPA_STATUS_SUCCESS != stat)
	{
		PRINT_ERR("Failed to initialise memory driver\n");
		return NULL;
	}

	stat = icp_sal_userStartMultiProcess("SHIM", CPA_FALSE);
	// if (CPA_STATUS_SUCCESS != stat)
	// {
	// 	PRINT_ERR("Failed to start user process SHIM\n");
	// 	qaeMemDestroy();
	// 	return (int)stat;
	// }
    //Cpa32U i = 0;
	//Cpa32U coreAffinity = 0;
	//CpaInstanceInfo2 info = { 0 };

	/*get the number of crypto instances*/
	stat = cpaCyGetNumInstances(numInst);
	// numInst_g--;
	// if (CPA_STATUS_SUCCESS != stat)
	// {
	// 	PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", stat);
	// 	return stat;
	// }
	//PRINT_DBG("numInst_g = %hd\n", numInst);
	if ((*numInst) > 0)
	{
		CyInstHandle = qaeMemAlloc(sizeof(CpaInstanceHandle) * (*numInst));
		// if (CyInstHandle == NULL)
		// {
		// 	PRINT_ERR("Failed to allocate memory for instances\n");
		// 	qaeMemFree((void **)&CyInstHandle);
		// 	return CPA_STATUS_FAIL;
		// }
		/*get the instances handles and place in allocated memory*/
		stat = cpaCyGetInstances((*numInst), CyInstHandle);
		// if (CPA_STATUS_SUCCESS != stat)
		// {
		// 	PRINT_ERR("cpaCyGetInstances failed with status: %d\n", stat);
		// 	qaeMemFree((void **)&CyInstHandle);
		// 	return stat;
		// }
		for (int i = 0; i < (*numInst); i++)
		{
			if (stat = cpaCySetAddressTranslation(*(CyInstHandle + i), sampleVirtToPhys) == CPA_STATUS_FAIL)
				return NULL;
			if (stat = cpaCyStartInstance(*(CyInstHandle + i)) == CPA_STATUS_FAIL)
				return NULL;
			
		}
    }
	return CyInstHandle;
}

CpaStatus getCryptoInstance(Cpa16U* numInst_g, CpaInstanceHandle* inst_g)
{

	CpaStatus status = CPA_STATUS_FAIL;
	Cpa32U i = 0;
	Cpa32U coreAffinity = 0;
	CpaInstanceInfo2 info = { 0 };

	/*get the number of crypto instances*/
	status = cpaCyGetNumInstances(numInst_g);
	// numInst_g--;
	if (CPA_STATUS_SUCCESS != status)
	{
		PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", status);
		return status;
	}
	//PRINT_DBG("numInst_g = %hd\n", *numInst_g);
	if (*numInst_g > 0)
	{
		inst_g = qaeMemAlloc(sizeof(CpaInstanceHandle) * (*numInst_g));
		if (inst_g == NULL)
		{
			PRINT_ERR("Failed to allocate memory for instances\n");
			qaeMemFree((void **)&inst_g);
			return CPA_STATUS_FAIL;
		}
		/*get the instances handles and place in allocated memory*/
		status = cpaCyGetInstances(*numInst_g, inst_g);
		if (CPA_STATUS_SUCCESS != status)
		{
			PRINT_ERR("cpaCyGetInstances failed with status: %d\n", status);
			qaeMemFree((void **)&inst_g);
			return status;
		}

		/*start all instances*/
		for (int i = 0; i < *numInst_g; i++)
		{
			if (status = cpaCySetAddressTranslation(*(inst_g + i), sampleVirtToPhys) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
			if (status = cpaCyStartInstance(*(inst_g + i)) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
			
		}

	}
	else
	{
		PRINT("There are no crypto instances\n");
		return CPA_STATUS_FAIL;
	}
	// numInst_g--;
	return status;
}

CpaStatus QATSetting(Cpa16U* numInst_g, CpaInstanceHandle* CyInstHandle)
{
	CpaStatus stat = CPA_STATUS_SUCCESS;

	stat = qaeMemInit();
	if (CPA_STATUS_SUCCESS != stat)
	{
		PRINT_ERR("Failed to initialise memory driver\n");
		return (int)stat;
	}

	stat = icp_sal_userStartMultiProcess("SHIM", CPA_FALSE);
	if (CPA_STATUS_SUCCESS != stat)
	{
		PRINT_ERR("Failed to start user process SSL\n");
		qaeMemDestroy();
		return (int)stat;
	}

	//stat = fipsSampleGetQaInstance(CyInstHandle);
	//sampleCyStartPolling(*CyInstHandle);
	stat = getCryptoInstance(numInst_g, CyInstHandle);
	return stat;
}

/******************************** END OF the preprocessing of QAT induction ***************************************/

/******************************** START OF Data Wrapping & Transformation ***************************************/

//mpz_export
char* data_export(const mpz_t* mpz_data, size_t* got_count)
{
	void *ret;
	int char_data_size = (*mpz_data)[0]._mp_size * sizeof(mp_limb_t);
	//PRINT_DBG("char_data_size = %d\n", char_data_size);
	char* char_data_ = (char *)malloc(abs(char_data_size));
	memset(char_data_, '\0', abs(char_data_size));

	ret = mpz_export(char_data_, got_count, 1, 1, 1, 0, *mpz_data);
	//PRINT_DBG("got_count = %d\n", *got_count);
	return char_data_;
}

//mpz_import
void data_import(char* char_data, mpz_t* mpz_data, size_t count)
{
	mpz_init(*mpz_data);
	mpz_import(*mpz_data, count, 1, 1, 1, 0, char_data);
}

//According to the binary a and binary length a_size, the QAT interface format aCpaFlatBuffer is obtained
CpaFlatBuffer* WarpData(char* a, size_t a_size, int empty)
{
	CpaStatus status = CPA_STATUS_SUCCESS;
	CpaFlatBuffer* aCpaFlatBuffer = NULL;
	status = OS_MALLOC(&aCpaFlatBuffer, sizeof(CpaFlatBuffer));
	if (status == CPA_STATUS_SUCCESS)
	{
		memset(aCpaFlatBuffer, 0, sizeof(CpaFlatBuffer));
		aCpaFlatBuffer->dataLenInBytes = a_size;
		status = PHYS_CONTIG_ALLOC(&aCpaFlatBuffer->pData, a_size);

		if ((NULL != aCpaFlatBuffer->pData) && (!empty))
		{
			memcpy(aCpaFlatBuffer->pData, a, a_size);
		}
	}
	return aCpaFlatBuffer;
}

/******************************** END OF Data Wrapping & Transformation ***************************************/

//Modular exponentiation interface
CpaFlatBuffer* ModExp(char* a, size_t a_size,
	char* b, size_t b_size,
	char* m, size_t m_size,
	CpaInstanceHandle *pCyInstHandle)
{
	int retval = 1;

	//Encapsulate the data in CpaFlatBuffer format
	CpaFlatBuffer* aCpaFlatBuffer = NULL;
	CpaFlatBuffer* bCpaFlatBuffer = NULL;
	CpaFlatBuffer* mCpaFlatBuffer = NULL;
	CpaFlatBuffer* resultCpaFlatBuffer = NULL;
	aCpaFlatBuffer = WarpData(a, a_size, 0);
	bCpaFlatBuffer = WarpData(b, b_size, 0);
	mCpaFlatBuffer = WarpData(m, m_size, 0);
	resultCpaFlatBuffer = WarpData(NULL, m_size, 1);

	//The underlying implementation interface
	retval = doModExpAsync(
		aCpaFlatBuffer,
		bCpaFlatBuffer,
		mCpaFlatBuffer,
		resultCpaFlatBuffer,
		*pCyInstHandle);

	//free mem
	PHYS_CONTIG_FREE(aCpaFlatBuffer->pData);
	PHYS_CONTIG_FREE(bCpaFlatBuffer->pData);
	PHYS_CONTIG_FREE(mCpaFlatBuffer->pData);
	//PHYS_CONTIG_FREE(resultCpaFlatBuffer->pData);
	OS_FREE(aCpaFlatBuffer);
	OS_FREE(bCpaFlatBuffer);
	OS_FREE(mCpaFlatBuffer);
	//OS_FREE(resultCpaFlatBuffer);

	PRINT_DBG("end of ModExp!\n");
	return resultCpaFlatBuffer;


}

/******************************** START OF ModInv ***************************************/

mpz_t g;
char* gInv_char_data = NULL;
size_t gInv_count = 0;

void getInv(const mpz_t* input, mpz_t* n)
{
	// Initialize g
	if(gInv_count == 0)
		mpz_init(g);

	if (mpz_cmp(g, *input) != 0)	//g != *input
	{
		mpz_set(g, *input);
		mpz_t g_inv;
		mpz_init(g_inv);
		mpz_invert(g_inv, *input, *n);
		gInv_char_data = data_export(g_inv, &gInv_count);
	}
	else
		return;
}

/******************************** END OF ModInv ***************************************/

//Modular exponentiation operation top-level interface function
void PowModN (mpz_t *output, const mpz_t *input, const mpz_t *power, const mpz_t *n, CpaInstanceHandle *pCyInstHandle) {
 	//export
 	char *power_char_data, *input_char_data, *n_char_data;	//Binary data
 	size_t power_count, input_count, n_count;	//Binary length
 	power_char_data = data_export(power, &power_count);	//The parameters are converted to binary data to adapte the QAT interface
 	input_char_data = data_export(input, &input_count);
 	n_char_data = data_export(n, &n_count);

 	CpaFlatBuffer *result_flat_data;	//Modular exponentiation results
 	CpaFlatBuffer *modInv_flat_data;	//ModInv results
 	mpz_t result_mpz_data;
	mpz_inits(result_mpz_data,NULL);

 	if((*power)[0]._mp_size > 0)
 	{
		//Modular exponentiation
 		result_flat_data = ModExp(	input_char_data, input_count,
 			power_char_data, power_count,
 			n_char_data, n_count,
			pCyInstHandle);

		//QAT format CpaFlatBuffer to GMP format mpz_t
 		data_import((char*)(result_flat_data->pData), &result_mpz_data, (size_t)(result_flat_data->dataLenInBytes));

 		mpz_set(*output, result_mpz_data);

		//free mem
		PHYS_CONTIG_FREE(result_flat_data->pData);
		OS_FREE(result_flat_data);
 	}
 	else if((*power)[0]._mp_size < 0)	//Preprocess when the index is negative
 	{
		getInv(input, n);
		//Modular exponentiation
		result_flat_data = ModExp(gInv_char_data, gInv_count,
			power_char_data, power_count,
			n_char_data, n_count,
			pCyInstHandle);

		//QAT format CpaFlatBuffer to GMP format mpz_t
		data_import((char*)(result_flat_data->pData), result_mpz_data, (size_t)(result_flat_data->dataLenInBytes));

		mpz_set(*output, result_mpz_data);

		//free mem
		PHYS_CONTIG_FREE(result_flat_data->pData);
		OS_FREE(result_flat_data);
 	}
 	else   //Index is 0
 	{
 		mpz_set_ui(*output, 1);
 	}

	//free mem
	free(power_char_data);
	free(input_char_data);
	free(n_char_data);

	//PRINT_DBG("end of PowModN !\n");
}