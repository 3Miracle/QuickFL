#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <unistd.h>
#include <openssl/async.h>
#include <openssl/crypto.h>
#include <pthread.h>

# include <sys/epoll.h>
# include <sys/types.h>
# include <sys/eventfd.h>
# include <fcntl.h>
# include <sched.h>
#include <sys/time.h>

#include "../include/libhcs/QAT_paillier_offload.h"


struct pcs_enc_t {
	int tes1;
	CpaInstanceHandle *CyInstHandle;
	pcs_public_key *pk;
	pcs_private_key *vk;
	hcs_random *hr;
	int *pTaskNum;
	struct timeval* pT_sum;
	};
int job_progress=0;

int test_encrypt(void *voidArg){
	struct pcs_enc_t *arg = (struct pcs_enc_t *)voidArg;
	mpz_t tmp;
	mpz_inits(tmp,NULL);
	(*(arg->pTaskNum))++;
	mpz_set_ui(tmp,(unsigned long int)(arg->tes1+120));
	//pcs_encrypt_crt(arg->pk, arg->vk, arg->hr, tmp, tmp, arg->CyInstHandle);
	pcs_encrypt(arg->pk, arg->hr, tmp, tmp, arg->CyInstHandle);
	(*(arg->pTaskNum))--;
	mpz_clear(tmp);
	return 0;
}

extern "C" {
	CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle,
		Cpa32U response_quota);
}

//CpaInstanceHandle CyInstHandle[3] = { 0 };
//CpaInstanceHandle *CyInstHandle;
Cpa16U numInst;
int i;
int qat_keep_polling=1;

int main(void)
{
	CpaInstanceHandle *CyInstHandle = QAT_initial(&numInst);

	// initialize data structures
	pcs_public_key *pk = pcs_init_public_key();
	pcs_private_key *vk = pcs_init_private_key();
    hcs_random *hr = hcs_init_random();
	// Generate a key pair with modulus of size 2048 bits
	pcs_generate_key_pair(pk, vk, hr, 2048);

	int ret;
	volatile int taskNum = 0;
    struct timeval t_sum = {0,0};
	ASYNC_JOB* job = NULL;  // Coroutine handles
	ASYNC_WAIT_CTX* wctx = NULL;
	wctx = ASYNC_WAIT_CTX_new();
	if (wctx == NULL) {
		printf("Failed to create ASYNC_WAIT_CTX\n");
		abort();
	}
	struct timeval t_val;
	struct timeval t_val_end;
	struct timeval t_result;
	double consume;
	struct pcs_enc_t* pArg = (struct pcs_enc_t*)malloc(sizeof(struct pcs_enc_t));
	gettimeofday(&t_val, NULL);
	for(int tes=0;tes<10000;tes++){
		pArg->CyInstHandle = CyInstHandle+ (tes % 18);
		pArg->pk = pk;
		pArg->vk = vk;
		pArg->hr = hr;
		pArg->tes1 = tes;
		pArg->pTaskNum = &taskNum;
        pArg->pT_sum = &t_sum;
		job = NULL;
		if (taskNum >= 90) 
				{
					 //Trigger a poll
					for (i = 0; i < numInst; i++){
						icp_sal_CyPollInstance(CyInstHandle[i], 0);
					}
					while (taskNum > 1022) //Continuous polling
					{
						for (i = 0; i < numInst; i++){
							icp_sal_CyPollInstance(CyInstHandle[i], 0);

						}
						//if (CPA_STATUS_RETRY == icp_sal_CyPollInstance(*pCyInstHandle, 0));
						//sleep(1);
					}
				}
		switch (ASYNC_start_job(&job, wctx, &ret, test_encrypt, pArg, sizeof(struct pcs_enc_t)))
				{
				case ASYNC_ERR:
				case ASYNC_NO_JOBS:
					printf("An error occurred\n");
					goto end;
				case ASYNC_PAUSE:
					//++job_progress;
					break;
				case ASYNC_FINISH:
					printf("Job finished with return value %d\n", ret);
					break;
				}
	}

	while(taskNum != 0) {
		for (i = 0; i < 3; i++){
			icp_sal_CyPollInstance(CyInstHandle[i], 0);
		}		
	}

	qat_keep_polling = 0;
	gettimeofday(&t_val_end, NULL);
	timersub(&t_val_end, &t_val, &t_result);
	consume = t_result.tv_sec + (1.0 * t_result.tv_usec) / 1000000;
	printf("-------------- elapsed time= %fs \n", consume);
	printf("-------------- Throughput = %f\n", 10000 / consume);

	pcs_free_public_key(pk);
	pcs_free_private_key(vk);
	hcs_free_random(hr);
	//sampleCyStopPolling();
	// cpaCyStopInstance(CyInstHandle);
	// icp_sal_userStop();
    // qaeMemDestroy();
    return 0;
end:
	ASYNC_WAIT_CTX_free(wctx);
	printf("Finishing\n");
    
    hcs_free_random(hr);
}