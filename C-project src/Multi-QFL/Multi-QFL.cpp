#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <stdlib.h>
#include <string.h>
#include "pcs_matrix.h"
#include <sys/time.h>
#include <pthread.h>

# include <sys/epoll.h>
# include <sys/types.h>
# include <sys/eventfd.h>
# include <fcntl.h>
# include <unistd.h>
#include <openssl/crypto.h>


static sampleThread gPollingThreadMultiInst;
static volatile int gPollingCyMultiInst = 0; // 增加volatile
struct pollingParam {
	CpaInstanceHandle* pCyInstHandle;
	Cpa16U numInst;
};

extern "C" {
	CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle,
		Cpa32U response_quota);
}
/*
* This function polls a crypto instance.
*
*/
static void sal_pollingMultiInst(void* argVoid)
{
	struct pollingParam* arg = (struct pollingParam*)argVoid;
	gPollingCyMultiInst = 1;
	int i;
	while (gPollingCyMultiInst)
	{
		for (i = 0; i < arg->numInst; i++)
		{
			icp_sal_CyPollInstance(arg->pCyInstHandle[i], 0);
		}
		OS_SLEEP(10);
	}
	free(arg);
	sampleThreadExit();
}
/*
* This function checks the instance info. If the instance is
* required to be polled then it starts a polling thread.
*/
void sampleCyStartPollingMultiInst(CpaInstanceHandle* pCyInstHandle, Cpa16U numInst)
{
	struct pollingParam* pArg = (struct pollingParam*)malloc(sizeof(struct pollingParam));
	pArg->numInst = numInst;
	pArg->pCyInstHandle = pCyInstHandle;

	/* Start thread to poll instance */
	sampleThreadCreate(&gPollingThreadMultiInst, sal_pollingMultiInst, pArg);

	//free(pArg);
}
/*
* This function stops the polling of a crypto instance.
*/
void sampleCyStopPollingMultiInst(void)
{
	gPollingCyMultiInst = 0;
	OS_SLEEP(10);
}
int qat_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr,
                      void *(*start_func) (void *), void *pArg)
{
    return pthread_create(pThreadId, attr, start_func,(void *)pArg);
}
int qat_fcntl(int fd, int cmd, int arg)
{
    return fcntl(fd, cmd, arg);
}

// //CpaInstanceHandle CyInstHandle[48] = { 0 };
// CpaInstanceHandle *CyInstHandle;
Cpa16U numInst;

// instance
CpaInstanceHandle pCyInstHandle[96] = { 0 };
//CpaInstanceHandle *pCyInstHandle;
//unsigned short numInst;

// pk & vk
pcs_public_key* pk;
pcs_private_key* vk;
hcs_random* hr;

// thread
pthread_t* threads;
struct threadArg {
	int thread_index;
	int bitKey;
	int pollThreshold;
};

// Thread function
void* singleThreadFunc(void* arg)
{
	struct threadArg* Arg = (struct threadArg*)arg;

	// The input and output data are all one-dimensional, that is, one data is repeatedly calculated
	//int m = 1;
	int n = 1;
	// Input
	simple_matrix* mul_mat_int = simple_matrix_init(n, n);
	// Output
	//PCS_matrix* mul_mat_enc = PCS_init_matrix(n, n);
	PCS_matrix* mul_mat_enc;

	// Data to be encrypted
	mpz_t temp;
	mpz_init(temp);
	mpz_set_si(temp, 1);
	mpz_mul_2exp(temp, temp, Arg->bitKey - 1);
	simple_mat_set_value(mul_mat_int, temp, 0, 0);

	// Matrix encrypt
	mul_mat_enc = matrix_encrypt(pk, vk, mul_mat_int, pCyInstHandle + + Arg->thread_index % numInst, Arg->pollThreshold);

	free(arg);
	simple_matrix_free(mul_mat_int);
	PCS_free_matrix(mul_mat_enc);
}


int Test(int nThread, int bitKey, int pollThreshold) {
	CpaStatus rt = QATSetting(&numInst, pCyInstHandle);	//QAT initialization
	//int numThread = 3;

	
    // initialize data structures
    pk = pcs_init_public_key();
    vk = pcs_init_private_key();
    hr = hcs_init_random();

    // Generate a key pair with modulus of size "bitKey" bits
    pcs_generate_key_pair(pk, vk, hr, bitKey);
	sampleCyStartPollingMultiInst(pCyInstHandle,numInst);

	threads = (pthread_t*)malloc(sizeof(pthread_t*) * nThread);
	int thread_index = 0;

	//timeval start
	struct timeval t_val;
	gettimeofday(&t_val, NULL);
	//printf("init start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
	long sec = t_val.tv_sec;
	time_t t_sec = (time_t)sec;

	// Each thread makes a task submission
	for (thread_index = 0; thread_index < nThread; thread_index++)
	{
		//int* arg = (int*)malloc(sizeof(int));
		//*arg = thread_index;
		struct threadArg* arg = (struct threadArg*)malloc(sizeof(struct threadArg));
		arg->bitKey = bitKey;
		arg->pollThreshold = pollThreshold;
		arg->thread_index = thread_index;

		printf("Create thread %d\n", thread_index);
		pthread_create(&threads[thread_index], NULL, singleThreadFunc, arg);
	}

	// Wait for the end of the running thread
	for (thread_index = 0; thread_index < nThread; thread_index++)
	{
		pthread_join(threads[thread_index], NULL);
	}

	//timeval end
	struct timeval t_val_end;
	gettimeofday(&t_val_end, NULL);
	struct timeval t_result;
	timersub(&t_val_end, &t_val, &t_result);
	double consume = t_result.tv_sec + (1.0 * t_result.tv_usec) / 1000000;
	printf("-------------- elapsed time= %fs \n", consume);
	printf("-------------- Throughput = %f\n", 1000.0 * nThread / consume);

	free(threads);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    hcs_free_random(hr);
	sampleCyStopPollingMultiInst();
}

int main()
{
	//Multiple sets of tests with different parameters
	for (int nThread = 1024; nThread <= 1024; nThread *= 3)
	//for (int nThread = 6; nThread <= 6; nThread *= 3)	//Number of threads
	{
		for (int bitKey = 2048; bitKey <= 2048; bitKey *= 2)	//The length of the key
		{
			for (int pollThreshold = 1024; pollThreshold <= 1024; pollThreshold *= 2)	//Polling threshold
			{
				printf("******************nThread = %d, bitKey = %d, pollThreshold = %d********************\n", nThread, bitKey, pollThreshold);
				Test(nThread, bitKey, pollThreshold);
			}
		}
	}
	return 0;
}