#include "QHCS_bench.h"

#include <openssl/async.h>
#include <openssl/crypto.h>
#include <unistd.h>

#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>

# include <errno.h>
# include <sys/epoll.h>
# include <sys/types.h>
# include <sys/eventfd.h>
#include <sched.h>
# include <sys/time.h>
# include <fcntl.h>

//--------------------------------------------------------------------- simple matrix

simple_matrix *simple_matrix_init(int m,int n){
    simple_matrix *mat=(simple_matrix *)malloc(sizeof(simple_matrix));
    mat->simple_array=(mpz_t *)malloc(m*n*sizeof(mpz_t));
    mat->m=m;
    mat->n=n;
    for(int i=0;i<m*n;i++){
        mpz_init(mat->simple_array[i]);
    }
    return mat;
}

void simple_matrix_free(simple_matrix *mat){
    free(mat->simple_array);
    free(mat);
}
void simple_mat_set_value(simple_matrix *mat,mpz_t val,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(mat->simple_array[index],val);
}

void simple_mat_get_value(simple_matrix *mat,mpz_t ret,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(ret,mat->simple_array[index]);
}

//------------------------------------------------------------------------ cipher matrix

PCS_matrix *PCS_init_matrix(int m,int n){
    PCS_matrix *mat=(PCS_matrix *)malloc(sizeof(PCS_matrix));
    mat->PCS_array=(mpz_t *)malloc(m*n*sizeof(mpz_t));
    mat->m=m;
    mat->n=n;
    for(int i=0;i<m*n;i++){
        mpz_init(mat->PCS_array[i]);
    }
    return mat;
}

void PCS_free_matrix(PCS_matrix *mat){
    free(mat->PCS_array);
    free(mat);
}
void PCS_mat_set_value(PCS_matrix *mat,mpz_t val,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(mat->PCS_array[index],val);
}

void PCS_mat_get_value(PCS_matrix *mat,mpz_t ret,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(ret,mat->PCS_array[index]);
}

//-------------------------------------------------------------------------------- matrix encrypt

struct elem_enc_t {
	simple_matrix* src_matrix;
	PCS_matrix* des_matrix;
	int i;
	int j;
	int k;
	CpaInstanceHandle *pCyInstHandle;
	pcs_public_key *pk;
	pcs_private_key *vk;
	hcs_random *hr;
	ASYNC_JOB **jobs;
    ASYNC_WAIT_CTX **awcs;
	//int *pTaskNum;
    //struct timeval* pT_sum;
};
pthread_t qat_polling_thread;
int qat_keep_polling = 1;
int internal_efd = 0;
typedef struct {
    int eng_fd;
    int inst_index;
} ENGINE_EPOLL_ST;
struct epoll_event eng_epoll_events[48] = {{ 0 }};
ENGINE_EPOLL_ST eng_poll_st[48] = {{ -1 }};
CpaInstanceHandle *pCyInstHandle = NULL;
Cpa16U numInst;
int jobs_inprogress = 0;


typedef struct sample_code_thread_attr_s
{
    char *name;       /**< name */
    Cpa32U stackSize; /**< stack size */
    Cpa32U priority;  /**< priority */
    Cpa32S policy;    /**< policy */
} sample_code_thread_attr_t;
typedef void (*performance_func_t)(void *);
#define CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(ptr)                             \
    if (ptr == NULL)                                                           \
    {                                                                          \
        PRINT_ERR(                                                             \
            "%s():%d NULL pointer error: [" #ptr "]", __func__, __LINE__);     \
        return CPA_STATUS_FAIL;                                                \
    }
//int taskNum = 0;

// static sampleThread gPollingThreadMultiInst;
// static volatile int gPollingCyMultiInst = 0; // 增加volatile
// struct pollingParam {
// 	CpaInstanceHandle* pCyInstHandle;
// 	Cpa16U numInst;
// };

// extern "C" {
// 	CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle,
// 		Cpa32U response_quota);
// }
// /*
// * This function polls a crypto instance.
// *
// */
// // static void sal_pollingMultiInst(void* argVoid)
// // {
// // 	struct pollingParam* arg = (struct pollingParam*)argVoid;
// // 	gPollingCyMultiInst = 1;
// // 	int i;
// // 	while (gPollingCyMultiInst)
// // 	{
// // 		for (i = 0; i < arg->numInst; i++)
// // 		{
// // 			icp_sal_CyPollInstance(arg->pCyInstHandle[i], 0);
// // 		}
// // 		OS_SLEEP(10);
// // 	}
// // 	free(arg);
// // 	sampleThreadExit();
// // }

// /*
// * This function checks the instance info. If the instance is
// * required to be polled then it starts a polling thread.
// */
// void sampleCyStartPollingMultiInst(CpaInstanceHandle* pCyInstHandle, Cpa16U numInst)
// {
// 	struct pollingParam* pArg = (struct pollingParam*)malloc(sizeof(struct pollingParam));
// 	pArg->numInst = numInst;
// 	pArg->pCyInstHandle = pCyInstHandle;

// 	/* Start thread to poll instance */
// 	sampleThreadCreate(&gPollingThreadMultiInst, sal_pollingMultiInst, pArg);

// 	//free(pArg);
// }
// /*
// * This function stops the polling of a crypto instance.
// */
// void sampleCyStopPollingMultiInst(void)
// {
// 	gPollingCyMultiInst = 0;
// 	OS_SLEEP(10);
// }

static void pollingMultiInst()
{
	qat_keep_polling = 1;
	int i;
	while (qat_keep_polling)
	{
		for (i = 0; i < numInst; i++)
		{
			icp_sal_CyPollInstance(pCyInstHandle[i], 0);
		}
		OS_SLEEP(10);
	}
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

int qat_async_epoll(struct epoll_event *events,
                     int timeout)
{
    int n = 0, i = 0;
    ENGINE_EPOLL_ST* epollst = NULL;
    n = epoll_wait(internal_efd, events, 48, timeout);
    for (i = 0; i < n; ++i) {
        if ((events[i].data.ptr) && (events[i].events & EPOLLIN)) {
            epollst = (ENGINE_EPOLL_ST*)events[i].data.ptr;
            icp_sal_CyPollInstance(pCyInstHandle[epollst->inst_index], 0);
        }
    }
    return 1;
}

CpaStatus sampleCodeThreadCreate(pthread_t *thread,
                                 sample_code_thread_attr_t *threadAttr,
                                 performance_func_t function,
                                 void *params)
{
    // CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);
    // CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(function);

    int status = 1;
    pthread_attr_t attr;
    struct sched_param param;
    Cpa32U pmin = 0;
    Cpa32U pmax = 0;

    status = pthread_attr_init(&attr);
    if (status != 0)
    {
        printf("%d\n", errno);
        return CPA_STATUS_FAIL;
    }

    /* Setting scheduling parameter will fail for non root user,
     * as the default value of inheritsched is PTHREAD_EXPLICIT_SCHED in
     * POSIX. It is not required to set it explicitly before setting the
     * scheduling policy */

    if (threadAttr == NULL)
    {
        status = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        if (status != 0)
        {
            pthread_attr_destroy(&attr);
            printf("%d\n", errno);
            return CPA_STATUS_FAIL;
        }

        status =
            pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
        if (status != 0)
        {
            pthread_attr_destroy(&attr);
            printf("%d\n", errno);
            return CPA_STATUS_FAIL;
        }

        /* Set priority based on value in threadAttr */
        memset(&param, 0, sizeof(param));
        param.sched_priority = 0;

        status = pthread_attr_setschedparam(&attr, &param);
        if (status != 0)
        {
            pthread_attr_destroy(&attr);
            printf("%d\n", errno);
            return CPA_STATUS_FAIL;
        }
    }
    else
    {
        /* Set scheduling policy based on value in threadAttr */

        if ((threadAttr->policy != SCHED_RR) &&
            (threadAttr->policy != SCHED_FIFO) &&
            (threadAttr->policy != SCHED_OTHER))
        {
            threadAttr->policy = SCHED_OTHER;
        }

        status = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        if (status != 0)
        {
            printf("%d\n", errno);
            pthread_attr_destroy(&attr);
            return CPA_STATUS_FAIL;
        }

        status = pthread_attr_setschedpolicy(&attr, threadAttr->policy);
        if (status != 0)
        {
            printf("%d\n", errno);
            pthread_attr_destroy(&attr);
            return CPA_STATUS_FAIL;
        }

        /* Set priority based on value in threadAttr */
        memset(&param, 0, sizeof(param));

        pmin = sched_get_priority_min(threadAttr->policy);
        pmax = sched_get_priority_max(threadAttr->policy);
        if (threadAttr->priority > pmax)
        {
            threadAttr->priority = pmax;
        }
        if (threadAttr->priority < pmin)
        {
            threadAttr->priority = pmin;
        }
        param.sched_priority = threadAttr->priority;
        if (threadAttr->policy != SCHED_OTHER)
        {
            status = pthread_attr_setschedparam(&attr, &param);
            if (status != 0)
            {
                printf("%d\n", errno);
                pthread_attr_destroy(&attr);
                return CPA_STATUS_FAIL;
            }
        }
    }

    status = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (status != 0)
    {
        printf("%d\n", errno);
        pthread_attr_destroy(&attr);
        return CPA_STATUS_FAIL;
    }

    status = pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    if (status != 0)
    {
        printf("%d\n", errno);
        pthread_attr_destroy(&attr);
        return CPA_STATUS_FAIL;
    }

    /*pthread_create expects "void *(*start_routine)(void*)" as the 3rd argument
     * but we are calling functions with return void instead of void*, normally
     * the return value of the start_routine contains the exit status, in this
     * sample code we track any internal errors in the start_routine, to allow
     * this to compile we need to cast "function" parameter, this is the same
     * as calling it as  void *(*function)(void*)*/
    status = pthread_create(thread, &attr, (void *(*)(void *))function, params);
    if (status != 0)
    {
        printf("%d\n", errno);
        pthread_attr_destroy(&attr);
        return CPA_STATUS_FAIL;
    }
    /*destroy the thread attributes as they are no longer required, this does
     * not affect the created thread*/
    pthread_attr_destroy(&attr);
    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadBind(pthread_t *thread, Cpa32U logicalCore)
{
    int status = 1;
    cpu_set_t cpuset;
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);
    CPU_ZERO(&cpuset);
    CPU_SET(logicalCore, &cpuset);

    status = pthread_setaffinity_np(*thread, sizeof(cpu_set_t), &cpuset);
    if (status != 0)
    {
        return CPA_STATUS_FAIL;
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus sampleCodeThreadStart(pthread_t *thread)
{
    CHECK_POINTER_AND_RETURN_FAIL_IF_NULL(thread);
    return CPA_STATUS_SUCCESS;
}


static int event_poll_func(CpaInstanceHandle instanceHandle)
{
    int fd = 0;
    int i = 0;
    int n = 0;
    int efd = 0;
    struct epoll_event event;
    struct epoll_event *events;
    CpaStatus status = CPA_STATUS_FAIL;

    typedef CpaStatus (*ptr2_icp_sal_GetFileDescriptor)(CpaInstanceHandle,
                                                        int *);
    typedef CpaStatus (*ptr2_icp_sal_PutFileDescriptor)(CpaInstanceHandle, int);
    typedef CpaStatus (*ptr2_icp_sal_PollInstance)(CpaInstanceHandle, Cpa32U);
    ptr2_icp_sal_GetFileDescriptor getFileDescriptorFn = NULL;
    ptr2_icp_sal_PollInstance pollInstanceFn = NULL;
    ptr2_icp_sal_PutFileDescriptor putFileDescriptorFn = NULL;
	getFileDescriptorFn = icp_sal_CyGetFileDescriptor;
	pollInstanceFn = icp_sal_CyPollInstance;
	putFileDescriptorFn = icp_sal_CyPutFileDescriptor;
    if (getFileDescriptorFn == NULL || pollInstanceFn == NULL ||
        putFileDescriptorFn == NULL)
    {
        printf("Error initializing event polling mechanism for servcie %d\n");
        return -1;
    }

    if (CPA_STATUS_SUCCESS != getFileDescriptorFn(instanceHandle, &fd))
    {
        printf("Error getting CY file descriptor for epoll instance\n");
        return -1;
    }

    efd = epoll_create1(0);
    if (-1 == efd)
    {
        printf("Error creating epoll fd for instance\n");
        return -1;
    }
    event.data.fd = fd;
    event.events = EPOLLIN;
    if (-1 == epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event))
    {
        printf("Error adding fd to epoll: %d\n");
        return -1;
    }

    events = qaeMemAlloc(1 * sizeof(event));
    if (NULL == events)
    {
        printf("Error allocating memory for epoll events\n");
        return -1;
    }

    while (qat_keep_polling)
    {
        n = epoll_wait(efd, events, 1, 100);
        for (i = 0; i < n; i++)
        {
            if (fd == events[i].data.fd && (events[i].events & EPOLLIN))
            {
                status = pollInstanceFn(instanceHandle, 0);
                if ((CPA_STATUS_SUCCESS != status) &&
                    (CPA_STATUS_RETRY != status))
                {
                    printf("Error:poll instance returned status %d\n",
                              status);
                }
            }
        }
    }
    if (-1 == epoll_ctl(efd, EPOLL_CTL_DEL, fd, &event))
    {
        printf("Error removing fd from epoll\n");
    }
    qaeMemFree((void **)&events);
    putFileDescriptorFn(instanceHandle, fd);
    close(efd);
    return 0;
}

CpaStatus cyCreatePollingThreadsIfPollingIsEnabled(void)
{
    CpaInstanceInfo2 *instanceInfo2 = NULL;
    Cpa16U i = 0, j = 0, numCreatedPollingThreads = 0;
    Cpa32U coreAffinity = 0;
	//pthread_t *pollingThread_g;
    CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa16U numPolledInstances_g = 0;
    performance_func_t *pollFnArr = NULL;
    // Cpa32U numCores = 0;
    // numCores = (Cpa32U)20;
	// printf("numcores = %d",numCores);
	instanceInfo2 = qaeMemAlloc(numInst * sizeof(CpaInstanceInfo2));
	if (NULL == instanceInfo2)
	{
		printf("Failed to allocate memory for pInstanceInfo2\n");
		return CPA_STATUS_FAIL;
	}
	pollFnArr = qaeMemAlloc(numInst * sizeof(performance_func_t));
	if (NULL == pollFnArr)
	{
		printf("Failed to allocate memory for polling functions\n");

		qaeMemFree((void **)&instanceInfo2);
		return CPA_STATUS_FAIL;
	}
	for (i = 0; i < numInst; i++)
	{
		status = cpaCyInstanceGetInfo2(pCyInstHandle[i], &instanceInfo2[i]);
		if (CPA_STATUS_SUCCESS != status)
		{
			qaeMemFree((void **)&instanceInfo2);
			qaeMemFree((void **)&pollFnArr);
			return CPA_STATUS_FAIL;
		}
		pollFnArr[i] = NULL;
		if (CPA_TRUE == instanceInfo2[i].isPolled)
		{
			numPolledInstances_g++;
			if (CPA_STATUS_SUCCESS == status)
			{
				pollFnArr[i] = event_poll_func;
				continue;
			}
			else if (CPA_STATUS_FAIL == status)
			{
				printf("Error getting file descriptor for Event based "
							"instance #%d\n",
							i);
				qaeMemFree((void **)&instanceInfo2);
				qaeMemFree((void **)&pollFnArr);
				return CPA_STATUS_FAIL;
			}
		}
	}
	if (0 == numPolledInstances_g)
	{
		qaeMemFree((void **)&instanceInfo2);
		qaeMemFree((void **)&pollFnArr);
		return CPA_STATUS_SUCCESS;
	}
	pollingThread_g =
		qaeMemAlloc(numPolledInstances_g * sizeof(pthread_t));
	if (NULL == pollingThread_g)
	{
		printf("Failed to allocate memory for polling threads\n");
		qaeMemFree((void **)&instanceInfo2);
		qaeMemFree((void **)&pollFnArr);
		return CPA_STATUS_FAIL;
	}
	for (i = 0; i < numInst; i++)
	{
		if (NULL != pollFnArr[i])
		{
			status = sampleCodeThreadCreate(
				&pollingThread_g[numCreatedPollingThreads],
				NULL,
				pollFnArr[i],
				pCyInstHandle[i]);
			if (status != CPA_STATUS_SUCCESS)
			{
				printf("Error starting polling thread %d\n", status);
				/*attempt to stop any started service, we dont check status
					* as some instances may not have been started and this
					* might return fail
					* */
				qaeMemFree((void **)&instanceInfo2);
				qaeMemFree((void **)&pollFnArr);
				return CPA_STATUS_FAIL;
			}
			/*loop of the instanceInfo coreAffinity bitmask to find the core
				*  affinity*/
			for (j = 0; j < CPA_MAX_CORES; j++)
			{
				if (CPA_BITMAP_BIT_TEST(instanceInfo2[i].coreAffinity, j))
				{
					coreAffinity = j;
					break;
				}
			}
			// if (numInst % numCores == 0)
			// {
			// 	/* To avoid recalculated and original core
			// 		* assignment equality */
			// 	coreAffinity =
			// 		(coreAffinity + numInst + 1) % numCores;
			// }
			// else
			// {
			// 	coreAffinity = (coreAffinity + numInst) % numCores;
			// }
			sampleCodeThreadBind(&pollingThread_g[numCreatedPollingThreads],
									coreAffinity);


			sampleCodeThreadStart(
				&pollingThread_g[numCreatedPollingThreads]);

			numCreatedPollingThreads++;
		}
	}
	qaeMemFree((void **)&instanceInfo2);
	qaeMemFree((void **)&pollFnArr);

    return CPA_STATUS_SUCCESS;
}


//event_poll function
// void *event_poll_func()
// {
//     CpaStatus status = 0;
//     struct epoll_event *events = NULL;
//     ENGINE_EPOLL_ST* epollst = NULL;

//     /* Buffer where events are returned */
//     events = OPENSSL_zalloc(sizeof(struct epoll_event) * 48);
//     if (NULL == events) {
//         printf("Error allocating events list\n");
//         goto end;
//     }

//     while (qat_keep_polling) {
//         int n = 0;
//         int i = 0;

//         n = epoll_wait(internal_efd, events, 48, 1000);
//         for (i = 0; i < n; ++i) {
//             if (events[i].events & EPOLLIN) {
//                 /*  poll for 0 means process all packets on the ET ring */
//                 epollst = (ENGINE_EPOLL_ST*)events[i].data.ptr;
//                 status = icp_sal_CyPollInstance(pCyInstHandle[epollst->inst_index], 0);
//                 if (CPA_STATUS_SUCCESS != status) {
//                     printf("icp_sal_CyPollInstance returned status %d\n", status);
//                 }
//             }
//         }
//     }
//     OPENSSL_free(events);
//     events = NULL;
// end:
//     return NULL;
// }


int element_encrypt(void *argVoid)
{
	struct elem_enc_t *arg = (struct elem_enc_t *)argVoid;
	//(*(arg->pTaskNum))++;

	//timeval start
	struct timeval t_val;
	gettimeofday(&t_val, NULL);

	mpz_t tmp1;
	mpz_init(tmp1);
	simple_mat_get_value(arg->src_matrix, tmp1, arg->i, arg->j);
	pcs_encrypt(arg->pk, arg->hr, tmp1, tmp1, arg->pCyInstHandle);
	gmp_printf("adasdadasdqeqweqwe %Zd\n", tmp1);
	PCS_mat_set_value(arg->des_matrix, tmp1, arg->i, arg->j);
	--jobs_inprogress;

	//timeval end
	// struct timeval t_val_end;
	// gettimeofday(&t_val_end, NULL);
	// struct timeval t_result;
	// timersub(&t_val_end, &t_val, &t_result);
	// timeradd(arg->pT_sum, &t_result, arg->pT_sum); 

	//free(arg);
	//(*(arg->pTaskNum))--;
	//printf("async_job completed with taskNum = %d !\n", *(arg->ptaskNum));
	return 0;
}

// QAT API
extern "C" {
	CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle,
		Cpa32U response_quota);
}

PCS_matrix *matrix_encrypt(pcs_public_key *pk,pcs_private_key *vk,simple_matrix *mat, CpaInstanceHandle* pCyInstHandle){

    PCS_matrix *mat_ret=PCS_init_matrix(mat->m,mat->n);
	int Num = (mat->m) * (mat->n);
    hcs_random *hr = hcs_init_random();

	// elem_enc_t arg
	// int taskNum = 0;
    // struct timeval t_sum;
	// struct timeval* pT_sum;
	struct elem_enc_t* pArg = (struct elem_enc_t*)malloc(sizeof(struct elem_enc_t));
	//*(pArg->pTaskNum) = 0;
	// *(pArg->pT_sum) = {0};

    int ret;
	int i,j,num1;
	OSSL_ASYNC_FD job_fd = 0;
    OSSL_ASYNC_FD max_fd = 0;
    int select_result = 0;
    size_t numfds;
    fd_set waitfdset;
    struct timeval select_timeout;
    FD_ZERO(&waitfdset);
    select_timeout.tv_sec = 0;
    select_timeout.tv_usec = 0;

	// pArg->jobs = OPENSSL_malloc(sizeof(ASYNC_JOB*)*100);
    // if (pArg->jobs == NULL) {
    //     printf("# FAIL: Unable to allocate args.jobs\n");
    // }
    // pArg->awcs = OPENSSL_malloc(sizeof(ASYNC_WAIT_CTX*)*100);
    // if (pArg->awcs == NULL) {
    //     printf("# FAIL: Unable to allocate args.awcs\n");
    // }
    // memset(pArg->jobs, 0, sizeof(ASYNC_JOB*)*100);
    // memset(pArg->awcs, 0, sizeof(ASYNC_WAIT_CTX*)*100);
    // for (i =0; i < 100; i++) {
    //     pArg->awcs[i] = ASYNC_WAIT_CTX_new();
    //     if (pArg->awcs[i] == NULL) {
    //         printf("# FAIL: Unable to allocate args.awcs[%d]\n", i);
    //     }
    // }
	// struct epoll_event *events = calloc(48, sizeof(struct epoll_event));
    // if (events == NULL) {
    //     printf("# FAIL: Error allocating memory events.\n");
    //     return ret;
    //}
	ASYNC_JOB* job = NULL; 
	ASYNC_WAIT_CTX* wctx = NULL;
	wctx = ASYNC_WAIT_CTX_new();
	if (wctx == NULL) {
		printf("Failed to create ASYNC_WAIT_CTX\n");
		abort();
	}

    // for (int k = 0; k < 1000; k++) {
	// 	for (int i = 0; i < mat->m; i++) {
	// 		for (int j = 0; j < mat->n; j++) {
	// 			struct timeval t_val;
	// 			gettimeofday(&t_val, NULL);

	// 			mpz_t tmp1;
	// 			mpz_init(tmp1);
	// 			simple_mat_get_value(mat, tmp1, i, j);
	// 			pcs_encrypt(pk, hr, tmp1, tmp1, pCyInstHandle);
	// 			PCS_mat_set_value(mat_ret, tmp1, i, j);

	// 			timeval end
	// 			struct timeval t_val_end;
	// 			gettimeofday(&t_val_end, NULL);
	// 			struct timeval t_result;
	// 			timersub(&t_val_end, &t_val, &t_result);
	// 			timeradd(pT_sum, &t_result, pT_sum);
	// 		}
	// 	}
	// }	
	for(num1 = 0; num1 < 1000; num1++){
		for (i = 0; i < mat->m; i++) {
			for (j = 0; j < mat->n; j++) {
				pArg->src_matrix = mat;
				pArg->des_matrix = mat_ret;
				pArg->i = i;
				pArg->j = j;
				pArg->k = i*(mat->m)+j;
				pArg->pCyInstHandle = pCyInstHandle + (num1)%3;
				pArg->pk = pk;
				pArg->vk = vk;
				pArg->hr = hr;
				// pArg->pTaskNum = &taskNum;
				// pArg->pT_sum = &t_sum;
				job = NULL;
				
				//Initiate a coroutine to submit an encryption task
				switch (ASYNC_start_job(&job, wctx, &ret, element_encrypt, pArg, sizeof(struct elem_enc_t)))
				{
				case ASYNC_ERR:
				case ASYNC_NO_JOBS:
					printf("An error occurred\n");
					break;
				case ASYNC_PAUSE:
					//printf("Job was paused\n");
					++jobs_inprogress;
					break;
				case ASYNC_FINISH:
					//printf("Job finished with return value %d\n", ret);
					//--jobs_inprogress;
					break;
				}
			}
		}
	}
	// while (jobs_inprogress > 0) {
    //     for (i = 0; i < 100 && jobs_inprogress > 0; i++) {
    //         if (pArg->jobs[i] == NULL)
    //             continue;

    //         if (!ASYNC_WAIT_CTX_get_all_fds(pArg->awcs[i], NULL, &numfds)
    //             || numfds > 1) {
    //             printf("# FAIL: Too Many FD's in Use\n");
    //             break;
    //         }
    //         ASYNC_WAIT_CTX_get_all_fds(pArg->awcs[i], &job_fd,  &numfds);
	// 		FD_ZERO(&waitfdset);
    //         FD_SET(job_fd, &waitfdset);
    //         if (job_fd > max_fd)
    //             max_fd = job_fd;
    //     }

    //     if (max_fd >= (OSSL_ASYNC_FD)FD_SETSIZE) {
    //         printf("# FAIL: Too many FD's in use in the system already\n");
    //         break;
    //     }

    //     select_result = select(max_fd + 1, &waitfdset, NULL, NULL,
    //                             &select_timeout);

    //     if (select_result == -1 && errno == EINTR)
    //         continue;

    //     if (select_result == -1) {
    //         printf("# FAIL: Select Failure \n");
    //         break;
    //     }

    //     if (select_result == 0) {
    //         pollingMultiInst();
	// 		//printf("blocked \n");
    //         continue;
    //     }
    //     for (i = 0; i < 100; i++) {
    //         if (pArg->jobs[i] == NULL)
    //             continue;
    //         if (!ASYNC_WAIT_CTX_get_all_fds(pArg->awcs[i], NULL, &numfds)
    //             || numfds > 1) {
    //             printf("# FAIL: Too Many FD's in Use\n");
    //             break;
    //         }
    //         ASYNC_WAIT_CTX_get_all_fds(pArg->awcs[i], &job_fd,  &numfds);

    //         if (numfds == 1 && !FD_ISSET(job_fd, &waitfdset))
    //             continue;
    //         switch (ASYNC_start_job(&pArg->jobs[i], pArg->awcs[i], &ret, element_encrypt,
    //                 pArg, sizeof(elem_enc_t))) {
    //         case ASYNC_PAUSE:
    //             break;
    //         case ASYNC_FINISH:
    //             --jobs_inprogress;
    //             pArg->jobs[i] = NULL;
    //             break;
    //         case ASYNC_NO_JOBS:
    //         case ASYNC_ERR:
    //             --jobs_inprogress;
    //             pArg->jobs[i] = NULL;
    //             break;
    //         }
    //     }
	// 	pollingMultiInst();
    //     //qat_epoll_engine(args->e, events, &poll_status, 0);
    // } /* while (jobs_inprogress > 0) */
	// while (jobs_inprogress > 0)
	// 	event_poll_func();
	// 	qat_keep_polling = 1;
    
	// OPENSSL_free(pArg->awcs);
    // OPENSSL_free(pArg->jobs);
	// free(events);
	
	// CpaStatus status;
	// while(taskNum != 0) 
	// 	status = icp_sal_CyPollInstance(*pCyInstHandle, 0);

	//get latency
	// double consume;
	// consume = t_sum.tv_sec + (1.0 * t_sum.tv_usec) / 1000000;
	// printf("latency sum = %fs \n", consume);
	// printf("average latency = %fs \n", consume / 1000);

// end:
// 	ASYNC_WAIT_CTX_free(wctx);
	//printf("Finishing\n");
    
    hcs_free_random(hr);
    return mat_ret;
}

int main(){
	CpaStatus stat = CPA_STATUS_SUCCESS;
	//CpaInstanceHandle pCyInstHandle[48] = { 0 };
	//CpaInstanceHandle *pCyInstHandle = NULL;
	//Cpa16U numInst;

	//CpaInstanceHandle *pCyInstHandle;
	//unsigned short numInst;

	// pk & vk
	pcs_public_key* pk;
	pcs_private_key* vk;
	hcs_random* hr;

	stat = qaeMemInit();
	if (CPA_STATUS_SUCCESS != stat)
	{
		printf("Failed to initialise memory driver\n");
		return (int)stat;
	}

	stat = icp_sal_userStartMultiProcess("SHIM", CPA_FALSE);
	if (CPA_STATUS_SUCCESS != stat)
	{
		printf("Failed to start user process SSL\n");
		qaeMemDestroy();
		return (int)stat;
	}
    //Cpa32U i = 0;
	//Cpa32U coreAffinity = 0;
	//CpaInstanceInfo2 info = { 0 };

	/*get the number of crypto instances*/
	stat = cpaCyGetNumInstances(&numInst);
	// numInst_g--;
	if (CPA_STATUS_SUCCESS != stat)
	{
		printf("cpaCyGetNumInstances failed with status: %d\n", stat);
		return stat;
	}
	//PRINT_DBG("numInst_g = %hd\n", numInst);
	if (numInst > 0)
	{
		pCyInstHandle = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInst);
		if (pCyInstHandle == NULL)
		{
			printf("Failed to allocate memory for instances\n");
			qaeMemFree((void **)&pCyInstHandle);
			return CPA_STATUS_FAIL;
		}
		/*get the instances handles and place in allocated memory*/
		stat = cpaCyGetInstances(numInst, pCyInstHandle);
		if (CPA_STATUS_SUCCESS != stat)
		{
			printf("cpaCyGetInstances failed with status: %d\n", stat);
			qaeMemFree((void **)&pCyInstHandle);
			return stat;
		}
		for (int i = 0; i < numInst; i++)
		{
			if (stat = cpaCySetAddressTranslation(*(pCyInstHandle + i), sampleVirtToPhys) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
			if (stat = cpaCyStartInstance(*(pCyInstHandle + i)) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
			
		}
    }
	stat = cyCreatePollingThreadsIfPollingIsEnabled();
	if(stat == CPA_STATUS_FAIL)
		printf("error error\n");
	
	// CpaStatus status;
	// int flags;
	// int engine_fd;
	// //struct epoll_event eng_epoll_events[256] = {{ 0 }};
	// //ENGINE_EPOLL_ST eng_poll_st[256] = {{ -1 }};
	// //int internal_efd = 0;

	// /*   Add the file descriptor to an epoll event list */
	// internal_efd = epoll_create1(0);
	// if (-1 == internal_efd) {
	// 	printf("Error creating epoll fd\n");
	// 	//qat_pthread_mutex_unlock();
	// 	return 0;
	// }

	// for (int instNum = 0; instNum < numInst; instNum++) {
	// 	/*   Get the file descriptor for the instance */
	// 	status =
	// 		icp_sal_CyGetFileDescriptor(pCyInstHandle[instNum],
	// 									&engine_fd);
	// 	if (CPA_STATUS_FAIL == status) {
	// 		printf("Error getting file descriptor for instance\n");
	// 		//qat_pthread_mutex_unlock();
	// 		return 0;
	// 	}
	// 	/*   Make the file descriptor non-blocking */
	// 	flags = qat_fcntl(engine_fd, F_GETFL, 0);
	// 	if (qat_fcntl(engine_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
	// 		printf("Failed to set engine_fd as NON BLOCKING\n");
	// 		//qat_pthread_mutex_unlock();
	// 		return 0;
	// 	}

	// 	eng_poll_st[instNum].eng_fd = engine_fd;
	// 	eng_poll_st[instNum].inst_index = instNum;

	// 	eng_epoll_events[instNum].data.ptr = &eng_poll_st[instNum];
	// 	eng_epoll_events[instNum].events = EPOLLIN | EPOLLET;
	// 	//eng_epoll_events[instNum].events = EPOLLIN;
	// 	if (-1 ==
	// 		epoll_ctl(internal_efd, EPOLL_CTL_ADD, engine_fd,
	// 					&eng_epoll_events[instNum])) {
	// 		printf("Error adding fd to epoll\n");
	// 		//qat_pthread_mutex_unlock();
	// 		return 0;
	// 	}
	// }
	// if (qat_create_thread(&qat_polling_thread, NULL, event_poll_func, NULL)) {
	// 	printf("Creation of polling thread failed\n");
	// 	qat_polling_thread = pthread_self();
	// 	//qat_pthread_mutex_unlock();
	// 	return 0;
    //     }







    // initialize data structures
    pk = pcs_init_public_key();
    vk = pcs_init_private_key();
    hr = hcs_init_random();

    // Generate a key pair with modulus of size "bitKey" bits
    pcs_generate_key_pair(pk, vk, hr, 2048);

	int m = 1;
	int n = 1;
	simple_matrix* mul_mat_int = simple_matrix_init(m, n);
	//PCS_matrix* mul_mat_enc = PCS_init_matrix(n, n);
	PCS_matrix* mul_mat_enc;

	mpz_t temp;
	mpz_init(temp);
	// mpz_t a,b,test1;
	// mpz_init(a);
	// mpz_init(b);
	// mpz_init(test1);
	// mpz_set_ui(a, 50);
	// mpz_set_ui(b, 76);
	mpz_set_ui(temp, 50);
	// mpz_mul_2exp(temp, temp, 2040);
	simple_mat_set_value(mul_mat_int, temp, 0, 0);
	// simple_mat_set_value(mul_mat_int, a, 0, 0);
	// simple_mat_set_value(mul_mat_int, b, 0, 1);

	struct timeval t_val;
	gettimeofday(&t_val, NULL);
	mul_mat_enc = matrix_encrypt(pk, vk, mul_mat_int, pCyInstHandle);
	
	qat_keep_polling = 0;
	struct timeval t_val_end;
	gettimeofday(&t_val_end, NULL);
	struct timeval t_result;
	timersub(&t_val_end, &t_val, &t_result);
	double consume = t_result.tv_sec + (1.0 * t_result.tv_usec) / 1000000;
	printf("-------------- elapsed time= %fs \n", consume);
	printf("-------------- Throughput = %f\n", 1000 / consume);
	// PCS_mat_get_value(mul_mat_enc,a,0,0);
	// PCS_mat_get_value(mul_mat_enc,b,0,1);
	// gmp_printf("%Zd\n", a);
	// gmp_printf("%Zd\n", b);
	// pcs_ee_add(pk, test1, a, b);    // Add encrypted a and b values together into c
	// pcs_decrypt(vk, test1, test1);
	// gmp_printf("%Zd\n", test1);

	simple_matrix_free(mul_mat_int);
	PCS_free_matrix(mul_mat_enc);
	
	
	
	
	
	// OPENSSL_free(args.awcs);
    // OPENSSL_free(args.jobs);
	pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    hcs_free_random(hr);
}



// Matrix encrypt
// PCS_matrix *matrix_encrypt(pcs_public_key *pk,pcs_private_key *vk,simple_matrix *mat, CpaInstanceHandle* pCyInstHandle, int pollThreshold){
//     PCS_matrix *mat_ret=PCS_init_matrix(mat->m,mat->n);
//     hcs_random *hr = hcs_init_random();

// 	// elem_enc_t arg
// 	int taskNum = 0;    //Inflight requests
//     struct timeval t_sum;
// 	struct timeval* pT_sum;
// 	struct elem_enc_t* pArg = (struct elem_enc_t*)malloc(sizeof(struct elem_enc_t));
// 	*(pArg->pTaskNum) = 0;
// 	*(pArg->pT_sum) = {0};

//     int ret;
// 	pArg->jobs = OPENSSL_malloc(sizeof(ASYNC_JOB*)*n*m);
//     if (pArg.jobs == NULL) {
//         printf("# FAIL: Unable to allocate args.jobs\n");
//     }
//     pArg.awcs = OPENSSL_malloc(sizeof(ASYNC_WAIT_CTX*)*n*m);
//     if (pArg.awcs == NULL) {
//         printf("# FAIL: Unable to allocate args.awcs\n");
//     }
//     memset(pArg.jobs, 0, sizeof(ASYNC_JOB*)*n*m);
//     memset(pArg.awcs, 0, sizeof(ASYNC_WAIT_CTX*)*n*m);
//     for (i =0; i < n*m; i++) {
//         pArg.awcs[i] = ASYNC_WAIT_CTX_new();
//         if (pArg.awcs[i] == NULL) {
//             printf("# FAIL: Unable to allocate args.awcs[%d]\n", i);
//         }
//     }

// 	ASYNC_JOB* job = NULL;  // Coroutine handles
// 	ASYNC_WAIT_CTX* wctx = NULL;
// 	wctx = ASYNC_WAIT_CTX_new();
// 	if (wctx == NULL) {
// 		printf("Failed to create ASYNC_WAIT_CTX\n");
// 		abort();
// 	}

//     // 10000 repeated encryption of input data
//     // for (int k = 0; k < 1000; k++) {
// 	// 	for (int i = 0; i < mat->m; i++) {
// 	// 		for (int j = 0; j < mat->n; j++) {
// 	// 			struct timeval t_val;
// 	// 			gettimeofday(&t_val, NULL);

// 	// 			mpz_t tmp1;
// 	// 			mpz_init(tmp1);
// 	// 			simple_mat_get_value(mat, tmp1, i, j);
// 	// 			pcs_encrypt(pk, hr, tmp1, tmp1, pCyInstHandle);  //Invoke libhcs API
// 	// 			PCS_mat_set_value(mat_ret, tmp1, i, j);

// 	// 			timeval end
// 	// 			struct timeval t_val_end;
// 	// 			gettimeofday(&t_val_end, NULL);
// 	// 			struct timeval t_result;
// 	// 			timersub(&t_val_end, &t_val, &t_result);
// 	// 			timeradd(pT_sum, &t_result, pT_sum);
// 	// 		}
// 	// 	}
// 	// }	

// 	for (int i = 0; i < mat->m; i++) {
// 		for (int j = 0; j < mat->n; j++) {
// 			pArg->src_matrix = mat;
// 			pArg->des_matrix = mat_ret;
// 			pArg->i = i;
// 			pArg->j = j;
// 			pArg->pCyInstHandle = pCyInstHandle;
// 			pArg->pk = pk;
// 			pArg->hr = hr;
// 			// pArg->pTaskNum = &taskNum;
// 			// pArg->pT_sum = &t_sum;

// 			job = NULL;
			
// 			//Initiate a coroutine to submit an encryption task
// 			switch (ASYNC_start_job(&job, wctx, &ret, element_encrypt, pArg, sizeof(struct elem_enc_t)))
// 			{
// 			case ASYNC_ERR:
// 			case ASYNC_NO_JOBS:
// 				printf("An error occurred\n");
// 				goto end;
// 			case ASYNC_PAUSE:
// 				printf("Job was paused\n");
// 				break;
// 			case ASYNC_FINISH:
// 				printf("Job finished with return value %d\n", ret);
// 				break;
// 			}
// 		}
// 	}
	
// 	CpaStatus status;
// 	while(taskNum != 0) //Recycle all submitted tasks
// 		status = icp_sal_CyPollInstance(*pCyInstHandle, 0);

// 	//get latency
// 	// double consume;
// 	// consume = t_sum.tv_sec + (1.0 * t_sum.tv_usec) / 1000000;
// 	// printf("latency sum = %fs \n", consume);
// 	// printf("average latency = %fs \n", consume / 1000);

// // end:
// // 	ASYNC_WAIT_CTX_free(wctx);
// 	//printf("Finishing\n");
    
//     hcs_free_random(hr);
//     return mat_ret;
// }