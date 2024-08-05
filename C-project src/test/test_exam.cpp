#include <gmp.h>
#include <libhcs.h>
#include "../include/libhcs/pcs_qat_offload.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/async.h>
#include <openssl/crypto.h>

# include <sys/types.h>
# include <sys/eventfd.h>
# include <fcntl.h>
# include <sched.h>


int qat_create_thread(pthread_t *pThreadId, const pthread_attr_t *attr,
                      void *(*start_func) (void *), void *pArg)
{
    return pthread_create(pThreadId, attr, start_func,(void *)pArg);
}
int qat_fcntl(int fd, int cmd, int arg)
{
    return fcntl(fd, cmd, arg);
}


CpaInstanceHandle *CyInstHandle;
Cpa16U numInst;
typedef struct {
    int eng_fd;
    int inst_index;
} ENGINE_EPOLL_ST;
struct epoll_event eng_epoll_events[64] = {{ 0 }};
ENGINE_EPOLL_ST eng_poll_st[64] = {{ -1 }};
int internal_efd = 0;
int i;
int qat_keep_polling=1;

void *event_poll_func()
{
    CpaStatus status = 0;
    struct epoll_event *events = NULL;
    ENGINE_EPOLL_ST* epollst = NULL;

    /* Buffer where events are returned */
    events = OPENSSL_zalloc(sizeof(struct epoll_event) * 32);
    if (NULL == events) {
        printf("Error allocating events list\n");
        goto end;
    }

    while (qat_keep_polling) {
        int n = 0;
        int i = 0;

        n = epoll_wait(internal_efd, events, 32, 1000);
        for (i = 0; i < n; ++i) {
            if (events[i].events & EPOLLIN) {
                /*  poll for 0 means process all packets on the ET ring */
                epollst = (ENGINE_EPOLL_ST*)events[i].data.ptr;
                status = icp_sal_CyPollInstance(CyInstHandle[epollst->inst_index], 0);
            }
        }
    }
    OPENSSL_free(events);
    events = NULL;
end:
    return NULL;
}


int main(){
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
		PRINT_ERR("Failed to start user process SHIM\n");
		qaeMemDestroy();
		return (int)stat;
	}

	/*get the number of crypto instances*/
	stat = cpaCyGetNumInstances(&numInst);
	if (CPA_STATUS_SUCCESS != stat)
	{
		PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", stat);
		return stat;
	}
	PRINT_DBG("numInst_g = %hd\n", numInst);
	if (numInst > 0)
	{
		CyInstHandle = qaeMemAlloc(sizeof(CpaInstanceHandle) * numInst); 
		if (CyInstHandle == NULL)
		{
			PRINT_ERR("Failed to allocate memory for instances\n");
			qaeMemFree((void **)&CyInstHandle);
			return CPA_STATUS_FAIL;
		}
		/*get the instances handles and place in allocated memory*/
		stat = cpaCyGetInstances(numInst, CyInstHandle);
		if (CPA_STATUS_SUCCESS != stat)
		{
			PRINT_ERR("cpaCyGetInstances failed with status: %d\n", stat);
			qaeMemFree((void **)&CyInstHandle);
			return stat;
		}
		for (int i = 0; i < numInst; i++)
		{
			if (stat = cpaCySetAddressTranslation(*(CyInstHandle + i), sampleVirtToPhys) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
			if (stat = cpaCyStartInstance(*(CyInstHandle + i)) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
			
		}
    }
	pthread_t qat_polling_thread;
	qat_polling_thread = pthread_self();
	
	CpaStatus status;
	int flags;
	int engine_fd;
	struct epoll_event *events = NULL;
    ENGINE_EPOLL_ST* epollst = NULL;


	/*   Add the file descriptor to an epoll event list */
	internal_efd = epoll_create1(0);
	if (-1 == internal_efd) {
		printf("Error creating epoll fd\n");
		//qat_pthread_mutex_unlock();
		return 0;
	}

	for (int instNum = 0; instNum < numInst; instNum++) {
		/*   Get the file descriptor for the instance */
		status =
			icp_sal_CyGetFileDescriptor(CyInstHandle[instNum],
										&engine_fd);
		if (CPA_STATUS_FAIL == status) {
			printf("Error getting file descriptor for instance\n");
			//qat_pthread_mutex_unlock();
			return 0;
		}
		/*   Make the file descriptor non-blocking */
		eng_poll_st[instNum].eng_fd = engine_fd;
		eng_poll_st[instNum].inst_index = instNum;

		flags = qat_fcntl(engine_fd, F_GETFL, 0);
		if (qat_fcntl(engine_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			printf("Failed to set engine_fd as NON BLOCKING\n");
			//qat_pthread_mutex_unlock();
			return 0;
		}

		eng_epoll_events[instNum].data.ptr = &eng_poll_st[instNum];
		eng_epoll_events[instNum].events = EPOLLIN | EPOLLET;
		if (-1 ==
			epoll_ctl(internal_efd, EPOLL_CTL_ADD, engine_fd,
						&eng_epoll_events[instNum])) {
			printf("Error adding fd to epoll\n");
			//qat_pthread_mutex_unlock();
			return 0;
		}
	}
	
	if (qat_create_thread(&qat_polling_thread, NULL, event_poll_func, NULL)) {
		printf("Creation of polling thread failed\n");
		qat_polling_thread = pthread_self();
		//qat_pthread_mutex_unlock();
		return 0;
        }

	// initialize data structures
	pcs_public_key *pk = pcs_init_public_key();
	pcs_private_key *vk = pcs_init_private_key();
	hcs_random *hr = hcs_init_random();

	// Generate a key pair with modulus of size 2048 bits
	pcs_generate_key_pair(pk, vk, hr, 2048);

	// libhcs works directly with gmp mpz_t types, so initialize some
	mpz_t a, b, c;
	mpz_inits(a, b, c, NULL);

	mpz_set_ui(a, 50);
	mpz_set_ui(b, 76);
	gmp_printf("a = %Zd\nb = %Zd\n", a, b);

	struct timeval t_val, t_val_end, t_result;
	gettimeofday(&t_val, NULL);
	for (int j = 0; j < 100000; j++)
	{
		pcs_encrypt(pk, hr, a, a, CyInstHandle);
	}
	gettimeofday(&t_val_end, NULL);
	timersub(&t_val_end, &t_val, &t_result);
	consume = t_result.tv_sec + (1.0 * t_result.tv_usec) / 1000000;
	printf("-------------- elapsed time= %fs \n", consume);
	printf("-------------- Throughput = %f\n", 100000 / consume);

	mpz_clears(a, b, c, NULL);
	pcs_free_public_key(pk);
	pcs_free_private_key(vk);
	hcs_free_random(hr);
	//sampleCyStopPollingMultiInst();
	return 0;
}