#include "pcs_matrix.h"

#include <openssl/async.h>
#include <openssl/crypto.h>
#include <libhcs.h>
#include <unistd.h>

#include <sys/time.h>

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
	CpaInstanceHandle *pCyInstHandle;
	pcs_public_key *pk;
	pcs_private_key *vk;
	hcs_random *hr;
	int *pTaskNum;
    struct timeval* pT_sum; // Total encryption time
};

//int taskNum = 0;

//
// int element_encrypt(void *argVoid)
// {
// 	struct elem_enc_t *arg = (struct elem_enc_t *)argVoid;
// 	(*(arg->pTaskNum))++;

// 	//timeval start
// 	struct timeval t_val;
// 	gettimeofday(&t_val, NULL);

// 	mpz_t tmp1;
// 	mpz_init(tmp1);
// 	simple_mat_get_value(arg->src_matrix, tmp1, arg->i, arg->j);
// 	pcs_encrypt_crt(arg->pk, arg->vk, arg->hr, tmp1, tmp1, arg->pCyInstHandle);  //libhcs API
// 	PCS_mat_set_value(arg->des_matrix, tmp1, arg->i, arg->j);

// 	//timeval end
// 	struct timeval t_val_end;
// 	gettimeofday(&t_val_end, NULL);
// 	struct timeval t_result;
// 	timersub(&t_val_end, &t_val, &t_result);
// 	timeradd(arg->pT_sum, &t_result, arg->pT_sum);  //

// 	//free(arg);
// 	(*(arg->pTaskNum))--;
// 	//printf("async_job completed with taskNum = %d !\n", *(arg->ptaskNum));
// 	return 0;
// }

extern "C" {
	CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle,
		Cpa32U response_quota);
}

PCS_matrix *matrix_encrypt(pcs_public_key *pk, pcs_private_key *vk, simple_matrix *mat, CpaInstanceHandle* pCyInstHandle, int pollThreshold){
    PCS_matrix *mat_ret=PCS_init_matrix(mat->m,mat->n);
    hcs_random *hr = hcs_init_random();

	// elem_enc_t arg
	int taskNum = 0;    
    struct timeval t_sum;   

    int ret;

    // Perform encryption of 10000 
    for (int k = 0; k < 10000; k++) {
		for (int i = 0; i < mat->m; i++) {
			for (int j = 0; j < mat->n; j++) {
				// struct timeval t_val;
				// gettimeofday(&t_val, NULL);

				mpz_t tmp1;
				mpz_init(tmp1);
				simple_mat_get_value(mat, tmp1, i, j);
				pcs_encrypt_crt(pk, vk, hr, tmp1, tmp1, pCyInstHandle);  //libhcs API
				PCS_mat_set_value(mat_ret, tmp1, i, j);

				// timeval end
				// struct timeval t_val_end;
				// gettimeofday(&t_val_end, NULL);
				// struct timeval t_result;
				// timersub(&t_val_end, &t_val, &t_result);
				// timeradd(pT_sum, &t_result, pT_sum);
			}
		}
	}
	return mat_ret;
    
}