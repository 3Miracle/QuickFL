#ifndef _PCS_MAT_H
#define _PCS_MAT_H
#include <libhcs.h>
#include <time.h>
#include <math.h>

typedef struct {
    mpz_t *simple_array;
    int m,n;
} simple_matrix;

typedef struct {
    mpz_t *PCS_array;
    int m,n;
} PCS_matrix;
//------------------------------------------------------------------------ simple matrix handler
simple_matrix *simple_matrix_init(int m,int n);

void simple_matrix_free(simple_matrix *mat);

void simple_mat_set_value(simple_matrix *mat,mpz_t val,int i,int j);

void simple_mat_get_value(simple_matrix *mat,mpz_t ret,int i,int j);

//------------------------------------------------------------------------ BGN matrix handler

PCS_matrix *PCS_init_matrix(int m,int n);

void PCS_free_matrix(PCS_matrix *mat);

void PCS_mat_set_value(PCS_matrix *mat,mpz_t val,int i,int j);

void PCS_mat_get_value(PCS_matrix *mat,mpz_t ret,int i,int j);

//------------------------------------------------------------------------ matrix enc && dec

PCS_matrix *matrix_encrypt(pcs_public_key *pk,pcs_private_key *vk,simple_matrix *mat, CpaInstanceHandle* pCyInstHandle);

#endif

