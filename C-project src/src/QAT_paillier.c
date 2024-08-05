#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <unistd.h>
#include <openssl/async.h>
#include <openssl/crypto.h>
#include <stdlib.h>

# include <sys/types.h>
#include <sys/time.h>

#include "../include/libhcs/pcs_qat_offload.h"

# define timersub(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;			      \
    if ((result)->tv_usec < 0) {					      \
      --(result)->tv_sec;						      \
      (result)->tv_usec += 1000000;					      \
    }									      \
  } while (0)

# define timeradd(a, b, result)						      \
  do {									      \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			      \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;			      \
    if ((result)->tv_usec >= 1000000)					      \
      {									      \
	++(result)->tv_sec;						      \
	(result)->tv_usec -= 1000000;					      \
      }									      \
  } while (0)

//--------------------------------------------------------------------- simple matrix


void simple_array_get_value(mpz_t *array, mpz_t ret, int i){
    mpz_set(ret,array[i]);
}


//-------------------------------------------------------------------------------- matrix encrypt

struct pcs_enc_t {
	mpz_t* pcs_array;
	char** des_array;
	CpaInstanceHandle *CyInstHandle;
    int i;
    pcs_public_key *pk;
    pcs_private_key_py *vk1;
	hcs_random *hr;
	int *pTaskNum;
};


//coroutine
int element_encrypt(void *argVoid)
{
	struct pcs_enc_t *arg = (struct pcs_enc_t *)argVoid;
	(*(arg->pTaskNum))++;
	mpz_t tmp1;
	mpz_init(tmp1);
    simple_array_get_value(arg->pcs_array, tmp1, arg->i);
    //gettimeofday(&t_val, NULL);
	pcs_encrypt_crt_py(arg->pk, arg->vk1, arg->hr, tmp1, tmp1, arg->CyInstHandle);  //Invoke libhcs API
	//gmp_printf("tmp1 = %Zd\n", tmp1);
    char *str = NULL;
	char *tmp = mpz_get_str(str,10,tmp1);
    //ret_set_value(arg->des_array,&tmp,arg->i);
    *(arg->des_array + arg->i) = tmp;
    // printf("des_array = %p\n",*(arg->des_array + arg->i));
    // printf("success!\n");

    //pcs_set_value(arg->des_array,tmp1,arg->i);
	//PCS_mat_set_value(arg->des_matrix, tmp1, arg->i, arg->j);

	// struct timeval t_val_end;
	// gettimeofday(&t_val_end, NULL);
	// struct timeval t_result;
	// timersub(&t_val_end, &t_val, &t_result);
	// timeradd(arg->pT_sum, &t_result, arg->pT_sum);
    mpz_clear(tmp1);
	(*(arg->pTaskNum))--;
	// printf("async_job completed with taskNum = %d !\n", *(arg->pTaskNum));
	return 0;
}


void array_encrypt(char **ret_array, char **array, int length, CpaInstanceHandle *CyInstHandle){
    struct timeval t_val;
	struct timeval t_val_end;
	struct timeval t_result;
    mpz_t n1, n2, n3, n4,p2,q2,qinv;
    mpz_inits(n1, n2, n3, n4, p2, q2, qinv, NULL);
    char a[] = {"16816259347332836780309998028941743358287925349776132230998924187274567002860099726783036051260978615040660168188619972048220255673894369165009375950290161445364693744524524595813588881664455061518925798080955464089405217902287714874999997894272106693650420295330078476644819736648414526778495271598885617421362729762471287693104006777439869245603097058286163471624127436138066734083616192720741224484628070490326736134753665182568384497511347086550442746091217100346836157773463518086256506985855670513165603236333657078659165126055966947319019605543178643978357878730917836516224238002801692773899313032973784090983"};
    char b[] = {"282786578436759005644937560145813462426183721272687900699476556349803470056100736816330027379660651214338072103164930087974768453076859417984688353704099564707355697984887218131822471609727542293401499452595642344976014576061429577694834934150915967081274575570364274736012747306492628509961050120325119229052216431837189272668393158735449295425345745455780945288078664566632896363071098260016312848844168123974382659586439208547826237407179184850625384906789350137037958550452781077969767470894752291540269806467910248061903610689881366040871943779410351772502922216837122517571991258134244475453107154865018600931790284738163635757236437581375805099796161615003834160967919443675981628754512198503040116220777092736584477904642943624084341291885370644316913386560504909619375975044084527326769568137650637115120980392344881718019512589429455404814820931624581365769055926471812310088603544194132731317145952545104253189368657832348174353343540718059983305750606810519079843225724846371483672670546735459539036970510927711031558839931094531216532822948466506272458099738887899091249806749862969660438250658512294466620573137915932212345048902829290497850335747300113580442571253913083705444547179011615397603416826636763587621906289"};
	char c[] = {"13579380809989864633645717232528548872628203730821696929229557137666713718509806652959888286557445304096534961956646747786589702521081054101154594878798596896645309313920782075618746189156185595775589890335705085484168191333925176619303440917723744512353995523583915451788878006653609594701786185557938694099224866144906820574642614957245954834491039430946481122298096611217841416790411997730577446403084019508075030942259474526585612682584895935562904251316108753448916646601824900935167056790505333941788000420307469868315607747641466651798053173100957459427072961288551164208270683318863037394868060400467503288641"};
	char d[] = {"20824703452511106921645277683648477681655219106282355213330368680611428897311260121393547262535264361405003110769273279153737321571705856394546926897027213180132278244589271408729054059174496222935044725305720553777025274464087627709884711160176948740010327349804054822027879537281592963740265146266753621217062991771560365205984573208618346084154625826324440406389381287828867991957357861416755741184409922219315635969891537028776939691206966163510580318225179200437466476794998898005410159488774698979757547774648561272999755057452667073528831433378714398896803128223183069336781013619029968616828138929874544007729"};
	char e[] = {"3151582357337161664789163099459861935094895168162795842729445700592858496009404489788754523956205243913099755601422751874408555696160021036935382423758867988175075751977553580333549277286855333242648813518821604159046200176884341079941867328998613924881415859412068288282751688054549040473860380869795377971320763583224610620307082476538437249082473148998910292344553008041702691341540337430110520584929731263962386629504377255781615519262881478495740237070257266458230240600900331933383983084325133532117030013258270829085286492762391198408315561822166788611323200748266208749517601332573955485498784569893016309238"};

    mpz_set_str(n1,a,10);
    mpz_set_str(n2,b,10);
	mpz_set_str(p2,c,10);
	mpz_set_str(q2,d,10);
	mpz_set_str(qinv,e,10);
    mpz_add_ui(n4,n1,1);

    pcs_public_key *pk = pcs_init_public_key();
    mpz_set(pk->n,n1);
    mpz_set(pk->g,n4);
    mpz_set(pk->n2,n2);

    pcs_private_key_py *vk1 = pcs_init_private_key_py();
    mpz_set(vk1->p2,p2);
    mpz_set(vk1->q2,q2);
    mpz_set(vk1->qinv,qinv);
    
    hcs_random *hr = hcs_init_random();
    mpz_t *pcs_array = (mpz_t *)malloc(length * sizeof(mpz_t));
    for(int i=0;i<length;i++){
        mpz_init_set_str(pcs_array[i], array[i], 10);
    }

    int ret;
    int j;
    int taskNum = 0;
    ASYNC_JOB* job = NULL;  // Coroutine handles
    ASYNC_WAIT_CTX* wctx = NULL;
    wctx = ASYNC_WAIT_CTX_new();
    if (wctx == NULL) {
        printf("Failed to create ASYNC_WAIT_CTX\n");
        abort();
    }
    struct pcs_enc_t* pArg = (struct pcs_enc_t*)malloc(sizeof(struct pcs_enc_t));
    gettimeofday(&t_val, NULL);
    for(int i=0;i<length;i++){
        pArg->pcs_array = pcs_array;
        pArg->des_array = ret_array;
        pArg->CyInstHandle = CyInstHandle+ (i % 3);
        pArg->i = i;
        pArg->pk = pk;
        pArg->vk1 = vk1;
        pArg->hr = hr;
        pArg->pTaskNum = &taskNum;
        job = NULL;
        if (taskNum >= 256) 
                {
                    //pollingMultiInst();  
                    for (j = 0; j < 3; j++){
                        icp_sal_CyPollInstance(CyInstHandle[j], 0);
                    }
                    while (taskNum > 400)
                    {
                        for (j = 0; j < 3; j++){
                            icp_sal_CyPollInstance(CyInstHandle[j], 0);

                        }
                        //if (CPA_STATUS_RETRY == icp_sal_CyPollInstance(*pCyInstHandle, 0));
                        //sleep(1);
                    }
                }
        switch (ASYNC_start_job(&job, wctx, &ret, element_encrypt, pArg, sizeof(struct pcs_enc_t)))
                {
                case ASYNC_ERR:
                case ASYNC_NO_JOBS:
                    printf("An error occurred\n");
                    goto end;
                case ASYNC_PAUSE:
                    //++job_inprogress;
                    break;
                case ASYNC_FINISH:
                    printf("Job finished with return value %d\n", ret);
                    break;
                }
    }
    while(taskNum != 0) {
		for (j = 0; j < 3; j++){
			icp_sal_CyPollInstance(CyInstHandle[j], 0);
		}		
	}
    gettimeofday(&t_val_end, NULL);
    timersub(&t_val_end, &t_val, &t_result);
	double consume = t_result.tv_sec + (1.0 * t_result.tv_usec) / 1000000;
	printf("-------------- elapsed time= %fs \n", consume);
    free(pArg);
    free(pcs_array);
    pcs_free_public_key(pk);
    //cpaCyStopInstance(CyInstHandle);
    //icp_sal_userStop();
	//hcs_free_random(hr);


end:
	ASYNC_WAIT_CTX_free(wctx);
	//printf("Finishing\n");
    
    hcs_free_random(hr);
    //return des_array;
}