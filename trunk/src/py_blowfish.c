#include <Python.h>
#include "blowfish.h"

#ifdef MORE_SECURE

    #define TRAILMAGIC "X\xf7\x73\x77X\x2aX\x07\xa4\x5c\x78X"
    #define TRAILLEN 12
    #define THRESLEN 20

#else

    #define TRAILMAGIC "XXXXXXXX"
    #define TRAILLEN 8
    #define THRESLEN 65536

#endif


static PyObject *
py_genkey(PyObject *self, PyObject *args);

static PyObject *
py_encrypt(PyObject *self, PyObject *args);

static PyObject *
py_decrypt(PyObject *self, PyObject *args);

static PyMethodDef BlowfishMethods[] = {
    {"genkey",  py_genkey, METH_VARARGS,
     "generate a key"},
    {"encrypt",  py_encrypt, METH_VARARGS,
     "encrypt"},
    {"decrypt",  py_decrypt, METH_VARARGS,
     "decrypt"},

    {NULL, NULL, 0, NULL}        /* Sentinel */
};


void bf_encrypt(BLOWFISH_CTX* ctx, char* buf, int *len){
    int i;
    if(*len<THRESLEN){
        for(i=0; i<TRAILLEN; ++i){
            if(TRAILMAGIC[i]=='X'){
                buf[*len+i]=(unsigned char)rand();
            }else{
                buf[*len+i]=TRAILMAGIC[i];
            }
        }
        *len+=TRAILLEN;
    }
    for(i=0; i < *len-8; i+=4){
        //fprintf(stderr,"encrypt %d %08X%08X -> ",i, *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
        Blowfish_Encrypt(ctx, (unsigned int*)(buf+i), (unsigned int*)(buf+i+4));
        //fprintf(stderr,"%08X%08X\n",  *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
    }
    for(i=(*len-8)&~7; i >=0; i-=4){
        //fprintf(stderr,"encrypt %d %08X%08X -> ",i, *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
        Blowfish_Encrypt(ctx, (unsigned int*)(buf+i), (unsigned int*)(buf+i+4));
        //fprintf(stderr,"%08X%08X\n",  *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
    }
}

void bf_decrypt(BLOWFISH_CTX* ctx, char* buf, int *len){
    int i;
    if(*len < TRAILLEN){
        // fail, this packet as malformed    
        *len=-1;
        return;
    }
    for(i=0; i < *len-8; i+=4){
        //fprintf(stderr,"decrypt %d %08X%08X -> ",i, *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
        Blowfish_Decrypt(ctx, (unsigned int*)(buf+i), (unsigned int*)(buf+i+4));
        //fprintf(stderr,"%08X%08X\n",  *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
    }
    for(i=(*len-8)&~7; i >=0; i-=4){
        //fprintf(stderr,"decrypt %d %08X%08X -> ",i, *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
        Blowfish_Decrypt(ctx, (unsigned int*)(buf+i), (unsigned int*)(buf+i+4));
        //fprintf(stderr,"%08X%08X\n",  *(unsigned int*)(buf+i), *(unsigned int*)(buf+i+4));
    }
    if(*len >= TRAILLEN && *len<THRESLEN+TRAILLEN){
        *len-=TRAILLEN;     
        for(i=0; i<TRAILLEN; ++i){
            if((buf[*len+i]!=TRAILMAGIC[i]) && TRAILMAGIC[i]!='X'){
                *len+=TRAILLEN;
                break;
            }
        }
    }
}

static PyObject *
py_genkey(PyObject *self, PyObject *args)
{
    BLOWFISH_CTX *ctx = (BLOWFISH_CTX *)malloc(sizeof(BLOWFISH_CTX));
    
    int keystr_len;
    char *keystr;
    if (!PyArg_ParseTuple(args, "s#", &keystr, &keystr_len)) {
        return NULL;
    }

    srand(*(unsigned int*)keystr);
    Blowfish_Init (ctx, (unsigned char*)keystr, keystr_len);
    return PyCObject_FromVoidPtr((void *)ctx, NULL);
}

static PyObject *
py_encrypt(PyObject *self, PyObject *args)
{
    PyCObject *key;
    char *data;
    int data_len;
    BLOWFISH_CTX * ctx;
    if (!PyArg_ParseTuple(args, "Os#", &key, &data, &data_len)) {
        return NULL;
    }
    //make a copy of data
    char *data_copy = (char *)malloc(data_len);
    memcpy(data_copy, data, data_len);
    ctx = (BLOWFISH_CTX *)PyCObject_AsVoidPtr(key);
    bf_encrypt(ctx, data_copy, &data_len);
    
    return PyString_FromStringAndSize(data_copy, data_len);
}

static PyObject *
py_decrypt(PyObject *self, PyObject *args)
{
    PyCObject *key;
    char *data;
    int data_len;
    BLOWFISH_CTX * ctx;
    if (!PyArg_ParseTuple(args, "Os#", &key, &data, &data_len)) {
        return NULL;
    }
    char *data_copy = (char *)malloc(data_len);
    memcpy(data_copy, data, data_len);

    ctx = (BLOWFISH_CTX *)PyCObject_AsVoidPtr(key);
    bf_decrypt(ctx, data_copy, &data_len);
    
    return PyString_FromStringAndSize(data_copy, data_len);
}

/**
 * Python module initialization 
 *
 */
PyMODINIT_FUNC
init_blowfish(void)
{
    PyObject *m;

    m = Py_InitModule("_blowfish", BlowfishMethods);
    if (m == NULL)
        return;

}


