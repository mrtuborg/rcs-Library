#include <stdio.h>
#include <string.h>
#include "ortsTypes.h"
#include "rcsCmd.h"
#include "crc16.h"
#include "global.h"

rcsCmd::rcsCmd()
{
    cmd=new rcsCmd_type;
}

rcsCmd::~rcsCmd()
{
    delete cmd;
}

BYTE rcsCmd::get_func_id()
{
    return func_id;
}

void rcsCmd::dbgPrint()
{
  printf("Функция №%d", func_id);
  printf(", Параметры [");
  if (func_paramsLength==0) printf (" ОТСУТСТВУЮТ ");
  else {
	for (int i=0; i<func_paramsLength; i++){
	    printf("%.2X ",*((BYTE*)func_params+i));
	}
  }
  printf("],  КС: %.4X\n", crc16_signature);
}

errType rcsCmd::decode(BYTE* data)
{
	errType result=err_not_init;
        //1. Copyng static part of cmd type:
	    memcpy(data, cmd, sizeof(rcsCmd::func_id)+sizeof(rcsCmd::func_paramsLength));
 	//2. Decoding dynamic part from dataBlock:
	    memcpy(data+sizeof(rcsCmd::func_id)+sizeof(rcsCmd::func_paramsLength), cmd->func_params, cmd->func_paramsLength);
	    memcpy(data+sizeof(rcsCmd::func_id)+sizeof(rcsCmd::func_paramsLength)+cmd->func_paramsLength, &cmd->crc16_signature, sizeof(rcsCmd::crc16_signature));
	return result;
}

errType rcsCmd::encode(BYTE* data)
{
	errType result=err_not_init;
	BYTE func_id=data[0];
	cmd->func_paramsLength=*(DWORD*)(data+1);
	encode(func_id, func_paramsLength, data+sizeof(rcsCmd::func_id)+sizeof(rcsCmd::func_paramsLength));
	cmd->crc16_signature=*(WORD*)(data+getCmdLength()-2);
        return result;
}


errType rcsCmd::encode(BYTE func_num, DWORD par_length, const BYTE* data)
{
	errType result=err_not_init;
	BYTE tmp[255];
	
        //1. Copyng static part of cmd type:
	     cmd->func_id=func_num;
	     cmd->func_paramsLength=par_length;
	     cmd->crc16_signature=0;
	     if (par_length>0) {
	//2. Creating dynamic part of cmd type:
	        cmd->func_params=new BYTE[par_length];
	//3. Decoding dynamic part from dataBlock:
	        memcpy(cmd->func_params, ((BYTE*)data), par_length);
	    }
	return result;
}


DWORD rcsCmd::get_func_paramsLength()
{
     return cmd->func_paramsLength;
}
  
DWORD rcsCmd::getCmdLength()
{
     return func_paramsLength+sizeof(func_id)+sizeof(crc16_signature)+sizeof(func_paramsLength);
}
  
const void* rcsCmd::get_func_paramsPtr(DWORD offset)
{
    return ((BYTE*)func_params+offset);
}

WORD rcsCmd::get_crc_sign()
{
    return crc16_signature;
}

errType rcsCmd::makeSign()
{
    cmd->crc16_signature=0;
    if (cmd->func_paramsLength>0) cmd->crc16_signature=CRC16_eval(cmd->func_params,cmd->func_paramsLength);
    cmd->crc16_signature=CRC16_eval(&cmd->func_paramsLength,sizeof(rcsCmd::func_paramsLength),cmd->crc16_signature);
    cmd->crc16_signature=CRC16_eval(&cmd->func_id,sizeof(rcsCmd::func_id),cmd->crc16_signature);
    	     
    return err_result_ok;
}

bool rcsCmd::checkSign()
{
    bool result=false;
    rcsCmd test_cmd;
    WORD test_sign;
    test_cmd.encode(cmd->func_id, cmd->func_paramsLength, func_params);
    test_cmd.makeSign();
    test_sign=test_cmd.get_crc_sign();
    
    if (verbose_level) {
	printf("test sign: %.4X\n",test_sign);
	printf("rcvd sign: %.4X\n",this->get_crc_sign());
    }
    
    if (test_sign==cmd->get_crc_sign()) result=true;
    return result;
}