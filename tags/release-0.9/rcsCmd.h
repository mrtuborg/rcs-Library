#pragma pack (1)

typedef sturct rcsCmd_type {
    BYTE func_id;
    DWORD func_paramsLength;
    void *func_params;
    WORD crc16_signature;

} rcsCmd_type

class rcsCmd {
    rcsCmd_type* cmd;
    
public:
 rcsCmd();
 ~rcsCmd();

 BYTE get_func_id();
 DWORD get_func_paramsLength();
 DWORD getCmdLength();
 WORD get_crc_sign();
 const void* get_func_paramsPtr(DWORD offset=0);
 
 
 void dbgPrint();
 errType decode(BYTE* dataBlock);
 errType encode(const BYTE* dataBlock);
 errType encode(BYTE, DWORD, const BYTE*);
 errType makeSign();

 bool checkSign();
} __attribute__ ((packed));
