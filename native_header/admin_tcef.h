#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

CK_ADMIN_FUNCTION_INFO(TCE_GetTokenStatus)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID,
    TC_t_TokenStatus_4 CK_PTR TokenStatus
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Create_Token)
#ifdef CK_NEED_ARG_LIST
(
    CK_CHAR_PTR pLabel,
    int labelLen,
    int M,
    int N,
    CK_SLOT_ID_PTR pslotID
);
#endif
    
CK_ADMIN_FUNCTION_INFO(TCE_Start_Personalize)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID,
    int M,
    int N,
    CK_CHAR_PTR pPin,
    int PinLen
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Finish_Personalize)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID
);
#endif
    
CK_ADMIN_FUNCTION_INFO(TCE_Start_Token)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID,
    int M,
    int N
);
#endif
    
CK_ADMIN_FUNCTION_INFO(TCE_Create_Install_Secret)
#ifdef CK_NEED_ARG_LIST
(
    int M,
    int N
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Depersonalize_Token)
#ifdef CK_NEED_ARG_LIST
(
   CK_SLOT_ID  slotID
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_PCA2_Restore_Keys)
#ifdef CK_NEED_ARG_LIST
(
CK_SESSION_HANDLE  hSession,
CK_ULONG           mode,
CK_BYTE            *pBuf,
CK_ULONG           bufLength
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_PCA2_Restore_Secret)
#ifdef CK_NEED_ARG_LIST
(
	CK_SESSION_HANDLE  hSession,
	CK_ULONG           mode,
	unsigned int       *phPCA2Secret
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Duplicate_Card)
#ifdef CK_NEED_ARG_LIST
(
   CK_SLOT_ID  slotID
);
#endif

	CK_ADMIN_FUNCTION_INFO(TCE_GetConfiguration)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_CHAR_PTR configuration,
    CK_ULONG_PTR pconfigurationlen
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_SetConfiguration)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID,
    TC_t_TokenConfiguration_4 CK_PTR configuration
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Desinstall_Token)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Security_Report)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    int N,
    int IDX,
    CK_CHAR_PTR pbuf,
    CK_ULONG_PTR pbuflen
);
#endif
    
CK_ADMIN_FUNCTION_INFO(TCE_GetLog)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    int N,
    int IDX,
    CK_CHAR_PTR pbuf,
    CK_ULONG_PTR pbuflen
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_TestEcho)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_CHAR_PTR pVar,
    CK_ULONG VarSize,
    CK_CHAR_PTR pMsg,
    CK_ULONG MsgSize,
    CK_CHAR_PTR pRsp,
    CK_ULONG_PTR pRspSize
    );
#endif

CK_ADMIN_FUNCTION_INFO(TCE_GetDate)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_ULONG_PTR pDate
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_SetProfile)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_CHAR_PTR pProfile,
    CK_ULONG ProfileLen
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_GetSlotId)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_ULONG_PTR pSlotId
);
#endif

	CK_ADMIN_FUNCTION_INFO(TCE_Logout)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Initialize)
#ifdef CK_NEED_ARG_LIST
(
    CK_CHAR_PTR SrvAddr,              // in: @ip PCA4
    CK_CHAR_PTR pSrvRelease,          // out: version logiciel serveur PCA4
    CK_ULONG_PTR pSrvReleaseSize,     // in, out si pSrvRelease=0 
    CK_ULONG_PTR pHSMId,              // out: Id PCA4 sur 2 octets poids fort
    CK_VERSION_PTR pCltRelease,       // out: version logiciel client PCA4
    TCE_INIT_ARGS_PTR pInitArgs      // in: RFU (ssl,certif,...)
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Initialize_v1)
#ifdef CK_NEED_ARG_LIST
(
    CK_CHAR_PTR SrvAddr,              // in: @ip PCA4
    CK_CHAR_PTR pSrvRelease,          // out: version logiciel serveur PCA4
    CK_ULONG_PTR pSrvReleaseSize,     // in, out si pSrvRelease=0 
    CK_ULONG_PTR pHSMId,              // out: Id PCA4 sur 2 octets poids fort
    CK_VERSION_PTR pCltRelease,       // out: version logiciel client PCA4
    TCE_INIT_ARGS_V1_PTR pInitArgs    // in: RFU (ssl,certif,...)
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Initialize_multi)
#ifdef CK_NEED_ARG_LIST
(
	CK_CHAR_PTR *rpc_server_ips,
    TCE_INIT_ARGS_PTR pInitArgs,
	unsigned int nRpc
);
#endif

	CK_ADMIN_FUNCTION_INFO(TCE_Finalize)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG HSMId,
    CK_ULONG flags
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_GetSlotList)
#ifdef CK_NEED_ARG_LIST
(
    CK_BBOOL tokenPresent,
    CK_SLOT_ID_PTR pSlotList,
    CK_ULONG_PTR pulCount,
    CK_ULONG HSMId
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Create_Install_Cards)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    int M,
    int N
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_SoftwareUpdate_Token)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_CHAR_PTR	pCodeDirectory,
    CK_CHAR_PTR pVersion
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_SoftwareUpdate_System)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_CHAR_PTR	pCodeDirectory,
    CK_CHAR_PTR pVersion
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_SetLibMode)
#ifdef CK_NEED_ARG_LIST
(
    int mode
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_FinalizeThread)
#ifdef CK_NEED_ARG_LIST
(
     void
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_SO_Master_Login)
#ifdef CK_NEED_ARG_LIST
(
     void
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Audit_Master_Login)
#ifdef CK_NEED_ARG_LIST
(
     void
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Audit_Login)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_SO_Master_Logout)
#ifdef CK_NEED_ARG_LIST
(
     void
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Audit_Master_Logout)
#ifdef CK_NEED_ARG_LIST
(
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_Audit_Logout)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID
);
#endif
CK_ADMIN_FUNCTION_INFO(TCE_SaveCerts)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_BYTE_PTR pBuf,
    CK_ULONG_PTR pulBufLen
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_RestoreCerts)
#ifdef CK_NEED_ARG_LIST
(
    CK_ULONG slotID,
    CK_BYTE_PTR pBuf,
    CK_ULONG ulBufLen
);
#endif

CK_ADMIN_FUNCTION_INFO(TCE_GetAppID)
#ifdef CK_NEED_ARG_LIST
(
	CK_BYTE clRand[16],
	CK_BYTE appId[32]
);
#endif	

CK_ADMIN_FUNCTION_INFO(TCE_JoinAppID)
#ifdef CK_NEED_ARG_LIST
(
	CK_BYTE appId[32]	
);	
	
#endif
	
CK_ADMIN_FUNCTION_INFO(TCE_UpdateTokenObjectList)
#ifdef CK_NEED_ARG_LIST
(
    CK_SLOT_ID slotID
);
#endif
	
CK_ADMIN_FUNCTION_INFO(TCE_analyze)
#ifdef CK_NEED_ARG_LIST
(
	CK_SLOT_ID slotId_hsmv,
	CK_CHAR **rpc_servers_ips,
	char  **rpc_servers_names,
	char **slot_names,
	TCE_INIT_ARGS *pInitArgs,
	unsigned int nRpc,
	unsigned char *password,
	unsigned int password_len,
	char *path,
	char *language
);
#endif
	
#ifdef __cplusplus
}
#endif









