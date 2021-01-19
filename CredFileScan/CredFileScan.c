/*++

Module Name:

    CredFileScan.c

Abstract:

    This is the main module of the CredFileScan miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>

#define PORT_NAME L"\\CredFileScanPort"
#define FILE_READ_BUFFER_SIZE   1024
#define CREDIT_CARD_PATTERN_SIZE 21 // size of CREDIT_CARD_PATTERN
#define FILTER_FILE_EXT L"txt"

// Globals
PFLT_FILTER gFilterHandle;
PFLT_PORT gServerPort;
PFLT_PORT gClientPort;

// structure defines
typedef struct _FILE_SCAN_REQ {

	ULONG numBytes;
	ULONG Reserved;             // for quad-word alignement of the Contents structure
	UCHAR Buffer[FILE_READ_BUFFER_SIZE];

} FILE_SCAN_REQ, * PFILE_SCAN_REQ;

typedef struct _FILE_SCAN_REPLY {

	FILTER_REPLY_HEADER ReplyHeader;
	FILE_SCAN_REQ Reply;

} FILE_SCAN_REPLY, * PFILE_SCAN_REPLY;

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
CredFileScanUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CredFileScanPreWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

NTSTATUS
ConnectNotifCallback(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie
);

VOID
DisconnectNotifCallback(
	_In_opt_ PVOID ConnectionCookie
);

EXTERN_C_END


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, CredFileScanUnload)
#pragma alloc_text(PAGE, ConnectNotifCallback)
#pragma alloc_text(PAGE, DisconnectNotifCallback)
#endif

//
//  filter callbacks
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	
	{ IRP_MJ_WRITE,
	  0,
	  CredFileScanPreWrite,
	  NULL},

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    CredFileScanUnload,                           //  MiniFilterUnload
	NULL,								//  InstanceSetup
    NULL,								//  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete
    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;
	UNICODE_STRING portNameString;
	PSECURITY_DESCRIPTOR secDescriptor;
	OBJECT_ATTRIBUTES objAttr;

    UNREFERENCED_PARAMETER( RegistryPath );

    DbgPrint("CredFileScan!DriverEntry: Entered\n");

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //Register with filter manager
    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Create a communication port for communication with the user mode app.
	RtlInitUnicodeString(&portNameString, PORT_NAME);

	//  Set the appropriate access permissions
	status = FltBuildDefaultSecurityDescriptor(&secDescriptor, FLT_PORT_ALL_ACCESS);
	if (NT_SUCCESS(status)) {

		InitializeObjectAttributes(&objAttr,
			&portNameString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			secDescriptor);

		status = FltCreateCommunicationPort(gFilterHandle,
			&gServerPort,
			&objAttr,
			NULL,
			ConnectNotifCallback,
			DisconnectNotifCallback,
			NULL,
			1);
		
		FltFreeSecurityDescriptor(secDescriptor);

		if (NT_SUCCESS(status)) {

		    // Start filtering the file events
			status = FltStartFiltering(gFilterHandle);

			if (NT_SUCCESS(status)) {
               return STATUS_SUCCESS;
			}

			FltCloseCommunicationPort(gServerPort);
		}
	}
	FltUnregisterFilter(gFilterHandle);
    return status;
}

NTSTATUS
CredFileScanUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );
    PAGED_CODE();

    DbgPrint("CredFileScan!CredFileScanUnload: Entered\n");
	// Close the communication with the user mode app.
	FltCloseCommunicationPort(gServerPort);
	// Unregister filter
    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
CredFileScanPreWrite(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

	Pre write callback.- sends the file to user mode for scan. Replaces the file contents
	if credit card number is found.

Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
		operation.

	CompletionContext - Output parameter which can be used to pass a context
		from this pre-write callback to the post-write callback.

Return Value:

	Always FLT_PREOP_SUCCESS_NO_CALLBACK.

--*/
{
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION fileNameInfo = NULL;
	UNICODE_STRING fileExtentionToFilter = { 0 };
    BOOLEAN  scanFile = FALSE;
	PUCHAR buffer;
	PFILE_SCAN_REQ scanReq = NULL;
	FILE_SCAN_REQ reply = { 0 };
	ULONG replyLength;

	ULONG offset = 0;
	ULONG remainingSize = 0;
	
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	RtlInitUnicodeString(&fileExtentionToFilter, FILTER_FILE_EXT);

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fileNameInfo);
	if (NT_SUCCESS(status)) {
		FltParseFileNameInformation(fileNameInfo);
		DbgPrint("Pre write received for file- extension:%wZ, name:%wZ \n",
			     &fileNameInfo->Extension , &fileNameInfo->Name);
		if (RtlEqualUnicodeString(&fileNameInfo->Extension, &fileExtentionToFilter, TRUE)) {
			DbgPrint("Found TXT file \n");
			scanFile = TRUE;
		}
		FltReleaseFileNameInformation(fileNameInfo);
	}
	if (!scanFile) {
		return returnStatus;
	}
	
	// No connection to user mode component, do not scan.
	if (gClientPort == NULL) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	DbgPrint("Scan the file.\n");
	try {
		//  Pass the contents of the buffer to user mode.
		if (Data->Iopb->Parameters.Write.Length != 0) {
			buffer = Data->Iopb->Parameters.Write.WriteBuffer;
			
			// Allocate the user mode message
			scanReq = ExAllocatePoolWithTag(NonPagedPool,
				                            sizeof(FILE_SCAN_REQ),
				                            'derC');
			if (scanReq == NULL) {
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
				leave;
			}

			DbgPrint("Scan the file of length %lu\n", Data->Iopb->Parameters.Write.Length);
			// TODO: Instead of sending buffer in chunks to user mode, 
			// check if there is way to share big buffer between user and kernel mode.
			remainingSize = Data->Iopb->Parameters.Write.Length;

			while (remainingSize > 0) {
				scanReq->numBytes = min(remainingSize, FILE_READ_BUFFER_SIZE);
				
				try {

					RtlCopyMemory(&scanReq->Buffer,
						buffer + offset,
						scanReq->numBytes);

				} except(EXCEPTION_EXECUTE_HANDLER) {
					//  Error accessing buffer. 
					Data->IoStatus.Status = GetExceptionCode();
					Data->IoStatus.Information = 0;
					returnStatus = FLT_PREOP_COMPLETE;
					leave;
				}

				replyLength = sizeof(FILE_SCAN_REQ);
				DbgPrint("Sending file to user mode.numBytes:%lu\n", scanReq->numBytes);

				status = FltSendMessage(gFilterHandle,
					&gClientPort,
					scanReq,
					sizeof(FILE_SCAN_REQ),
					&reply,
					&replyLength,
					NULL);

				if (STATUS_SUCCESS == status) {
					DbgPrint("Successfully received reply from user mode. numBytes:%lu, replyLength:%d\n", reply.numBytes, replyLength);
					try {
						RtlCopyMemory(buffer + offset,
							reply.Buffer,
							reply.numBytes);

					} except(EXCEPTION_EXECUTE_HANDLER) {
						//  Error accessing buffer. 
						Data->IoStatus.Status = GetExceptionCode();
						Data->IoStatus.Information = 0;
						returnStatus = FLT_PREOP_COMPLETE;
						leave;
					}
				}
				else {
					DbgPrint("Error sending message to user-mode. Status 0x%X\n", status);
				}
				
				offset += scanReq->numBytes;
				remainingSize -= scanReq->numBytes;
				// To handle the boundry condition between two chunks of buffer
				// you need to subtract CREDIT_CARD_PATTERN_SIZE bytes.
				if (remainingSize != 0) {
					offset -= CREDIT_CARD_PATTERN_SIZE;
					remainingSize += CREDIT_CARD_PATTERN_SIZE;
				}
				DbgPrint("offset : %lu, remainingSize : %lu\n", offset, remainingSize);

			}
		}
	}
	finally {
		if (scanReq != NULL) {
			ExFreePoolWithTag(scanReq, 'derC');
	    }
	}

	return returnStatus;
}

NTSTATUS
ConnectNotifCallback(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie
)
/*++

Routine Description

	This is called when user-mode connects to the server port - to establish a
	connection

Arguments

	ClientPort - This is the client connection port that will be used to
		send messages from the filter

	ServerPortCookie - The context associated with this port when the
		minifilter created this port.

	ConnectionContext - Context from entity connecting to this port (most likely
		your user mode service)

	SizeofContext - Size of ConnectionContext in bytes

	ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

	STATUS_SUCCESS - to accept the connection

--*/
{
	PAGED_CODE();
	
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	DbgPrint("Connection established with user mode on port=0x%p\n", ClientPort);
	gClientPort = ClientPort;
	return STATUS_SUCCESS;
}


VOID
DisconnectNotifCallback(
	_In_opt_ PVOID ConnectionCookie
)
/*++

Routine Description

	This is called when the connection is torn-down. We use it to close our
	handle to the connection

Arguments

	ConnectionCookie - Context from the port connect routine

Return value

	None

--*/
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("User mode communication disconnected, port=0x%p\n", gClientPort);

	FltCloseClientPort(gFilterHandle, &gClientPort);
}
