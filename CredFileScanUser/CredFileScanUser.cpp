// CredFileScanUser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <regex>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fltuser.h>
#include <sstream>

using namespace std;

#define FILE_READ_BUFFER_SIZE   1024
#define PORT_NAME L"\\CredFileScanPort"
#define WORKER_THREAD_COUNT        64
#define CREDIT_CARD_PATTERN "CC[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]"
#define CREDIT_CARD_FILL_IN "CCxxxx-xxxx-xxxx-xxxx"

typedef struct _FILE_SCAN_REQ {

	ULONG numBytes;
	ULONG Reserved;             // for quad-word alignement of the Contents structure
	UCHAR Buffer[FILE_READ_BUFFER_SIZE];

} FILE_SCAN_REQ, * PFILE_SCAN_REQ;

typedef struct _FILE_SCAN_REQ_MESSAGE {
	FILTER_MESSAGE_HEADER MessageHeader;
	FILE_SCAN_REQ Request;

	//
	//  Overlapped structure: this is not really part of the message
	//  However we embed it instead of using a separately allocated overlap structure
	//

	OVERLAPPED Ovlp;

} FILE_SCAN_REQ_MESSAGE, * PFILE_SCAN_REQ_MESSAGE;

typedef struct _FILE_SCAN_REPLY {
	FILTER_REPLY_HEADER ReplyHeader;
	FILE_SCAN_REQ Reply;

} FILE_SCAN_REPLY, * PFILE_SCAN_REPLY;

//
//  Context passed to worker threads
//

typedef struct WORKER_THREAD_CONTEXT {

	HANDLE Port;
	HANDLE Completion;

} WORKER_THREAD_CONTEXT, * PWORKER_THREAD_CONTEXT;

string convertToString(UCHAR* a, int size)
/*++

Routine Description

	Utility function to convert uchar buffer to string


Arguments

	a  - pointer to buffer
	size  - size of the buffer

Return Value

	string representation of the buffer

--*/
{
	UINT8* buff = new UINT8[size + 1];
	memcpy(buff, a, size);
	buff[size] = '\0';
	stringstream sstream;
	sstream << buff;
	string s = sstream.str();
	delete[] buff;
	return s;
}

DWORD
workerThread(
	_In_ PWORKER_THREAD_CONTEXT Context
)
/*++

Routine Description

	This is a worker thread that scans file contents for credit card number and replaces card number with
	defined pattern.


Arguments

	Context  - This thread context has a pointer to the port handle we use to send/receive messages,
				and a completion port handle that was already associated with the comm. port by the caller

Return Value

	HRESULT indicating the status of thread exit.

--*/
{
	PFILE_SCAN_REQ scanReq;
	FILE_SCAN_REPLY replyMessage;
	PFILE_SCAN_REQ_MESSAGE message;
	LPOVERLAPPED pOvlp;
	BOOL result;
	DWORD outSize;
	HRESULT hr;
	ULONG_PTR key;

	while (TRUE) {
		//  De-queue completion packets
		result = GetQueuedCompletionStatus(Context->Completion, &outSize, &key, &pOvlp, INFINITE);

		message = CONTAINING_RECORD(pOvlp, FILE_SCAN_REQ_MESSAGE, Ovlp);
		if (!result) {
			hr = HRESULT_FROM_WIN32(GetLastError());
			break;
		}
		printf("Received message, size %Id\n", pOvlp->InternalHigh);

		scanReq = &message->Request;
		assert(scanReq->numBytes <= FILE_READ_BUFFER_SIZE);
		
		// Manipulate buffer 
		std::regex regexp(CREDIT_CARD_PATTERN);

		string  buff = convertToString(scanReq->Buffer, scanReq->numBytes);
		//cout << buff << endl;
		string safeString = regex_replace(buff, regexp, CREDIT_CARD_FILL_IN);

		// Fill up the reply
		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;
		replyMessage.Reply.numBytes = scanReq->numBytes;
		memcpy(replyMessage.Reply.Buffer, safeString.c_str(), replyMessage.Reply.numBytes);

		printf("Replying message, numBytes: %d, replySize:%d\n", replyMessage.Reply.numBytes, sizeof(replyMessage));

		hr = FilterReplyMessage(Context->Port,
								(PFILTER_REPLY_HEADER)&replyMessage,
								sizeof(replyMessage));

		if (SUCCEEDED(hr)) {
			printf("Replied message\n");
		} else {
			printf("Error replying message. Error = 0x%X\n", hr);
			break;
		}

		memset(&message->Ovlp, 0, sizeof(OVERLAPPED));

		hr = FilterGetMessage(Context->Port,
							  &message->MessageHeader,
							  FIELD_OFFSET(FILE_SCAN_REQ_MESSAGE, Ovlp),
							  &message->Ovlp);

		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {

			break;
		}
	}

	if (!SUCCEEDED(hr)) {

		if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
			printf("Port is disconnected.\n");
		} else {
			printf("Unknown error occured. Error = 0x%X\n", hr);
		}
	}
	free(message);
	return hr;
}



int main()
{

	DWORD threadCount = WORKER_THREAD_COUNT;
	HANDLE threads[WORKER_THREAD_COUNT];
	WORKER_THREAD_CONTEXT context;
	HANDLE port, completion;
	PFILE_SCAN_REQ_MESSAGE msg;
	DWORD threadId;
	HRESULT hr;
	DWORD i;
	
	// Connect over communication port
	printf("Connecting to the mini filter ...\n");

	hr = FilterConnectCommunicationPort(PORT_NAME,
										0,
										NULL,
										0,
										NULL,
										&port);

	if (IS_ERROR(hr)) {
		printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
		return 2;
	}

	//  Create a completion port to associate with this handle.
	completion = CreateIoCompletionPort(port,
		NULL,
		0,
		threadCount);

	if (completion == NULL) {
		printf("ERROR: Creating completion port: %d\n", GetLastError());
		CloseHandle(port);
		return 3;
	}

	printf("Connection Port = 0x%p Completion Port= 0x%p\n", port, completion);
	context.Port = port;
	context.Completion = completion;

	// Create worker threads
	for (i = 0; i < threadCount; i++) {

		threads[i] = CreateThread(NULL, // default security
								  0, // default stack size
								  (LPTHREAD_START_ROUTINE)workerThread,
								  &context,
								  0,
								  &threadId);

		if (threads[i] == NULL) {
			hr = GetLastError();
			printf("ERROR: Couldn't create thread: %d\n", hr);
			goto exit;
		}


		//  Allocate the message.
		msg = (PFILE_SCAN_REQ_MESSAGE)malloc(sizeof(FILE_SCAN_REQ_MESSAGE));
		if (msg == NULL) {
			hr = ERROR_NOT_ENOUGH_MEMORY;
			goto exit;
		}
		
		memset(&msg->Ovlp, 0, sizeof(OVERLAPPED));

		//  Request messages from the filter driver
		hr = FilterGetMessage(port,
			&msg->MessageHeader,
			FIELD_OFFSET(FILE_SCAN_REQ_MESSAGE, Ovlp),
			&msg->Ovlp);

		if (hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
			free(msg);
			goto exit;
		}

	}

	hr = S_OK;
	WaitForMultipleObjectsEx(i, threads, TRUE, INFINITE, FALSE);

exit:
	CloseHandle(port);
	CloseHandle(completion);
	return hr;
}
