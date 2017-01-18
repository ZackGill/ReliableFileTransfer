#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <map>
#include <string>
#include <vector>
#include <stdint.h>
#include <sys/stat.h>
#include <math.h>
#include <algorithm>
#include <deque>
#include <set>
#include <tuple>

using namespace std;

/*
 *	The Packet structure for our client-server file system (RATS, or RelilAble Tranfer System).
 *	Note: We will handle reliablity and all as not recieving ACKS. Although this may increase congestion,
 *	this protocol does not care about that.
 *	|opcode||sequence Number||data size||Checksum|
 *	  8bits       32bits      16 bits     16bits
 *	Opcode has some wasted bits, but easier to make it a byte on it's own.
 *	Opcode is: 	0x00 - File request, data is file path.
 *			0x01 - File Sending, data is file data.
 *			Ox02 - ACK, data is sequence number of next packet that is expected.
 *			0x03 - Error, file does not exist. Data is empty, size is set to 0.
 *			0x04 - Error ACK, data is empty.
 *			0x05 - Done Sending File, data and size are empty
 *			0x06 - File Done ACK, data and size are empty.
 *	Sequence Number is packet num. 32 bits are used to allow for large files being transferred.
 *	Data size: The size of the data section in bytes. For this project, goes up to 1024, but did 2 bytes
 *			for ease of implementation. 
 *	Checksum: Checksum of the entire packet. Typical type of checksum algorithim. 
 *	This means a header of 9 bytes. 
*/

typedef struct{
	char opCode;
	uint32_t seqNum;
	uint16_t size;
	uint16_t check;
}ratsHead;

struct packetData{
	unsigned char data[1015];
};

deque<tuple<int, struct packetData, size_t>> packetsRec; // deck of seq-num + packet data + packet size
set<uint32_t> sequence;

bool notDone = true;

int startWin = 0;
int endWin = 4;

// Comparator function to organize packetsRec
bool tupleCompare(tuple<int, struct packetData, size_t> first, tuple<int, struct packetData, size_t> second){
	return get<0>(first) < get<0>(second);
}

// Generates checksum like a regular IP checksum.
uint16_t generateChecksum(char *buf, int size)
{

	uint32_t sum = 0;
	uint16_t ip;
	unsigned char *place = (unsigned char *)buf;

	while(size > 1){
		ip = (short)(((short)place[1]) << 8) | place[0];
		sum += ip;
		if( sum & 0x80000000) // Carry
			sum = (sum & 0xFFFF) + (sum >> 16);
		size -= 2;
		place += 2;
	}
	// More Carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	// Invert sum
	return (uint16_t)(~sum);

}



// Return 1 if not valid, 0 if valid.
int checkChecksum(char* buf, int size)
{
	// To check checksum, go thorugh size bytes of buf, adding as words. If end up with 0
	// it is right.
	
	// Using generateChecksum function to check it. Assuming buf points to IP header, size is IP size.
	// Assuming Checksum field was not cleared to 0 before.
	uint16_t check = generateChecksum(buf, size);
	
	if(check == 0)
		return 0;
	return 1;
}


// fileData writes data to file, needs the socket, serverAddr, File Pointer, and the remaining 3 parameters are if
// the original packet needs to be resent.
void fileData(int &sock, struct sockaddr_in &serverAddr, FILE* file, bool &first, char *oldPacket, uint16_t &size){
	// check seq num of packet, copy it to our packetsRec deque.
	char buf[1024];
	socklen_t addrLen = sizeof(serverAddr);
	for(int i = 0; i < 5; i++){ // Expecting 5 packets, loop five times, but only add to packetsRec if unique
		int recLen = recvfrom(sock, buf, 1024, 0, (struct sockaddr *)&serverAddr, &addrLen);
		// If timeout error and was the first send, send file request again.
		if(errno == EAGAIN || errno == EWOULDBLOCK){
			if(first){
				int err = sendto(sock, oldPacket, (9 + size), 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
				if(err < 0){
					perror("Error requesting file: timeout\n");
				}
				first = false;
				return;
			}
		}
		first = false;
		
		ratsHead recHdr;
		char *current = buf;
		memcpy(&recHdr.opCode, current, 1);
		current++;
		memcpy(&recHdr.seqNum, current, 4);
		current+= 4;
		memcpy(&recHdr.size, current, 2);
		current += 2;
		memcpy(&recHdr.check, current, 2);
		current += 2;

		// Checksum. If bad, just drop.
		if(checkChecksum(buf, recLen) == 0){
			printf("Dropped packet: bad checksum seq is %d\n", recHdr.seqNum);
			continue;
		}

		// If File Not Found error, ack back and close.
		if(recHdr.opCode == 0x03){
			printf("Got file does not exist packet\n");
			char toSend[9];
			char *sendCurrent = toSend;
			ratsHead sendHdr;
		
			sendHdr.opCode = 0x04;
			memcpy(sendCurrent, &sendHdr.opCode, 1);
			sendCurrent++;
		
			sendHdr.seqNum = 0;
			memcpy(sendCurrent, &sendHdr.seqNum, 4);
			sendCurrent += 4;

			sendHdr.size = 0;
			memcpy(sendCurrent, &sendHdr.size, 2);
			sendCurrent += 2;

			sendHdr.check = 0;
			memcpy(sendCurrent, &sendHdr.check, 2);

			auto check = generateChecksum(toSend, 9);
			sendHdr.check = check;
			memcpy(sendCurrent, &sendHdr.check, 2);
			printf("Sending file does not exist ACK\n");
			int err = sendto(sock, toSend, 9, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
			if(err<0){
				perror("Error sending Error ACK\n");
				return;
			}
			notDone = false;
			return;
		}

		// If File done, ack back and return.
		if(recHdr.opCode == 0x05){
			printf("Got file done packet\n");
			char toSend[9];
			char *sendCurrent = toSend;
			ratsHead sendHdr;
		
			sendHdr.opCode = 0x06;
			memcpy(sendCurrent, &sendHdr.opCode, 1);
			sendCurrent++;
		
			sendHdr.seqNum = 0;
			memcpy(sendCurrent, &sendHdr.seqNum, 4);
			sendCurrent += 4;

			sendHdr.size = 0;
			memcpy(sendCurrent, &sendHdr.size, 2);
			sendCurrent += 2;

			sendHdr.check = 0;
			memcpy(sendCurrent, &sendHdr.check, 2);

			auto check = generateChecksum(toSend, 9);
			sendHdr.check = check;
			memcpy(sendCurrent, &sendHdr.check, 2);
			printf("Sending file done sending ACK\n");
			int err = sendto(sock, toSend, 9, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
			if(err<0){
				perror("Error sending Error ACK\n");
				return;
			}
			notDone = false;
			if(packetsRec.size() == 0)
				return;
		}

		uint32_t seq = recHdr.seqNum;
		printf("Data packet: seq is %u\n", seq);
	
		struct packetData data;
		memcpy(&data, current, recHdr.size);

		// if this sequence has not yet been found, add packet info.
		if(sequence.find(seq) == sequence.end()){
			if(recHdr.size > 0){
				packetsRec.push_back(make_tuple(seq, data, recHdr.size));
				sequence.insert(seq);
			}
		}
	}
	sort(packetsRec.begin(), packetsRec.end(), tupleCompare);

	// If the lowest recieved packet is our start window, can write. Increment start and end win, pop.
	while(get<0>(packetsRec.front()) == startWin){
		//printf("Writing packet %d\n", get<0>(packetsRec.front()));
		//printf("Packet size is %d\n", get<2>(packetsRec.front()));
		fwrite(&get<1>(packetsRec.front()), get<2>(packetsRec.front()), 1, file);
		startWin++;
		endWin++;
		packetsRec.pop_front();
	}

	uint32_t expected = 0;

	expected = (*sequence.end()) + 1;

	// Looking for a difference greater than 1. If there is one, we expected the current element + 1.
	// If no difference, we expect end + 1.
	for(auto a = sequence.begin(); a != sequence.end(); ++a){
		auto b = a;
		++b;
		if((*a - *b) > 1){
			if(((*a)+1) == startWin)
				expected = *(a) + 1;
		}
	}

	char toSend[13];
	char *sendCurrent = toSend;
	ratsHead sendHdr;
		
	sendHdr.opCode = 0x02;
	memcpy(sendCurrent, &sendHdr.opCode, 1);
	sendCurrent++;
		
	sendHdr.seqNum = 0;
	memcpy(sendCurrent, &sendHdr.seqNum, 4);
	sendCurrent += 4;

	sendHdr.size = 4;
	memcpy(sendCurrent, &sendHdr.size, 2);
	sendCurrent += 2;

	sendHdr.check = 0;
	memcpy(sendCurrent, &sendHdr.check, 2);
	sendCurrent += 2;

	memcpy(sendCurrent, &expected, 4);

	printf("seq num sending %d\n", expected);

	auto check = generateChecksum(toSend, 13);
	sendHdr.check = check;
	sendCurrent -= 2;
	memcpy(sendCurrent, &sendHdr.check, 2);
	printf("Sending file data ACK\n");
	int err = sendto(sock, toSend, 13, 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
	if(err < 0){
		perror("Error sending ack\n");
	}
	return;
}

int main(){
	



	char port[16];
	printf("Enter port: ");
	fgets(port, 16, stdin);

	if((atoi(port) <= 0) || (atoi(port) > 65535)){
		printf("Invalid port number.\n");
		return 1;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	if(sock < 0){
		perror("cannot create socket");
		return 1;
	}

	char ip[16];
	printf("Enter an IP: ");
	fgets(ip, 16, stdin);
	
	// Checking that ip is divided into 4 sections with '.', and all are numeric.
	int count = 0;
	char *temp = (char *)malloc(16);
	char *tempIP = (char *)malloc(16);
	strcpy(tempIP, ip);
	temp = strtok(tempIP, ".");

	// temp will be Null after last token is read/found with strtok
	while(temp != NULL)
	{
		count++;
		int i = 0;
		
		// Loop checks each character of current section to see if numeric.
		while(i < strlen(temp) - 1)
		{
			if (isdigit(temp[i])){
				i++;
			}
			else{
				printf("Not a valid IP. Not Numeric.\n");
				return 1;
			}
		}
		// Check that value of section is less than 256.
		if( (atoi(temp)) > 255 || atoi(temp) < 0){
			printf("Not a valid IP. Out of range.\n");
			return 1;
		}
		temp = strtok(NULL, ".");
	}
	// If we didn't loop above 4 times, wrong number of sections.
	if (count != 4){
		printf("Not a valid IP. Wrong number of sections.\n");
		free(temp);
		free(tempIP);
		return 1;
	}
	else{
		free(tempIP);
		free(temp);
	}


	printf("Enter relative file path you request: ");
	char *filep = (char *)malloc(256);
	fgets(filep, 256, stdin);


	// Setting up struct for bind. Using htonl to be portable and extra safe.
	struct sockaddr_in myAddr, serverAddr;
	myAddr.sin_family = AF_INET;
	myAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myAddr.sin_port = htons(atoi(port));


	int e = bind(sock, (struct sockaddr *)&myAddr, sizeof(myAddr));
	if(e < 0){
		perror("Bind didn't work\n");
		return 1;
	}
	filep = strtok(filep, "\n");

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = inet_addr(ip);
	serverAddr.sin_port = htons(atoi(port));

	// Send request, enter recv loop.
	ratsHead sendHdr;
	sendHdr.opCode = 0x00;
	sendHdr.seqNum = 0;
	sendHdr.size = strlen(filep);
	printf("Size is %d\n", sendHdr.size);
	sendHdr.check = 0;	

	char toSend[9 + sendHdr.size];

	char *current = toSend;
	memcpy(current, &sendHdr.opCode, 1);
	current++;
	memcpy(current, &sendHdr.seqNum, 4);
	current += 4;
	memcpy(current, &sendHdr.size, 2);
	current += 2;
	memcpy(current, &sendHdr.check, 2);

	current += 2;
	memcpy(current, filep, sendHdr.size);
	sendHdr.check = generateChecksum(toSend, sizeof(toSend));
	current -= 2;
	memcpy(current, &sendHdr.check, 2);


	printf("Sending request for file %s\n", filep);
	int err = sendto(sock, toSend, (9 + sendHdr.size), 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
	if(err < 0){
		perror("Error requesting file\n");
		return 1;
	}

	struct timeval timeout;
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
		perror("Setsockopt failed\n");



	FILE *file = fopen(filep, "wb");

	bool first = true;
	// Loops until flag notDone is unset when received fileDone ACK
	while(notDone){
		fileData(sock, serverAddr, file, first, toSend, sendHdr.size);
	}
	fclose(file);
	free(filep);

	return 0;
}
