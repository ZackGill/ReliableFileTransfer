/*
 * Project 4 Server
 *
*/
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
 *			Ox02 - ACK, data is sequence number of packet that is being ACKed.
 *			0x03 - Error, file does not exist. Data is empty, size is set to 0.
 *			0x04 - Error ACK, data is empty.
 *			0x05 - Done Sending file, data and size are empty.
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


int startWin, endWin, maxWin;
size_t fileSize;

int doneSending = 0; // Switch to 1 when done.
set <int> acks;
deque<struct packetData> packets;


void checkRecieve(char *buf, int &size, int &sock, struct sockaddr_in &clientAddr);

struct packetData{
	size_t dataSize;
	unsigned char data[1015];
};

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
	
	// Using generateChecksum function to check it. Assuming buf points to start of header.
	uint16_t check = generateChecksum(buf, size);
	if(check == 0)
		return 0;
	return 1;
}

// Returns the highest possible ACK following typical sliding window restrictions. 
int checkAcks(){
	// After sorting set of acks from least to greatest, loop through until greater than 1 diff.
	for(auto a = acks.begin(); a != acks.end(); ++a){
		auto b = a;
		++b;
		if((*a - *b) > 1)
			return *a;
	}
	return 0;
}

// checkRecieve checks a packet to see if it is an ACK or a request for a file. 
// buf is the packet data recieved, size is size of packet (counting checksum, opcode, and sequence)
// returns op code as int.
int checkRecieve(char *buf, int &size){
	if(maxWin < endWin)
		endWin = maxWin;
	ratsHead recHdr;
	char *current = buf;
	memcpy(&recHdr.opCode, current, 1);
	current++;
	memcpy(&recHdr.seqNum, current, 4);
	current += 4;
	memcpy(&recHdr.size, current, 2);
	current += 2;
	memcpy(&recHdr.check, current, 2);
	current += 2;
	//Check Checksum. If invalid, drop. We implement reliability via lack of ACKS, so don't send an error.
	if(checkChecksum(buf, size) == 0){
		printf("Dropped packet: Bad checksum\n");
		return -1;
	}

	// If Error ACK, simply reset everything
	if(recHdr.opCode == 0x04){
		startWin = 0;
		endWin = 4;
		return 4;
	}
	// File is done ACK, reset everything, return.
	if(recHdr.opCode == 0x06){
		startWin = 0;
		endWin = 4;
		return 6;
	}

	// If ACK, can update window.
	if(recHdr.opCode == 0x02){
		uint32_t seq;
		memcpy(&seq, current, 4);
		printf("Seq from ack was %d\n", seq);
		acks.insert(seq);

		if(startWin > maxWin)
			startWin = maxWin + 1;

		if(startWin < seq){
			startWin = seq;
			endWin = seq + 4;
		}
		if(endWin > maxWin)
			endWin = maxWin;
	
		if(startWin > maxWin)
			doneSending = 1;

		printf("startWin %d endWin %d maxWin %d\n", startWin, endWin, maxWin);

		return 2;
	}

	if(recHdr.opCode == 0x00){
		startWin = 0;
		endWin = 4;
		return 0;
	}
}

// Function to send the file not Found packet
void nullFile(int &sock, struct sockaddr_in &clientAddr){
	char toSend[9];
	char *sendCurrent = toSend;
	ratsHead sendHdr;
		
	sendHdr.opCode = 0x03;
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
	printf("Sending file not found\n");
	int err = sendto(sock, toSend, 9, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr));
	if(err < 0){
		perror("Error Sending error to client\n");
	}
	char buf[13]; // 13 bytes for error ACK (9 header, 4 data);
	socklen_t addrLen = sizeof(clientAddr);
	int recSize = recvfrom(sock, buf, 13, 0, (struct sockaddr *)&clientAddr, &addrLen);
	if(errno == EAGAIN || errno == EWOULDBLOCK){
		printf("Error sending, sending not found again\n");
		int err = sendto(sock, toSend, 9, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr));
		if(err < 0){
			perror("Error Sending error to client\n");
		}
		char buf[13]; // 13 bytes for error ACK (9 header, 4 data);
		socklen_t addrLen = sizeof(clientAddr);
		int recSize = recvfrom(sock, buf, 13, 0, (struct sockaddr *)&clientAddr, &addrLen);
	}
	printf("Error response is %d bytes\n", recSize);
	checkRecieve(buf, recSize);
	return;

}

// Filewrite sends the file in packets. Pass along the file path.
// Tries to open the file to see if it exists
void fileWrite(int &sock, struct sockaddr_in &clientAddr, char *buf){
	ratsHead recHdr;
	char *current = buf;
	memcpy(&recHdr.opCode, current, 1);
	current++;
	memcpy(&recHdr.seqNum, current, 4);
	current += 4;
	memcpy(&recHdr.size, current, 2);
	current += 2;
	memcpy(&recHdr.check, current, 2);
	current += 2;

	char filep[ntohs(recHdr.size)];
	memcpy(filep, current, ntohs(recHdr.size));

	FILE *file = fopen(filep, "rb");
	if(file == NULL){
		nullFile(sock, clientAddr);
		return;
	}
	struct stat status;
	stat(filep, &status);
	maxWin = ceil(status.st_size / 1015.0) - 1;
	fileSize = status.st_size;
	if(maxWin < endWin)
		endWin = maxWin;
	int first, oldWin;
	first = 1;
	oldWin = startWin;

	while(1){
		if(startWin > maxWin){
			oldWin = startWin;
			doneSending = 1;
		}
		for(int i = 0; i < (startWin - oldWin); i++){
			packets.pop_front();
			struct packetData data;
			if(fileSize < 1015){
					fread(&data.data, 1, fileSize, file);
					data.dataSize = fileSize;
			}
			else{
				fread(&data.data, 1, 1015, file);
				data.dataSize = 1015;
			}
			packets.push_back(data);
			fileSize -= 1015;
		}
		oldWin = startWin;
		if(first){ // First time sending, need to put in the starting packets.
			first--;
			for(int i = 0; i < endWin + 1; i++){
				struct packetData data;
				if(fileSize < 1015){
					fread(&data.data, 1, fileSize, file);
					data.dataSize = fileSize;
				}
				else{
					fread(&data.data, 1, 1015, file);
					data.dataSize = 1015;
				}
				packets.push_back(data);
				fileSize -= 1015;
			}
		}

		if(doneSending){ // Done, send packet saying so.
			char toSend[9];
			char *sendCurrent = toSend;
			ratsHead sendHdr;
		
			sendHdr.opCode = 0x05;
			memcpy(sendCurrent, &sendHdr.opCode, 1);
			sendCurrent++;
		
			sendHdr.seqNum = startWin+1;
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
			printf("Sending file done packet\n");
			int err = sendto(sock, toSend, 9, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr));
			if(err < 0){
				perror("Error Sending error to client\n");
				return;
			}
			char buf[9]; // 9 bytes for file done ACK (just header info);
			socklen_t addrLen = sizeof(clientAddr);
			int recSize = recvfrom(sock, buf, 9, 0, (struct sockaddr *)&clientAddr, &addrLen);
			printf("File done response is %d bytes\n", recSize);
			checkRecieve(buf, recSize);
			// Timeout error. Go to recursive function that keeps sending/calling itself till it works.
			if(errno == EAGAIN || errno == EWOULDBLOCK){
				//timeout(sock, toSend, clientAddr, 9);
			}
			fclose(file);
			return;
		}

		// Now have data packets to send, send them. Seq num is start win + whatever element it is.
		for(int i = 0; i < packets.size(); i++){
			char toSend[9 + packets[i].dataSize];
			char *sendCurrent = toSend;
			ratsHead sendHdr;
		
			sendHdr.opCode = 0x01;
			memcpy(sendCurrent, &sendHdr.opCode, 1);
			sendCurrent++;
			
			sendHdr.seqNum = startWin + i;
			if((startWin + i) > endWin)
				break;
			memcpy(sendCurrent, &sendHdr.seqNum, 4);
			sendCurrent += 4;
	
			sendHdr.size = packets[i].dataSize;
			memcpy(sendCurrent, &sendHdr.size, 2);
			sendCurrent += 2;	

			sendHdr.check = 0;
			memcpy(sendCurrent, &sendHdr.check, 2);		
			sendCurrent += 2;
			memcpy(sendCurrent, &packets[i].data, sendHdr.size);

			char *temp = toSend;

			auto check = generateChecksum(temp, 9 + sendHdr.size);
			sendHdr.check = check;
			sendCurrent -= 2;
			memcpy(sendCurrent, &sendHdr.check, 2);

			// Can send now
			printf("Sending file data to client\n");
			printf("Seq is %d\n", sendHdr. seqNum);
			int err = sendto(sock, toSend, sizeof(toSend), 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr));
			if(err < 0){
				perror("Error Sending data to client\n");
				return;
			}

		}

		char buf[13]; // 13 bytes for ACK (9 for header, 4 for data (seq num));
		socklen_t addrLen = sizeof(clientAddr);
		int recSize = recvfrom(sock, buf, 13, 0, (struct sockaddr *)&clientAddr, &addrLen);
		printf("ACK response is %d bytes\n", recSize);
		checkRecieve(buf, recSize);
		
		// Since this function is called multiple times, and we only change window based on acks.
		// Timeouts just mean we have to send packets again.


	}

}

// Start of sending packets. Called to faciliate things.
void recSend(int &sock, struct sockaddr_in &clientAddr){
	char buf[1024];
	socklen_t addrLen = sizeof(clientAddr);

	int recLen = recvfrom(sock, buf, 1024, 0, (struct sockaddr *)&clientAddr, &addrLen);
	int checker = checkRecieve(buf, recLen);
	if(checker == 0){ // Send along to fileWrite
		fileWrite(sock, clientAddr, buf);
	}
	return;
}



int main(){
	startWin = 0; // Window starts at 0-4
	endWin = 4;
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

	// Setting up struct for bind. Using htonl to be portable and extra safe.
	struct sockaddr_in serverAddr, clientAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(atoi(port));


	int e = bind(sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
	if(e < 0){
		perror("Bind didn't work\n");
		return 1;
	}

	struct timeval timeout;
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
		perror("Setsockopt failed\n");

	// Recieving loop
	while(1){
		recSend(sock, clientAddr);
	}
	

	return 0;
}
