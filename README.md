# -CN-Stripping-IP-packets
 - 2017년 1학기 성균관대학교 최형기 교수님 컴퓨터네트웤개론 수업 2번째 과제
 - IPv4 패킷 분석 및 추적 프로그램
 - 2017 1st semester Sungkyunkwan University Professor Hyoung-Kee Choi's Introduction to Computer Networking class, 2nd assignment
 - IPv4 packet analysis and tracking using Wireshark program

## 1. Problem
### (1) Object
 - You will be collecting a trace of packets using Wireshark or Tcpdump. You need to parse the trace to disclose packet’s information in the trace. This homework will help you to understand IP header clearly and extend your experience on networking tools and utilities.
   
### (2) Packet Trace
 - Using either Wireshark or Tcpdump you will be collecting packets into a file. 
 - Generate as various traffic as possible so that your trace would include different types of packets. 
 - Require your trace to have following property.
 
   ![image](https://user-images.githubusercontent.com/26705935/40837438-6a35b878-65d5-11e8-9920-49d08d87b557.png)
   
### (3) Format of Trace (PCAP formatted)
 - The first 24 bytes is for the file information. You may safely ignore this file header. 
 - Each packet is encapsulated a number of packet headers. 
 - The outmost one is 16-byte ***pcap_pkthdr***. The format of this header is shown in below.
 
   ![image](https://user-images.githubusercontent.com/26705935/40837520-acfb82e6-65d5-11e8-8961-7ef6fdb31601.png)
 
   - The ***struct timeval sec*** refers to the timestamp that packet was recorded into the trace in second. 
   - The ***struct timeval usec*** refers to the timestamp that packet was recorded into the trace in micro-second. 
   - The ***caplen*** refers to the length of the packet presented in the trace. 
   - The ***len*** refers to the actual length of the packet. 
   - Headers in the next are the Ethernet header and IP header. The formats of these headers are available in elsewhere.
   
### (4) Parsing Information
 - You need to parse the following information in the trace.
 
   ![image](https://user-images.githubusercontent.com/26705935/40837694-3e413cc8-65d6-11e8-81e3-cf22a61ed464.png)
   
 - Word of Caution) Please pay attention to the Endian. Depending upon the endian type the way you parse the information should be different. Verify your result against Wireshark.
 
## 2. Environment
 - language : C++
 - IDE : Microsoft Visual studio 2017
 - OS : Windows 10
 
## 3. Result
### (1) Wireshark에서 packet을 파일로 추출하기
 - Wireshark에서 Ethernet으로 Packet을 분석한 뒤에, 분석 결과를 .pcap 확장자 파일로 저장하였다.
 
### (2) 소스 코드 설명
 - 저장한 .pcap 파일을 불러오고, 패킷의 파일 헤더, 패킷 헤더 및 패킷을 순서대로 읽고 구조상대로 순차적으로 저장하였다.
 - 이후 형식에 맞도록 출력하였다. 주의할 점은 엔디안 방식에 따른 바이트 오더가 다르다는 것이다. Windows10, 즉 인텔 프로세스에서는 주로 리틀 엔디안(Little Endian) 바이트 오더를 사용한다. 또한 네트워크 상에서 표준으로 이용되는 프로토콜은 네트워크 바이트 오더인 빅 엔디안(Big Endian)으로 생각하였다. 이를 기준으로 바이트 오더를 바꾸는 함수(ntohs_)를 구현하여 수치의 바이트 오더를 고려하여 출력하였다.
 
 - 다음은 사용된 constant 및 구조체에 대한 설명이다.
 
 ```
 #define MAX_P 30
 
 - packet의 수가 많으면 결과를 출력하는 데 많은 시간이 소요되기 때문에, threshold를 30으로 설정하였다.
 ```
 
 ```
 typedef struct p_file_header_{
	int magic;
	unsigned short major_ver;
	unsigned short minor_ver;
	int thiszone;
	unsigned sigfigs;
	unsigned snaplen;
	unsigned linktype;
}p_file_header;

 - 파일 헤더의 형식이다. 따로 출력할 필요는 없지만, 읽어야 하기 때문에 구조체를 구현하고 저장만 하였다.
 ```

 ```
 typedef struct timeval_ {
	long timesec;
	long timeusec;
}timeval;

 - 패킷 헤더의 시간은 두 가지로 저장된다. 초 단위와 마이크로 초단위이다.
 ```

 ```
typedef struct ethernet_ {
	unsigned char dest_mac[MAC_ADDR_LEN];
	unsigned char src_mac[MAC_ADDR_LEN];
	unsigned short type;
}ethernet;
 
 - Ethernet 프로토콜 스택 구조에 맞게 구조체를 정의한다. 
 - Ethernet 프로토콜 스택 헤더는 목적지 MAC주소와 발신지 MAC 주소, 그리고 프로토콜 타입으로 구성된다.
 ```

 ```
typedef struct ip_header_{
	unsigned char hlen : 4;
	unsigned char version : 4;
	unsigned char service;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag;
	unsigned char time_to_live;
	unsigned char protocol;
	unsigned short checksum;
	unsigned int src_addr;
	unsigned int dest_addr;
}ip_header;

 - ip 헤더의 구조체 구성이다. 
 - hlen과 version은 호스트 바이트 오더가 little endian이라는 가정을 하고 순서를 바꾸었다.
 ```
 
 - 다음은 정의한 함수에 대한 설명이다.
   - void PacketParse(FILE *fp) : 각 패킷의 헤더를 읽고, 값을 저장.
   - void ViewPHeader(p_header *ph) : packet header의 구성 요소 및 내용 출력.
   - void ViewMac(unsigned char *mac) : MAC 주소를 형식에 맞게 출력.
   - unsigned short ntohs_(unsigned short value) : Endian 유형을 고려하여 값 변경.
   - void ViewEthernet(char *buffer) : Ethernet 프로토콜의 내용을 구조체에 저장 및 송,수신 MAC 주소를 출력.
   - void ViewIP(char *buffer) : IPv4 프로토콜을 분석하여 저장 및 내용 출력.
   
### (3) 실험 및 결과
 - Ethernet packet에 대해 코드를 실행한 결과는 다음과 같다.
 
   ![image](https://user-images.githubusercontent.com/26705935/40839300-e5d21196-65dc-11e8-8133-c2b3a09aef35.png)
 
 - 또한 Wireshark 프로그램을 이용하여 packet의 내용을 추출하였다.
   - Frame 1
 
     ![image](https://user-images.githubusercontent.com/26705935/40839329-05297ade-65dd-11e8-9081-8fc3bc4a2999.png)
   
   - Frame 2
   
     ![image](https://user-images.githubusercontent.com/26705935/40839361-2ee1fa2c-65dd-11e8-9820-95b95a229ac6.png)
   
   - Frame 3
   
     ![image](https://user-images.githubusercontent.com/26705935/40839367-36997dd0-65dd-11e8-8bcc-a9b1dc54a957.png)
   
 - 소스 코드 실행 결과와 Wireshark 분석 결과를 비교하였을 때, 각 frame마다 포함하고 있는 항목들의 값이 일치하는 것을 볼 수 있다.
 
## 4. Future work
 - 위의 코드는 Windows 10 OS 상에서 구현하였다. 운영체제에 따라 엔디안 방식이 달라지기 때문에, Linux OS에서도 구현해봄으로써 차이점을 분석한다.
