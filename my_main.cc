#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "ftpdemo_pac.h"
#include "binpac.h"


using namespace std;


int main() {
  pcap_t *pcapfile;
  char errbuf[PCAP_ERRBUF_SIZE];
 const u_char *packet;
  struct pcap_pkthdr *header; 
 int code;
 
    click_ftp_info info;

  binpac::FTPDEMO::FTPDEMO_Conn* interp = new binpac::FTPDEMO::FTPDEMO_Conn(&info);
  
  binpac::const_byteptr buffer;

   bool real_orig = false;

  pcapfile = pcap_open_offline("/home/lavaniyaa/faf-exercise.pcap", errbuf);
  if (pcapfile == NULL) {
      cout << "pcap_open_offline() failed: " << errbuf << endl;
      return 1;
  }

 while((code = pcap_next_ex( pcapfile, &header, &packet)) >= 0){
 if (code < 0)
     cout << "Error in pcap_next_ex\n";
 buffer = const_cast<binpac::const_byteptr>(packet+54);
 interp->NewData(real_orig, buffer, buffer + (header->len-54) );
 if(info.portnum != NULL)
  cout<<info.portnum<<"\n";
 if(info.filetype != NULL)
  cout<<info.filetype<<"\n";
 }
 

  return 0;
}

