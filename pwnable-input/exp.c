i#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <unistd.h>
#include<sys/socket.h>
#include<arpa/inet.h>

int main(){
	char *argv[101]={"/home/input2/input",[1 ... 99]="a",NULL};
	argv['A']="\x00";
	argv['B']="\x20\x0a\x0d";
	argv['C']="12345";
	char* env[2]={"\xde\xad\xbe\xef=\xca\xfe\xba\xbe",NULL};
	
	FILE* fp=fopen("\x0a","w");
	fwrite("\x00\x00\x00\x00",4,1,fp);
	fclose(fp);
	
	int pipestdin[2]={-1,-1};
	int pipestderr[2]={-1,-1};
	pid_t pid;
	pipe(pipestdin);
	pipe(pipestderr);
	pid=fork();
	if(pid==0){
		close(pipestdin[1]);close(pipestderr[1]);
		dup2(pipestdin[0],0);close(pipestdin[0]);
		dup2(pipestderr[0],2);close(pipestderr[0]);
		execve("/home/input2/input",argv,env);
	}
	else{
		close(pipestdin[0]);close(pipestderr[0]);
		write(pipestdin[1],"\x00\x0a\x00\xff",4);
		write(pipestderr[1],"\x00\x0a\x02\xff",4);
		
	}
	
	sleep(1);
	int sockfd;
	struct sockaddr_in server;
	sockfd = socket(AF_INET,SOCK_STREAM,0);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(12345);
	connect(sockfd,(struct sockaddr*)&server,sizeof(server));
	char buf[4]="\xde\xad\xbe\xef";
	write(sockfd,buf,4);
	close(sockfd); 	
}

