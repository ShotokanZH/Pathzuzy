/*
make test
chown root:root test
chmod 4755 test		#setuid!!
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
using namespace std;

int main(){
	cout<<"Running as: "<<endl;
	system("whoami");
	cout<<"Elevating.."<<endl;
	setuid(0);
	system("whoami");
	return 0;
}

