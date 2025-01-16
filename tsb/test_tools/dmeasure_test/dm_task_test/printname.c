#include<stdio.h>
#include<unistd.h>

int main(void){
        int ret = 0;

        for(;;){
                printf("%s\n", "My name is Linux");
                sleep(2);
        }

        return ret;
}
