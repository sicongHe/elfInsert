#include "/usr/include/elf.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>    
#include <sys/io.h>
void workOutAddr(int value, int arr[]) {
  int a = value/(16*16);
  int b = value%(16*16);
  int a2 = a / (16*16);
  int b2 = a % (16*16);

  arr[0] = b;
  arr[1] = b2;
  arr[2] = a2;
}
int main(){
	//get orig_entry
	char elf_ehdr[sizeof(Elf64_Ehdr)];
	Elf64_Ehdr *p_ehdr;
	p_ehdr = (Elf64_Ehdr *)elf_ehdr;
	int origfile = open("test", O_RDONLY);
	ssize_t ret = read(origfile, elf_ehdr, sizeof(elf_ehdr));
	Elf64_Addr orig_entry = p_ehdr->e_entry;
	Elf64_Addr new_entry = 0;
	printf("Elfhead size:%d\n", (int)(p_ehdr->e_ehsize));
	printf("Orig_Entry:%x\n", (int)(orig_entry));

	//get program_head_vaddr 
	//get program_head_size
	char elf_phdr[sizeof(Elf64_Phdr)];
	Elf64_Phdr *p_phdr;//programe header
	p_phdr = (Elf64_Phdr *)elf_phdr;
	Elf64_Addr program_head_vaddr = 0;
	Elf64_Word program_head_size = 0;
	for (int i = 0; i < (int)(p_ehdr->e_phnum); i++){
		read(origfile, elf_phdr, sizeof(elf_phdr));
		// printf("for times:%d\n", i);
		if(p_phdr->p_paddr < orig_entry && (p_phdr->p_paddr + p_phdr->p_filesz) > orig_entry){
			printf("%s %d \n", "get:",i);
			program_head_vaddr = p_phdr->p_vaddr;
			program_head_size = p_phdr->p_filesz;
		}
	}
	printf("program head Vaddr:%lu\n", program_head_vaddr);
	printf("program head size:%d\n", program_head_size);

	//get new_entry
	char elf_shdr[sizeof(Elf64_Shdr)];
	Elf64_Shdr *p_shdr;
	p_shdr = (Elf64_Shdr *)elf_shdr;
	Elf64_Off entry_section_offset = 0;
	Elf64_Xword entry_section_size = 0;
	int dis = (int)p_ehdr->e_shoff - sizeof(elf_ehdr) - (int)p_ehdr->e_phnum*sizeof(elf_phdr);
	ret = lseek(origfile, (int)p_ehdr->e_shoff - sizeof(elf_ehdr) - (int)p_ehdr->e_phnum*sizeof(elf_phdr), SEEK_CUR);
	for (int i = 0; i< (int)p_ehdr->e_shnum; i++){
		read(origfile, elf_shdr, sizeof(elf_shdr));
		//printf("for times:%d\n", i);
		if (p_shdr->sh_addr+p_shdr->sh_size == program_head_vaddr+program_head_size){
			printf("%s%d\n", "get:",i);
			entry_section_offset = p_shdr->sh_offset;
			entry_section_size = p_shdr->sh_size;
			new_entry = p_shdr->sh_addr + p_shdr->sh_size;
		}
	}
	printf("new_entry:%x\n", (int)new_entry);
	
	int ori_arr[3];
  workOutAddr(orig_entry, ori_arr);

  //计算出数据的地址,扔到将插入的代码中
  int dataEntry = new_entry + 73;
  int data_arr[3];
  workOutAddr(dataEntry, data_arr);

  //机器码。作用是创建一个文件写入字符串
  //其中0x5*是将压栈与弹栈保护其中原始内容
  char binary[] = {
    0x50,
    0x53,
    0x51,
    0x52,
    0x48, 0xc7, 0xc0, 0x08, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc3, data_arr[0], data_arr[1], data_arr[2], 0x00,
    0x48, 0xc7, 0xc1, 0xa4, 0x01, 0x00, 0x00,
    0xcd, 0x80,
    0x48, 0x89, 0xc3,
    0x48, 0xc7, 0xc0, 0x04, 0x00, 0x00, 0x00,
    0x48, 0xc7, 0xc1, data_arr[0], data_arr[1], data_arr[2], 0x00,
    0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00,
    0xcd, 0x80,
    0x48, 0xc7, 0xc0, 0x06, 0x00, 0x00, 0x00,
    0xcd, 0x80,
    0x5a,
    0x59,
    0x5b,
    0x58,

    //跳转指令
    0xbd, ori_arr[0], ori_arr[1], ori_arr[2], 0x00, 0xff, 0xe5,

    //数据区域
    0x68, 0x65, 0x6c, 0x6c, 0x6f,
    0x00, 0x66, 0x2e,
    0xef, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
    0x00
  };
	//insert new code
	lseek(origfile, 0, SEEK_SET);
	char nop[] = {0x90};
	char parasize[] = {0xbd, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe5};
	struct _jump
	{
		char opcode_mov;
		int addr;
		short opcode_jmp;
	}__attribute__((packed));
    // printf("%lu\n", sizeof(parasize));
	struct _jump * jump = (struct _jump *)parasize;
	// printf("%lu\n", sizeof(jump));
	jump->addr = orig_entry;
	// printf("%lu\n", sizeof(jump));
 //    printf("%lu\n", sizeof(parasize));
    printf("%s\n", "Creating a new file...");
    //create new file
    int newfile = open("newtest",O_RDWR);
    //long unsigned int length = 2437320;
   	read(origfile, elf_ehdr, sizeof(elf_ehdr));
    p_ehdr->e_entry = new_entry;
    p_ehdr->e_shoff += 4096;
    write(newfile,elf_ehdr,sizeof(elf_ehdr));
    int pflag = 0;
    for (int i = 0; i < (int)(p_ehdr->e_phnum); i++){
		read(origfile, elf_phdr, sizeof(elf_phdr));
		printf("for times:%d\n", i);
		if(pflag == 1){
			p_phdr->p_offset += 4096;
		}
		if(i == 2){
			printf("%s %d \n", "get:",i);
			p_phdr->p_memsz += 4096;
			p_phdr->p_filesz += 4096;
			//program_head_vaddr = p_phdr->p_vaddr;
			//program_head_size = p_phdr->p_filesz;
			pflag = 1;
		}
		write(newfile, elf_phdr, sizeof(elf_phdr));
	}
	printf("new program head Vaddr:%lu\n", program_head_vaddr);
	printf("new program head size:%d\n", program_head_size);
	printf("jump distance:%d\n", dis);
	char tmp[2435000];
	// printf("write size:%ld\n" ,write(newfile,tmp,dis + 4096));
	// lseek(origfile, dis, SEEK_CUR);
	int pos = lseek(origfile,0,SEEK_CUR);
	read(origfile,tmp,entry_section_offset + entry_section_size - pos);
	write(newfile,tmp,entry_section_offset + entry_section_size - pos);
	
	write(newfile, binary,sizeof(binary));
	for (int i = 0; i < 4096 - sizeof(binary); i++){
		write(newfile,nop,1);
	}
	read(origfile,tmp,dis - (entry_section_offset + entry_section_size - pos));
	write(newfile,tmp,dis - (entry_section_offset + entry_section_size - pos));
	int afterA = 0;
	for (int i = 0; i< (int)p_ehdr->e_shnum; i++){
		read(origfile, elf_shdr, sizeof(elf_shdr));
		//printf("for times:%d\n", i);
		if(afterA == 1){
			p_shdr->sh_offset += 4096;
			//p_shdr->sh_addr += 4096;
		}
		if (i == 18){
			printf("%s%d\n", "get:",i);
			p_shdr->sh_size += 4096;
			//p_shdr->sh_entsize += 4096;
			afterA = 1;
		}
		
		write(newfile,elf_shdr,sizeof(elf_shdr));
	}
	printf("new_entry:%x\n", (int)new_entry);
	close(newfile);
	close(origfile);
	return 0;
}
