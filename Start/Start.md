Start

I start with 2 basic commands: “file” and “checksec” and find out that there is no canary and NX was disabled, so I think there can be buffer overflow and ret2shellcode in this program. I also try to run it.

<img src="Start_assets/media/image1.png" style="width:6.5in;height:2.44028in" />

I reverse this program by IDA, but I cannot see any read or write functions in this program. However, I realize “Let's start the CTF:” was on stack, read and write function are using in system.

| **Lệnh**       | **Chuỗi ký tự ASCII** |
|----------------|-----------------------|
| push 3A465443h | "CTF:"                |
| push 20656874h | "the "                |
| push 20747261h | "art "                |
| push 74732073h | "s st"                |
| push 2774654Ch | "Let'"                |

<img src="Start_assets/media/image2.png" style="width:4.54885in;height:4.00021in" />

```asm
mov ecx, esp ; addr 
mov dl, 14h ; len 
mov bl, 1 ; fd 
mov al, 4 
int 80h ; LINUX - sys_write
-> sys_write function
xor   ebx, ebx
mov   dl, 3Ch ; '<'
mov   al, 3
int   80h           ; LINUX –
-> sys_read function
```

This challenge doesn’t have win function so I have to use bufferoverflow and ret2shellcode to solve this challenge. So I have to looking for return address and the offset.

<img src="Start_assets/media/image3.png" style="width:5.41742in;height:3.15669in" />

<img src="Start_assets/media/image4.png" style="width:5.96958in;height:2.40659in" />

I put 2 breakpoint at 0x0804808f and 0x0804809c in GDB, so I can easily find out offset = 0xffc5f318 - 0xffc5f304 = 0x14(20 in decimal)

Sys_write function can leak the stack address by jumping directly to the middle of the function bypasses the preparation of the text message.

The previous ret command removed 4 bytes, shifting ESP upward into an area used for system data.

The program immediately assigns this higher memory position as the target buffer for the write function.

The system leaks twenty bytes from that location, displayed ESP address in the first 4 bytes.

Return address = ESP address + offset

Then I can easily bufferoverflow and ret2shellcode

<img src="Start_assets/media/image5.png" style="width:6.5in;height:2.54375in" />

<img src="Start_assets/media/image6.png" style="width:6.5in;height:3.95278in" />
