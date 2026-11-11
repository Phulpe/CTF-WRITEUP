Stack1

<img src="Stack_assets/media/image1.png" style="width:6.5in;height:0.98403in" />

<img src="Stack_assets/media/image2.png" style="width:5.69871in;height:2.20864in" />  
  
<img src="Stack_assets/media/image3.png" style="width:5.91749in;height:2.55244in" />

I reverse this program by IDA and find out a function can make a error, strcpy() function does not check the size of variables. Allowing a stack to buffer overflow.

This challenge need v5 = 1633837924 to win, so I think I need to buffer overflow from dest to v5. As shown in IDA, dest\[64\] is stored in ESP+0x1C, v5 is stored in ESP+0x5C so offset = 0x5C – 0x1C = 0x40 (64 in decimal)

1633837924 in decimal = 0x61626364 in hex, maps to byte sequence 64 63 62 61 (ASCII "dcba")

So payload = b‘A’\*64 + b”dcba”, we need to send it to stack at the beginning of program

<img src="Stack_assets/media/image4.png" style="width:4.59439in;height:1.75024in" />

<img src="Stack_assets/media/image5.png" style="width:6.5in;height:0.61528in" />

Stack2

<img src="Stack_assets/media/image6.png" style="width:6.5in;height:0.66875in" />

<img src="Stack_assets/media/image7.png" style="width:4.72983in;height:2.20864in" />

<img src="Stack_assets/media/image8.png" style="width:5.59453in;height:2.8754in" />

I reversed this program in IDA and found a vulnerable strcpy() call that copies the GREENIE environment variable without checking its size, allowing a stack buffer overflow.

This challenge requires modified == 0x0d0a0d0a to win, so I need to overflow from buffer into modified. As shown in IDA, buffer\[64\] is stored at ESP+0x18 and modified is stored at ESP+0x58, so offset = 0x58 - 0x18 = 0x40 (64 in decimal).

In little-endian, 0x0d0a0d0a maps to the byte sequence \x0a\x0d\x0a\x0d. So payload = b"A"\*64 + b"\x0a\x0d\x0a\x0d". To deliver it, I use process(\[exe.path\], env={"GREENIE": payload}), which injects payload into the GREENIE environment variable for getenv("GREENIE") to read and pass into strcpy().

<img src="Stack_assets/media/image9.png" style="width:6.5in;height:1.84931in" />

<img src="Stack_assets/media/image10.png" style="width:6.5in;height:0.74375in" />

Stack3

I try to run, check the basic structure and protection of this program

<img src="Stack_assets/media/image11.png" style="width:6.5in;height:2.37639in" />

Then I reversed this program in IDA and found a vulnerable gets() function that reads user input without checking the buffer size, allowing a stack buffer overflow.

<img src="Stack_assets/media/image12.png" style="width:6.5in;height:2.15069in" />

<img src="Stack_assets/media/image13.png" style="width:6.5in;height:3.61875in" />

<img src="Stack_assets/media/image14.png" style="width:3.04209in;height:1.4377in" />

This challenge requires overwriting the function pointer fp with the address of win() (0x08048424) so the program jumps to win() when calling fp(). As shown in IDA, buffer\[64\] is stored at ESP+0x1C (EBP-0x4C) and fp is stored at ESP+0x5C (EBP-0x0C), so offset = 0x5C - 0x1C = 0x40 (64 in decimal).

So payload = b"A"\*64 + p32(0x08048424), which we send to stdin when gets() executes.

<img src="Stack_assets/media/image15.png" style="width:5.04237in;height:2.1253in" />

<img src="Stack_assets/media/image16.png" style="width:5.30282in;height:1.30226in" />

Stack 4

<img src="Stack_assets/media/image17.png" style="width:6.5in;height:2.65556in" />

<img src="Stack_assets/media/image18.png" style="width:6.03209in;height:1.47937in" /><img src="Stack_assets/media/image19.png" style="width:4.87568in;height:1.57314in" />

<img src="Stack_assets/media/image20.png" style="width:2.417in;height:0.80219in" />

In IDA, I see win() function and error from gets() function, so I think this is buffer overflow and ret2win

<img src="Stack_assets/media/image21.png" style="width:6.5in;height:5.99028in" />

In GDB, I put breakpoint at get and ret command to see their storage address, ret command in ESP 0xffbf3a2c, get command in 0xffbf399e0, so the offset = 0xffbf3a2c - 0xffbf399e0 = 0x4C(76 in decimal)

So the payload = b’A’\*76 + p32(0x080483f4)

<img src="Stack_assets/media/image22.png" style="width:6.05293in;height:2.33366in" />

<img src="Stack_assets/media/image23.png" style="width:4.59439in;height:0.79178in" />
