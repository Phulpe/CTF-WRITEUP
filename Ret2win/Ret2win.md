Ret2win

I started with common “checksec” and “file” command to know the basic structure of this challenge, and run it to know how it works.

<img src="Ret2win_assets/media/image1.png" style="width:6.5in;height:3.99444in" />

Then I use IDA to reverse this program. In pwnme function, I notice the array of s has 32 bytes but read command can read 0x38u(56 in decimal) bytes, and the canary turned off so I think that we will use buffer overflow to solve this challenge.

<img src="Ret2win_assets/media/image2.png" style="width:6.5in;height:1.86528in" />

<img src="Ret2win_assets/media/image3.png" style="width:4.78192in;height:1.70857in" />

I also see system(“/bin/cat flag.txt”) command in ret2win function, so I think I have to reach this function to solve the challenge.

<img src="Ret2win_assets/media/image4.png" style="width:6.5in;height:4.45625in" />-\> Therefore I guess that I must send payload from read function to the return address of pwnme function and insert the ret2win function address to make the program run into ret2win function.

I put breakpoints at read function and at the end of pwnme function

<img src="Ret2win_assets/media/image5.png" style="width:6.5in;height:4.28819in" />I see the read command is stored in RSP 0x7ffcc7c07040 this gdb

<img src="Ret2win_assets/media/image6.png" style="width:6.5in;height:4.23611in" />

And I see the ret command of pwnme function is stored in 0x7ffcc7c07068 in this gdb and located in 0x400755

<img src="Ret2win_assets/media/image7.png" style="width:5.85498in;height:2.65662in" />

Finally, I see the address of ret2win function is 0x400756

-\> &#32;Offset: 0x7ffcc7c07068 - 0x7ffcc7c07040 = 0x28(40 in decimal) and the ret2win function address is 0x400756 so I can easily write explosive script to solve this challenge.

<img src="Ret2win_assets/media/image8.png" style="width:6.12586in;height:3.29213in" />

Because there are only 8 bytes to return at 0x400756 and cannot run system() function, so I must push return address at 0x400755 to have 16 bytes

<img src="Ret2win_assets/media/image9.png" style="width:5.56328in;height:3.20878in" />
