# Easter Egg 3

Hint: https://twitter.com/OverTheWireCTF/
Points: 10
Solves: 36

I am the author of this challenge.

## Solution 
In the picture of this [tweet](https://twitter.com/OverTheWireCTF/status/1204370177237954565) there is a 2D barcode.
It's an Aztec barcode inside of a QR code. Here is a picture highlighting the Aztec code:
![easter egg 3 highlighted](https://github.com/semchapeu/CTF-WriteUps/blob/master/OverTheWire%20Advent%202019/Easter%20Egg%203/eastergg3_highlighted.png?raw=true)

Scanning the inner Aztec code results in `414f54577b6234726330643373`, if you decode this hex into ASCII you get `AOTW{b4rc0d3s`-
Scanning the outer QR code results in `137:64:137:154:171:146:63:175` if you decode these octal numbers into ASCII you get `_4_lyf3}`

Putting the two together you get the flag `AOTW{b4rc0d3s_4_lyf3}`.
