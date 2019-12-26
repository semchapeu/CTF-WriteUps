# Heap Playground

- Points: 368
- Solves: 31
- Author: semchapeu

## Solution

It's a x86_64 binary with the common protections PIE, Full-Relro, stack canaries and a non-executable stack. It uses glibc 2.27 with tcache enabled.

When you run it you are presented with the following options:

```
1. Create chunk
2. Delete chunk
3. Print chunk
4. Edit chunk
5. Exit
```

- Create chunk allows you to allocate chunks with sizes from 1 to 1024 bytes and fill it with data.
- Delete chunk allows you to free a chunk.
- Print chunk will print the contents of a chunk.


The vulnerability is in the edit_chunk function:
```C
void edit_chunk(struct chunk *chunk, int index, char c){
	if(index < 0){
		index = -index;
	}
	index = index % chunk->size;
	memset((char *)chunk+index+sizeof(struct chunk),c,1);
}
```

When `index` is below 0 it negates it. However if `index` is `0x80000000` (`-2147483648` in decimal), negating this number does not change it at all and it remains negative (This is known as the "Leblancian Paradox"). A negative number modulo a positive number is negative. Meaning `index` will be negative and can be somewhat controlled by the chunk size.

Now that you can write out of bounds of any chunk you created you can use various heap exploitation methods to leak adresses and a get a shell. See [exploit.py](./exploit.py)
