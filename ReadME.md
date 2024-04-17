# MD5 Cracker

This is simple brute force multithread MD5 cracker. It can crack MD5 hashes or check how many hashes per second your computer can calculate.

## How to use

### Cracking MD5 hash

```MD5 [-v] passwordLength hash threads```

- `-v` - show statistics

### Checking performance

Software checks performance using 1, 2, 4, 8, 16 and 32 threads. Average speed is measured for 5 minutes.

```MD5 --test-speeds passwordLength```

## How to build

```bash
mkdir build
cmake -B build -S ./ 
cmake --build build --config Release --target all 
```
