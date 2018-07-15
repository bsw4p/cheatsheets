# Libfuzzer


## Compilation

```bash
clang .. -fsanitize-coverage=trace-cmp -fsanitize=fuzzer,address .. 
```


## Coverage

### Compile
```bash
clang -fprofile-instr-generate -fcoverage-mapping  <target>.cc -o coverage
```

### Run 
```bash
./coverage <CORPUS> && llvm-profdata merge -sparse *.profraw -o coverage.profdata && llvm-cov show coverage -instr-profile=coverage.profdata
```

