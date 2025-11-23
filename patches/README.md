# Syzkaller OOB Fuzzer 패치 파일

이 디렉토리에는 Syzkaller에 적용할 패치 파일들이 있습니다.

## 포함된 파일

### 1. custom_oob.txt
커스텀 OOB 시스템콜 정의

**적용 위치:** `syzkaller/sys/linux/custom_oob.txt`

### 2. common_linux.h에 추가할 코드 (manual)
Executor 구현 - 파일 끝에 추가:

```c
#if SYZ_EXECUTOR

static void* oob_buffers[16] = {0};
static size_t oob_buffer_sizes[16] = {0};

#ifdef __cplusplus
extern "C" {
#endif

long syz_oob_alloc(volatile long size, volatile long flags) {
    if (size < 1 || size > 8192) return -1;
    
    void* buf = mmap(NULL, size, PROT_READ|PROT_WRITE, 
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) return -1;
    
    for (int i = 0; i < 16; i++) {
        if (oob_buffers[i] == NULL) {
            oob_buffers[i] = buf;
            oob_buffer_sizes[i] = size;
            debug("syz_oob_alloc: allocated %p size %zu\\n", buf, size);
            return (long)buf;
        }
    }
    
    munmap(buf, size);
    return -1;
}

long syz_oob_write(volatile long buf_ptr, volatile long offset,
                   volatile long data_ptr, volatile long count) {
    char* buf = (char*)buf_ptr;
    char* data = (char*)data_ptr;
    size_t buf_size = 0;
    
    for (int i = 0; i < 16; i++) {
        if (oob_buffers[i] == buf) {
            buf_size = oob_buffer_sizes[i];
            break;
        }
    }
    
    if (buf_size == 0) return -1;
    
    if ((size_t)(offset + count) > buf_size) {
        debug("syz_oob_write: OOB - buf_size=%zu, offset=%ld, count=%ld\\n",
              buf_size, offset, count);
    }
    
    memcpy(buf + offset, data, count);
    return 0;
}

long syz_oob_read(volatile long buf_ptr, volatile long offset,
                  volatile long data_ptr, volatile long count) {
    char* buf = (char*)buf_ptr;
    char* data = (char*)data_ptr;
    size_t buf_size = 0;
    
    for (int i = 0; i < 16; i++) {
        if (oob_buffers[i] == buf) {
            buf_size = oob_buffer_sizes[i];
            break;
        }
    }
    
    if (buf_size == 0) return -1;
    
    if ((size_t)(offset + count) > buf_size) {
        debug("syz_oob_read: OOB - buf_size=%zu, offset=%ld, count=%ld\\n",
              buf_size, offset, count);
    }
    
    memcpy(data, buf + offset, count);
    return 0;
}

long syz_oob_boundary_test(volatile long buf_ptr, volatile long buf_size,
                           volatile long access_offset, volatile long access_size) {
    if ((size_t)(access_offset + access_size) > (size_t)buf_size) {
        debug("syz_oob_boundary_test: VIOLATION\\n");
        return -1;
    }
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif
```

### 3. mutation.go에 추가할 코드 (manual)
`mutateInt` 함수 시작 부분에 추가:

```go
// OOB boundary-biased mutation
isOOBCandidate := strings.Contains(arg.Type().Name(), "offset") ||
                  strings.Contains(arg.Type().Name(), "size") ||
                  strings.Contains(arg.Type().Name(), "count")

if isOOBCandidate && r.oneOf(2) {
    boundaryValues := []uint64{0, 1, 255, 256, 512, 1024, 2048, 4096}
    
    switch r.Intn(5) {
    case 0:
        arg.Val = boundaryValues[r.Intn(len(boundaryValues))]
    case 1:
        bitSize := arg.Type().TypeBitSize()
        maxVal := uint64((1 << bitSize) - 1)
        arg.Val = maxVal - uint64(r.Intn(10))
    case 2:
        power := uint64(1 << r.Intn(13))
        arg.Val = power + uint64(r.Intn(3)) - 1
    case 3:
        arg.Val = uint64(^uint64(r.Intn(4096)))
    case 4:
        arg.Val += uint64(r.Int63n(16) - 8)
    }
    return true
}
```

## 적용 방법

`setup.sh` 스크립트가 자동으로 적용합니다.

수동 적용:
```bash
# 1. custom_oob.txt 복사
cp patches/custom_oob.txt workspace/syzkaller/sys/linux/

# 2. common_linux.h 수동 편집
# workspace/syzkaller/executor/common_linux.h 파일 끝에 위 코드 추가

# 3. mutation.go 수동 편집
# workspace/syzkaller/prog/mutation.go의 mutateInt 함수에 위 코드 추가
```
