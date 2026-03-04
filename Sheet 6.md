# Task 1
- We used the following C code to:
    - Measure the time (in CPU cycles) to access a variable when **cached**.
    - Measure the time to access the same variable after **flushing it from cache**.
- We utilized:
    - `__rdtscp()` for accurate time measurement.
    - `_mm_clflush()` to flush the variable from the cache.
#### 🔧 Code Summary:
- We used a single `uint8_t` variable (`target = 42`) to measure access time.
- Each measurement was repeated `NUM_TRIALS = 100` times.
- Results were saved in a CSV file (`cache_timings.csv`) for visualization.
- After running the code, we visualized the data using a Python script with seaborn/matplotlib.
    - **Cache hits** consistently took ~84 CPU cycles.
    - **Cache misses** varied significantly but were much higher, with a median of 728 cycles.
    - The Python script also suggested a **median-based threshold** of 406 cycles
![[Pasted image 20250717012640.png]]
# Task 2
- The attack follows a 3-step process:
1. **FLUSH**: Evict all array elements from the CPU cache using `_mm_clflush()`.
2. **VICTIM ACCESS**: Let the victim function access `array[secret].dat`, which brings that specific element back into the cache.
3. **RELOAD**: Measure the access time for every `array[i].dat`. The one with a time below a known threshold (`406 cycles`) is inferred to be the secret index.
## Cache Isolation with `DataBlock`
- To prevent false cache hits caused by cache line sharing or CPU prefetching, we used a padded struct:
```
typedef struct datablock {
    uint8_t lpad[2048];   // padding to shift 'dat' far from neighbors
    uint8_t dat;          // the actual value accessed
    uint8_t rpad[2047];   // ensures 4096 bytes total (1 page)
} DataBlock;
```
- This guarantees that each `dat` value:
    - Sits in a unique cache line
    - Is mapped to its own 4KB memory page
    - Cannot be preloaded by neighboring memory access patterns
## **Final Code Overview**
- flushSideChannel()
```
void flushSideChannel() {
    for (int i = 0; i < 256; i++) {
        _mm_clflush(&array[i].dat);  // ✅ Evicts each dat from cache
    }
}
```
- reloadSideChannel()
```
uint8_t reloadSideChannel() {
    int junk = 0;
    uint64_t time1, time2;
    uint64_t best_time = UINT64_MAX;
    int best_index = -1;

    for (int i = 0; i < 256; i++) {
        volatile uint8_t *addr = &array[i].dat;

        time1 = __rdtscp(&junk);
        junk = *addr;
        time2 = __rdtscp(&junk) - time1;

        // ✅ Choose lowest access time under threshold
        if (time2 < best_time && time2 < CACHE_HIT_THRESHOLD) {
            best_time = time2;
            best_index = i;
        }
    }

    return best_index;
}

```
## Experimental Results
![[Pasted image 20250717013150.png]]
# Task 4
- We were provided with a skeleton `SpectreExperiment.c` file. We integrated previously implemented `flushSideChannel()` and `reloadSideChannel()` functions, and used a padded `DataBlock` structure to isolate each byte in its own cache line. We then trained the CPU’s branch predictor using valid inputs and attempted to trigger speculative execution with an out-of-bounds index (`97`). The reload logic then detected which value was loaded speculatively into the cache.

## Explanation of Results
- During execution, the for-loop in Exhibit A.1 calls `victim(i)` for values `0–9`, which are all valid (`x < size`). This consistently taken branch trains the CPU’s branch predictor to assume that the condition is usually true. Then, when `victim(97)` is called, the CPU speculatively executes the memory access inside the `if` block, loading `array[97].dat` into the cache. Although the speculative result is discarded, the cache state remains altered. By measuring access times to all array indices in `reloadSideChannel()`, we can detect which index was accessed speculatively.
- ![[Pasted image 20250717014115.png]]
## Answers to Theoretical Questions
### Q1: What is the role of the for-loop marked as Exhibit A.1...?
- The for-loop in Exhibit A.1 trains the CPU’s branch predictor. It calls `victim(i)` with `i = 0–9`, which satisfies `x < size` (size = 10). The CPU sees that this branch is always true and starts predicting that future `x < size` checks will also be true. When we later call `victim(97)`, the CPU speculatively assumes the branch is true and accesses `array[97].dat`. This speculative access is leaked into the cache, allowing the attacker to detect the secret through timing.
---
### Q2: What happens when you comment out Exhibit B and Exhibit C...?
- **Exhibit B** (`_mm_clflush(&size)`) is used to delay the CPU’s ability to check `x < size`. If we comment it out, the CPU gets the correct value of `size` too quickly and does not speculate. As a result, no speculative access occurs, and the attack fails.
- becaus the size value will be in cach 
     - ![[Pasted image 20250717014340.png]]
     - Attack fails when Exhibit B is commented out — no speculative execution triggered.
---
- **Exhibit C** (`flushSideChannel()`) ensures that all `array[i].dat` values are removed from the cache before the speculative access. Without it, many entries are already in the cache (e.g., from training), causing noisy measurements and frequent false positives. This leads to incorrect results or no leak detection.
    - ![[Pasted image 20250717014452.png]]
    - Attack becomes noisy when Exhibit C is removed — many false positives appear due to residual cache entries.
---
### Q3: What happens when you replace `victim(i)` with `victim(i + 20)`...?
- When `victim(i)` is replaced with `victim(i + 20)`, the training loop uses values like `victim(20)` to `victim(29)`, which are all invalid (`x >= size`). This causes the branch predictor to learn that the condition `x < size` is usually false. As a result, when `victim(97)` is called later, the CPU predicts the branch as false and does not speculatively execute the memory access. Therefore, the secret is not loaded into the cache, and the attack fails.
     - ![[Pasted image 20250717014653.png]]
     - Training with invalid inputs disables speculative execution — secret not leaked.
# Task 5
## Understanding the Code Structure
- **`restrictedAccess(size_t x)`**: Enforces sandboxing by allowing access only within `[0, 9]`.
- **`spectreAttack(size_t malicious_x)`**:
    - Trains the branch predictor with in-bound accesses.
    - Flushes the upper bound and the side channel.
    - Triggers speculative out-of-bounds access using the `malicious_x` offset to read the secret.
    - Loads `array[secret_byte].dat` to leave a footprint in the cache.
- **`reloadSideChannel()`**:
    - Iterates over all 256 entries.
    - Measures access time using `__rdtscp`.
    - Detects which `array[i].dat` was loaded speculatively.
- **`flushSideChannel()`**: Evicts all cache lines.
## Experimental Results
- The program was executed multiple times. In several runs, the correct result `83 (S)` was recovered, which corresponds to the ASCII value of the first character in the secret string. However, occasional failures (`0 ()`) were also observed, due to the inherent noise in speculative execution and timing measurements.
- ![[Pasted image 20250717014958.png]]
# Task 6
## Approach
- We repeated the speculative attack multiple times (`ATTACK_ATTEMPTS = 30`) and recorded which byte was most frequently accessed via the FLUSH+RELOAD technique.
- We used a **results[256] array** to count the number of cache hits per possible secret value.
- After the loop, we chose the byte with the maximum hits as the most likely secret.
- A short **busy-wait delay** was introduced to avoid noisy CPU cache behavior between attempts.
## Code Modifications
- Added a loop around `spectreAttack()` and `reloadSideChannel()` in `main()`.
- Introduced `results[]` to store counts.
- Added `busy_wait()` function to reduce noise.
- Replaced speculative access with:
```
volatile uint8_t *target = (uint8_t *)buffer + offset;
s = *target;
array[s].dat += 1;
```
## Outcome
- After 30 attack attempts, the correct secret byte (e.g., `'S'` with ASCII 83) was successfully recovered in most runs.
![[Pasted image 20250717015254.png]]

# Task 7
## Approach
- We **reuse the existing Spectre attack** logic from Task 6, which can extract a single byte using speculative out-of-bounds access.
- To extract the full string, we:
    1. Loop over all indices of the secret string.
    2. Adjust the offset passed to the Spectre gadget for each character.
    3. Perform multiple attempts per byte and use a voting scheme to guess the most likely value.
    4. Store and print the leaked bytes until the full string is recovered.

## Code Modifications
- In the `main()` function, we added a loop:
```
for (int byte_index = 0; byte_index < strlen(secret); byte_index++) { ... }
```
- We calculate the offset dynamically:
```
size_t offset = (size_t)((uintptr_t)secret - (uintptr_t)buffer) + byte_index;
```
- The guessed values for each byte are stored in a `char recovered[]` array and printed after the loop.
## **Results**
![[Pasted image 20250717015609.png]]