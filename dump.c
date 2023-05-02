#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

/*
 * memory format
 * 0x00:  ??
 * 0x04:  Memory buffer
 * 0x08:  Buffer size
 * 0x0C:  ??
 * 0x10:  ??
 * 0x14:  Lower memory bound
 * 0x18:  Upper memory bound
*/
struct memory_region {
    uint8_t  unk0[4];
    uint32_t buf_addr;
    uint32_t buf_size;
    uint8_t  unk1[8];
    uint32_t lower_mem_bound;
    uint32_t upper_mem_bound;
    uint8_t  unk2[4];
};

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <Emulator PID> <Rom Dump> [Ram Dump]", argv[0]);
        return -1;
    }

    // Get handle on the emulator
    uint32_t pid;
    sscanf(argv[1], "%" SCNd32, &pid);

    HANDLE proc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        false, pid
    );

    if (proc == NULL) {
        printf("Failed to open handle: 0x%x\n", GetLastError());
        return -1;
    }

    // Scan for pattern to find CSimU8core instance
    // 57 44 54 49 4E 54 00 00 00 00 00 00 00 00 00 00 00 00
    static const uint8_t pattern[] = {0x57, 0x44, 0x54, 0x49, 0x4E, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint64_t *matches = NULL;
    int numMatches = 0;
    uint64_t addr;
    MEMORY_BASIC_INFORMATION blockInfo;
    for(addr = 0; VirtualQueryEx(proc, (LPCVOID)addr, &blockInfo, sizeof(blockInfo)) != 0; addr += blockInfo.RegionSize) {
        //printf("ADDR: %08llx SIZE: %08lx STATE: %08lx TYPE: %08lx PROTECT: %08lx\n", addr, blockInfo.RegionSize, blockInfo.State, blockInfo.Type, blockInfo.Protect & PAGE_GUARD);
        // Check that the memory is commited (ie actually in use) and that's it's private
        if (blockInfo.State == MEM_COMMIT && (blockInfo.Protect & PAGE_GUARD) == 0) {
            // Copy it into our address space
            uint8_t *buffer = malloc(sizeof(uint8_t) * blockInfo.RegionSize);
            uint32_t bytesRead;
            if(ReadProcessMemory(proc, (LPCVOID)addr, buffer, blockInfo.RegionSize, &bytesRead) == 0) {
                printf("Failed to read memory: 0x%x\n", GetLastError());
                printf("Read 0x%x bytes\n", bytesRead);
                return -1;
            }

            // Search for pattern
            int pIdx = 0, mIdx = 0;
            while(mIdx <= blockInfo.RegionSize) {
                if (buffer[mIdx] == pattern[pIdx]) {
                    pIdx++;
                } else if (buffer[mIdx] == pattern[0]) {
                    pIdx = 1;
                } else {
                    pIdx = 0;
                }
                mIdx++;

                // Check if we're at the end of the pattern
                if (pIdx == (sizeof(pattern)/sizeof(uint8_t))) {
                    printf("Found CSimU8core instance @ 0x%llx\n", addr + mIdx - sizeof(pattern)/sizeof(uint8_t));
                    numMatches++;
                    matches = realloc(matches, sizeof(uint64_t) * numMatches);
                    matches[numMatches - 1] = addr + mIdx - sizeof(pattern)/sizeof(uint8_t);
                    pIdx = 0;
                }
            }

            // Free memory
            free(buffer);
        }
    }

    if (numMatches > 0) {
        // That pattern is found 10e bytes into the structure
        addr = matches[0] - 0x10e;

        uint8_t buffer[0xFF];
        if(ReadProcessMemory(proc, (LPCVOID)addr, buffer, 0xFF, NULL) == 0) {
            printf("Failed to read memory: 0x%x\n", GetLastError());
            return -1;
        }

        // ROM Segment 0 +0x2C
        // ROM Segment 1 +0x64
        // RAM           +0x48
        struct memory_region *rom_seg0 = (struct memory_region *)(buffer + 0x2C);
        struct memory_region *rom_seg1 = (struct memory_region *)(buffer + 0x64);
        struct memory_region *ram = (struct memory_region *)(buffer + 0x48);

        printf("           Start       End         Size      \n");
        printf("ROM Seg 0: 0x%08lx  0x%08lx  0x%08lx\n", rom_seg0->buf_addr, rom_seg0->buf_addr + rom_seg0->buf_size, rom_seg0->buf_size);
        printf("ROM Seg N: 0x%08lx  0x%08lx  0x%08lx\n", rom_seg1->buf_addr, rom_seg1->buf_addr + rom_seg1->buf_size, rom_seg1->buf_size);
        printf("RAM:       0x%08lx  0x%08lx  0x%08lx\n", ram->buf_addr, ram->buf_addr + ram->buf_size, ram->buf_size);

        // Allocate space for the ROM
        uint32_t rom_size = rom_seg0->buf_size + rom_seg1->buf_size;
        uint8_t *rom_buf = malloc(sizeof(uint8_t) * rom_size);
        
        // ROM Segment 0
        if(ReadProcessMemory(proc, (LPCVOID)rom_seg0->buf_addr, rom_buf, rom_seg0->buf_size, NULL) == 0) {
            printf("Failed to read ROM Seg 0 @ %lx: 0x%x\n", rom_seg0->buf_addr, GetLastError());
            return -1;
        }

        // ROM Segment 1
        if(ReadProcessMemory(proc, (LPCVOID)rom_seg1->buf_addr, rom_buf + rom_seg0->buf_size, rom_seg1->buf_size, NULL) == 0) {
            printf("Failed to read ROM Seg 1 @ %lx: 0x%x\n", rom_seg1->buf_addr, GetLastError());
            return -1;
        }

        // RAM
        uint8_t *ram_buf = malloc(sizeof(uint8_t) * ram->buf_size);
        if(ReadProcessMemory(proc, (LPCVOID)ram->buf_addr, ram_buf, ram->buf_size, NULL) == 0) {
            printf("Failed to read RAM @ %lx: 0x%x\n", ram->buf_addr, GetLastError());
            return -1;
        }

        // Write rom dump to file
        FILE *f;
        f = fopen(argv[2], "wb");
        fwrite(rom_buf, sizeof(uint8_t), rom_size, f);
        fclose(f);
        printf("Wrote ROM dump to file\n");

        // Write ram dump to file
        if (argc >= 4) {
            f = fopen(argv[3], "wb");
            fwrite(ram_buf, sizeof(uint8_t), ram->buf_size, f);
            fclose(f);
            printf("Wrote RAM dump to file\n");
        }
    } else {
        printf("Couldn't find pattern\n");
    }

    printf("Done!\n");

    return 0;
}