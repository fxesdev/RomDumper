#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <psapi.h>

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

static const uint8_t pattern_csimu8[] = {0x57, 0x44, 0x54, 0x49, 0x4E, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t pattern_romname[] = {0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

HMODULE getModule(HANDLE proc, char *name) {
    HMODULE mods[100];
    uint32_t cbNeeded;
    char modName[100];

    if (EnumProcessModules(proc, mods, sizeof(mods), &cbNeeded)) {
        for(int x = 0; x < (cbNeeded/sizeof(HMODULE)); x++) {
            GetModuleBaseNameA(proc, mods[x], modName, sizeof(modName));
            if(strcmp(name, modName) == 0) {
                return mods[x];
            }
        }
    }

    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <target> <Emulator PID>", argv[0]);
        return -1;
    }

    // Check what we want to dump
    bool dump_rom = false;
    bool dump_ram = false;
    for(char *c = argv[1]; *c != '\0'; c++) {
        if (*c == 'o') dump_rom = true;
        if (*c == 'a') dump_ram = true;
    }

    // Get handle on the emulator
    uint32_t pid;
    sscanf(argv[2], "%" SCNd32, &pid);

    HANDLE proc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        false, pid
    );

    if (proc == NULL) {
        printf("Failed to open handle: 0x%x\n", GetLastError());
        return -1;
    }

    // Get SimU8.dll base address
    HMODULE SimU8_mod = getModule(proc, "SimU8.dll");
    if (SimU8_mod == NULL) {
        printf("Failed to get handle for SimU8.dll\n");
        return -1;
    }
    
    MODULEINFO modinfo;
    if(GetModuleInformation(proc, SimU8_mod, &modinfo, sizeof(modinfo)) == 0) {
        printf("Failed to get module info for SimU8.dll\n");
        return -1;
    }
    uint32_t SimU8_base_addr = (uint32_t)modinfo.lpBaseOfDll;

    uint32_t sim_state_addr = SimU8_base_addr + 0x16CE20;

    uint8_t buffer[0xFF];
    if(ReadProcessMemory(proc, (LPCVOID)sim_state_addr, buffer, 0xFF, NULL) == 0) {
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

    // Try and detect ROM name
    char rom_name[8] = "dump";
    int pIdx = 0, mIdx = 0;
    while(mIdx < rom_size) {
        if (rom_buf[mIdx] == pattern_romname[pIdx]) {
            pIdx++;
        } else if (rom_buf[mIdx] == pattern_romname[0]) {
            pIdx = 1;
        } else {
            pIdx = 0;
        }
        mIdx++;

        // Check if we're at the end of the pattern
        if (pIdx == (sizeof(pattern_romname)/sizeof(uint8_t))) {
            // Find 0x20 after name, then extract it
            while(rom_buf[mIdx] != 0x20) mIdx++;
            mIdx -= 7;
            memcpy(rom_name, rom_buf + mIdx, 7);
            rom_buf[7] = 0;

            printf("Found ROM name: %s\n", rom_name);

            // Truncate the ROM as the name is found at the end
            uint32_t new_size = (mIdx + 0xFFFF) & ~0xFFFF;
            printf("Truncated ROM to 0x%08lx from 0x%08lx\n", new_size, rom_size);
            rom_size = new_size;
        }
    }

    // Generate filenames
    char rom_filename[16];
    sprintf(rom_filename, "%s.rom.bin", rom_name);
    char ram_filename[16];
    sprintf(ram_filename, "%s.ram.bin", rom_name);

    // Write rom dump to file
    if (dump_rom) {
        FILE *f;
        f = fopen(rom_filename, "wb");
        fwrite(rom_buf, sizeof(uint8_t), rom_size, f);
        fclose(f);
        printf("Wrote ROM dump to file\n");
    }
    
    // Write ram dump to file
    if (dump_ram) {
        FILE *f = fopen(ram_filename, "wb");
        fwrite(ram_buf, sizeof(uint8_t), ram->buf_size, f);
        fclose(f);
        printf("Wrote RAM dump to file\n");
    }
    

    printf("Done!\n");

    return 0;
}